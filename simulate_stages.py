#!/usr/bin/env python3
"""
8-Stage IEC-104 Attack Scenario Simulation.

Generates PCAP traffic and feature vectors for each attack stage based on:
"Threat Scenario Generation for IEC104 Cyber Defense"
https://www.researchgate.net/publication/382158810

Stages:
  1. Discovery (T0888)         - C_IC_NA_1 interrogation sweep
  2. Collection: Monitor (T0801) - Frequent reads on specific IOAs
  3. Collection: Automated (T0802) - Persistent polling loop
  4. Command & Control (T0869)  - Secondary HMI session
  5. Brute Force I/O (T0806)    - IOA sweep with C_SC_NA_1
  6. Modify Parameter (T0836)   - C_SE_NA_1 setpoint changes
  7. Unauthorized Command (T0855) - TypeID 45/46 without proper COT
  8. Manipulation of Control (T0831) - Rapid contradictory open/close

Usage:
    python simulate_stages.py --output-dir output
    python simulate_stages.py --stage 5 --output-dir output
    python simulate_stages.py --features-only
    python simulate_stages.py --evaluate-rules
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import struct
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IEC-104 frame builders (raw bytes -- no live network required)
# ---------------------------------------------------------------------------

IEC104_PORT = 2404
APCI_START = 0x68

# COT codes
COT_SPONT = 3
COT_REQUEST = 5
COT_ACT = 6
COT_ACTCON = 7
COT_DEACT = 8
COT_DEACTCON = 9
COT_ACTTERM = 10
COT_INROGEN = 20
COT_UNKNOWN_TYPE = 44
COT_UNKNOWN_COT = 45

# TypeIDs
TYPEID_M_SP_NA_1 = 1    # Single-point information
TYPEID_M_ME_NA_1 = 9    # Measured value, normalized
TYPEID_C_SC_NA_1 = 45   # Single command
TYPEID_C_DC_NA_1 = 46   # Double command
TYPEID_C_SE_NA_1 = 48   # Set-point, normalized
TYPEID_C_IC_NA_1 = 100  # Interrogation command
TYPEID_C_RD_NA_1 = 102  # Read command

# U-frame control bytes
UFRAME_STARTDT_ACT = bytes([0x07, 0x00, 0x00, 0x00])
UFRAME_STARTDT_CON = bytes([0x0B, 0x00, 0x00, 0x00])
UFRAME_TESTFR_ACT = bytes([0x43, 0x00, 0x00, 0x00])
UFRAME_TESTFR_CON = bytes([0x83, 0x00, 0x00, 0x00])


@dataclass
class SequenceCounter:
    """Track I-frame send/receive sequence numbers."""
    send_seq: int = 0
    recv_seq: int = 0

    def next_send(self) -> int:
        val = self.send_seq
        self.send_seq += 1
        return val

    def next_recv(self) -> int:
        val = self.recv_seq
        self.recv_seq += 1
        return val


def build_uframe(ctrl_bytes: bytes) -> bytes:
    """Build a U-frame (STARTDT, TESTFR, etc.)."""
    return bytes([APCI_START, 4]) + ctrl_bytes


def build_iframe(
    type_id: int,
    cot: int,
    common_addr: int,
    ioa: int,
    info_elements: bytes,
    seq: SequenceCounter,
    originator: int = 0,
    sq: int = 0,
    num_objects: int = 1,
) -> bytes:
    """Build an I-frame with ASDU."""
    send_n = seq.next_send()
    recv_n = seq.recv_seq
    ctrl = struct.pack("<HH", send_n << 1, recv_n << 1)

    # ASDU header
    vsq = (sq << 7) | (num_objects & 0x7F)
    asdu_header = struct.pack("<BBB",
                              type_id,
                              vsq,
                              cot & 0x3F)
    asdu_header += struct.pack("<B", originator)
    asdu_header += struct.pack("<H", common_addr)

    # IOA (3 bytes, little-endian)
    ioa_bytes = struct.pack("<I", ioa)[:3]

    apdu_payload = ctrl + asdu_header + ioa_bytes + info_elements
    length = len(apdu_payload)
    return bytes([APCI_START, length]) + apdu_payload


def build_interrogation(common_addr: int, seq: SequenceCounter, cot: int = COT_ACT) -> bytes:
    """C_IC_NA_1: Interrogation command."""
    return build_iframe(TYPEID_C_IC_NA_1, cot, common_addr, 0, bytes([20]), seq)


def build_read_command(common_addr: int, ioa: int, seq: SequenceCounter) -> bytes:
    """C_RD_NA_1: Read command."""
    return build_iframe(TYPEID_C_RD_NA_1, COT_REQUEST, common_addr, ioa, b"", seq)


def build_single_command(
    common_addr: int,
    ioa: int,
    sco: int,
    seq: SequenceCounter,
    cot: int = COT_ACT,
) -> bytes:
    """C_SC_NA_1: Single command.
    sco: Single Command Output -- bit 0 = on/off, bit 7 = S/E qualifier.
    """
    return build_iframe(TYPEID_C_SC_NA_1, cot, common_addr, ioa, bytes([sco]), seq)


def build_double_command(
    common_addr: int,
    ioa: int,
    dco: int,
    seq: SequenceCounter,
    cot: int = COT_ACT,
) -> bytes:
    """C_DC_NA_1: Double command.
    dco: Double Command Output -- bits 0-1 = state (1=off, 2=on), bit 7 = S/E.
    """
    return build_iframe(TYPEID_C_DC_NA_1, cot, common_addr, ioa, bytes([dco]), seq)


def build_setpoint_normalized(
    common_addr: int,
    ioa: int,
    value: float,
    seq: SequenceCounter,
    cot: int = COT_ACT,
) -> bytes:
    """C_SE_NA_1: Set-point command, normalized value.
    value: -1.0 to +1.0, encoded as signed 16-bit.
    """
    nva = int(max(-32768, min(32767, value * 32767)))
    info = struct.pack("<hB", nva, 0)
    return build_iframe(TYPEID_C_SE_NA_1, cot, common_addr, ioa, info, seq)


def build_monitor_response(
    type_id: int,
    common_addr: int,
    ioa: int,
    info_elements: bytes,
    seq: SequenceCounter,
    cot: int = COT_SPONT,
) -> bytes:
    """Build a monitor-direction response (from RTU)."""
    return build_iframe(type_id, cot, common_addr, ioa, info_elements, seq)


# ---------------------------------------------------------------------------
# PCAP writer (minimal, no dependency on libpcap)
# ---------------------------------------------------------------------------

def _pcap_global_header() -> bytes:
    """PCAP global header (little-endian, Ethernet link type)."""
    return struct.pack("<IHHiIII",
                       0xA1B2C3D4,  # magic
                       2, 4,         # version
                       0,            # thiszone
                       0,            # sigfigs
                       65535,        # snaplen
                       1)            # link type: Ethernet


def _pcap_packet(ts: float, payload: bytes) -> bytes:
    """Wrap payload in PCAP packet record with Ethernet/IP/TCP headers."""
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)

    eth = bytes(6) + bytes(6) + b"\x08\x00"  # src/dst MAC + IPv4

    ip_total_len = 20 + 20 + len(payload)
    ip_header = struct.pack(">BBHHHBBH4s4s",
                            0x45, 0,
                            ip_total_len,
                            0, 0,
                            64, 6,
                            0,
                            b"\x0a\x00\x01\x64",   # 10.0.1.100 (attacker)
                            b"\x0a\x00\x01\xc8")   # 10.0.1.200 (RTU)

    tcp_header = struct.pack(">HHIIBBHHH",
                             12345, IEC104_PORT,
                             1000, 2000,
                             0x50, 0x18,
                             65535,
                             0,
                             0)

    frame = eth + ip_header + tcp_header + payload
    cap_len = len(frame)
    return struct.pack("<IIII", ts_sec, ts_usec, cap_len, cap_len) + frame


def write_pcap(path: Path, packets: list[tuple[float, bytes]]):
    """Write a list of (timestamp, iec104_bytes) to a PCAP file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(_pcap_global_header())
        for ts, payload in packets:
            f.write(_pcap_packet(ts, payload))
    logger.info("Wrote %d packets to %s", len(packets), path)


# ---------------------------------------------------------------------------
# Stage generators
# ---------------------------------------------------------------------------

@dataclass
class StageResult:
    """Result from a stage simulation."""
    stage: int
    name: str
    mitre_technique: str
    mitre_id: str
    packets: list[tuple[float, bytes]] = field(default_factory=list)
    features: dict = field(default_factory=dict)
    event_count: int = 0
    description: str = ""


def _base_ts() -> float:
    """Base timestamp for simulation."""
    return datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc).timestamp()


def stage_1_discovery(base_ts: float | None = None) -> StageResult:
    """Stage 1: Discovery (T0888) -- Interrogation sweep across station addresses."""
    ts = base_ts or _base_ts()
    seq = SequenceCounter()
    packets = []

    # STARTDT to initiate link
    packets.append((ts, build_uframe(UFRAME_STARTDT_ACT)))
    ts += 0.05
    packets.append((ts, build_uframe(UFRAME_STARTDT_CON)))
    ts += 0.1

    # Sweep interrogation across multiple common addresses (station discovery)
    station_addresses = list(range(1, 21))  # Probe 20 stations
    for addr in station_addresses:
        packets.append((ts, build_interrogation(addr, seq)))
        ts += 0.3  # 300ms between probes

    # Some stations respond with monitor data
    rtu_seq = SequenceCounter()
    for addr in [1, 3, 5]:  # Only 3 stations respond
        for ioa in range(1, 6):
            info = bytes([0x00])  # SIQ: OFF, quality OK
            packets.append((ts, build_monitor_response(
                TYPEID_M_SP_NA_1, addr, ioa, info, rtu_seq, cot=COT_INROGEN
            )))
            ts += 0.01

    result = StageResult(
        stage=1,
        name="Discovery",
        mitre_technique="Remote System Discovery",
        mitre_id="T0888",
        packets=packets,
        event_count=len(station_addresses) + 15,
        description="Interrogation sweep across 20 station addresses, 3 responded",
    )
    result.features = {
        "n_events": result.event_count,
        "n_flows": 1,
        "total_bytes": len(packets) * 40,
        "unique_typeIDs": 2,
        "unique_cots": 3,
        "unique_ioas": 5,
        "unique_common_addresses": 20,
        "interrogation_count": 20,
        "events_per_second": result.event_count / 8.0,
        "command_vs_monitor_ratio": 20 / 15,
        "orig_event_ratio": 20 / result.event_count,
        "command_rate": 20 / 8.0,
        "dominant_type_ratio": 20 / result.event_count,
        "dominant_ioa_ratio": 0.14,
        "ioa_entropy": 1.6,
        "mean_asdu_length": 14,
        "typeID_entropy": 0.95,
        "cot_entropy": 1.2,
        "iat_mean": 0.25,
        "iat_std": 0.15,
    }
    return result


def stage_2_collection_monitor(base_ts: float | None = None) -> StageResult:
    """Stage 2: Collection -- Monitor Process State (T0801)."""
    ts = (base_ts or _base_ts()) + 10
    seq = SequenceCounter()
    packets = []

    target_ioas = [100, 200, 300, 400, 500]
    common_addr = 1

    for cycle in range(30):
        for ioa in target_ioas:
            packets.append((ts, build_read_command(common_addr, ioa, seq)))
            ts += 0.05

            rtu_seq = SequenceCounter(send_seq=cycle * 5)
            nva = struct.pack("<hB", int(50 * 327.67), 0)
            packets.append((ts, build_monitor_response(
                TYPEID_M_ME_NA_1, common_addr, ioa, nva, rtu_seq, cot=COT_REQUEST
            )))
            ts += 0.05
        ts += 1.9

    result = StageResult(
        stage=2,
        name="Collection: Monitor Process State",
        mitre_technique="Monitor Process State",
        mitre_id="T0801",
        packets=packets,
        event_count=300,
        description="Frequent reads on 5 IOAs (100-500) every 2s for 60s",
    )
    result.features = {
        "n_events": 300,
        "n_flows": 1,
        "total_bytes": 300 * 30,
        "unique_typeIDs": 2,
        "unique_cots": 2,
        "unique_ioas": 5,
        "unique_common_addresses": 1,
        "interrogation_count": 0,
        "events_per_second": 5.0,
        "command_vs_monitor_ratio": 1.0,
        "orig_event_ratio": 0.5,
        "command_rate": 2.5,
        "dominant_type_ratio": 0.5,
        "dominant_ioa_ratio": 0.2,
        "ioa_entropy": 2.32,
        "mean_asdu_length": 16,
        "typeID_entropy": 1.0,
        "cot_entropy": 0.5,
        "iat_mean": 0.2,
        "iat_std": 0.8,
        "iat_cv": 4.0,
    }
    return result


def stage_3_collection_automated(base_ts: float | None = None) -> StageResult:
    """Stage 3: Automated Collection (T0802) -- Persistent polling loop."""
    ts = (base_ts or _base_ts()) + 80
    seq = SequenceCounter()
    packets = []

    common_addr = 1
    poll_ioas = list(range(1, 51))

    for cycle in range(20):
        packets.append((ts, build_interrogation(common_addr, seq)))
        ts += 0.5

        rtu_seq = SequenceCounter(send_seq=cycle * 50)
        for ioa in poll_ioas:
            info = bytes([0x00])
            packets.append((ts, build_monitor_response(
                TYPEID_M_SP_NA_1, common_addr, ioa, info, rtu_seq, cot=COT_INROGEN
            )))
            ts += 0.005
        ts += 2.5

    result = StageResult(
        stage=3,
        name="Collection: Automated Collection",
        mitre_technique="Automated Collection",
        mitre_id="T0802",
        packets=packets,
        event_count=20 + 1000,
        description="Persistent interrogation loop: 50 IOAs every 3s for 60s",
    )
    result.features = {
        "n_events": 1020,
        "n_flows": 1,
        "total_bytes": 1020 * 25,
        "unique_typeIDs": 2,
        "unique_cots": 2,
        "unique_ioas": 50,
        "unique_common_addresses": 1,
        "interrogation_count": 20,
        "events_per_second": 17.0,
        "command_vs_monitor_ratio": 0.02,
        "orig_event_ratio": 0.02,
        "command_rate": 0.33,
        "dominant_type_ratio": 0.98,
        "dominant_ioa_ratio": 0.02,
        "ioa_entropy": 5.64,
        "mean_asdu_length": 12,
        "typeID_entropy": 0.14,
        "cot_entropy": 0.14,
        "iat_mean": 0.06,
        "iat_std": 0.3,
        "event_regularity": 0.85,
    }
    return result


def stage_4_command_control(base_ts: float | None = None) -> StageResult:
    """Stage 4: Command & Control (T0869) -- Secondary HMI session."""
    ts = (base_ts or _base_ts()) + 150
    seq = SequenceCounter()
    packets = []

    packets.append((ts, build_uframe(UFRAME_STARTDT_ACT)))
    ts += 0.05
    packets.append((ts, build_uframe(UFRAME_STARTDT_CON)))
    ts += 0.1

    for i in range(10):
        packets.append((ts, build_uframe(UFRAME_TESTFR_ACT)))
        ts += 0.05
        packets.append((ts, build_uframe(UFRAME_TESTFR_CON)))
        ts += 5.0

    common_addr = 1
    for ioa in [100, 200]:
        packets.append((ts, build_single_command(common_addr, ioa, 0x01, seq)))
        ts += 1.0

    result = StageResult(
        stage=4,
        name="Command & Control",
        mitre_technique="Standard Application Layer Protocol",
        mitre_id="T0869",
        packets=packets,
        event_count=24,
        description="Secondary TCP session established, 10 keepalives + 2 relayed commands",
    )
    result.features = {
        "n_events": 2,
        "n_flows": 2,
        "total_bytes": 24 * 20,
        "unique_typeIDs": 1,
        "unique_cots": 1,
        "unique_ioas": 2,
        "unique_common_addresses": 1,
        "interrogation_count": 0,
        "events_per_second": 0.03,
        "command_vs_monitor_ratio": 999.0,
        "orig_event_ratio": 1.0,
        "command_rate": 0.03,
        "dominant_type_ratio": 1.0,
        "dominant_ioa_ratio": 0.5,
        "u_startdt_act_count": 1,
        "u_startdt_con_count": 1,
        "u_testfr_act_count": 10,
        "u_testfr_con_count": 10,
        "u_testfr_success_ratio": 1.0,
        "u_link_state_change_flag": 1,
    }
    return result


def stage_5_brute_force_io(base_ts: float | None = None) -> StageResult:
    """Stage 5: Brute Force I/O (T0806) -- IOA sweep with C_SC_NA_1."""
    ts = (base_ts or _base_ts()) + 210
    seq = SequenceCounter()
    packets = []

    common_addr = 1
    ioa_range = list(range(100, 2001))

    for ioa in ioa_range:
        packets.append((ts, build_single_command(common_addr, ioa, 0x01, seq)))
        ts += 0.03

    result = StageResult(
        stage=5,
        name="Brute Force I/O",
        mitre_technique="Brute Force I/O",
        mitre_id="T0806",
        packets=packets,
        event_count=len(ioa_range),
        description=f"IOA sweep: C_SC_NA_1 on IOAs {ioa_range[0]}-{ioa_range[-1]} ({len(ioa_range)} targets)",
    )
    result.features = {
        "n_events": len(ioa_range),
        "n_flows": 1,
        "total_bytes": len(ioa_range) * 22,
        "unique_typeIDs": 1,
        "unique_cots": 1,
        "unique_ioas": len(ioa_range),
        "unique_common_addresses": 1,
        "interrogation_count": 0,
        "events_per_second": 33.3,
        "command_vs_monitor_ratio": 999.0,
        "orig_event_ratio": 1.0,
        "command_rate": 33.3,
        "dominant_type_ratio": 1.0,
        "dominant_ioa_ratio": 1 / len(ioa_range),
        "ioa_entropy": math.log2(len(ioa_range)),
        "mean_asdu_length": 15,
        "typeID_entropy": 0.0,
        "cot_entropy": 0.0,
        "iat_mean": 0.03,
        "iat_std": 0.001,
        "iat_cv": 0.033,
        "orig_command_count": len(ioa_range),
    }
    return result


def stage_6_modify_parameter(base_ts: float | None = None) -> StageResult:
    """Stage 6: Modify Parameter (T0836) -- Setpoint changes on critical IOAs."""
    ts = (base_ts or _base_ts()) + 280
    seq = SequenceCounter()
    packets = []

    common_addr = 1
    targets = [
        (1001, 0.95),   # Pressure limit -> near max
        (1002, -0.80),  # Temperature threshold -> abnormal
        (1003, 0.10),   # Flow rate -> reduced
        (2001, 0.99),   # Safety trip point -> near max
        (2002, 0.01),   # Alarm threshold -> near zero (disabling alarm)
    ]

    for ioa, value in targets:
        packets.append((ts, build_setpoint_normalized(common_addr, ioa, value, seq)))
        ts += 2.0

        rtu_seq = SequenceCounter(send_seq=100)
        nva = struct.pack("<hB", int(value * 32767), 0)
        packets.append((ts, build_iframe(
            TYPEID_C_SE_NA_1, COT_ACTCON, common_addr, ioa, nva, rtu_seq
        )))
        ts += 0.1

    result = StageResult(
        stage=6,
        name="Modify Parameter",
        mitre_technique="Modify Parameter",
        mitre_id="T0836",
        packets=packets,
        event_count=10,
        description="Setpoint changes on 5 critical IOAs (1001-2002)",
    )
    result.features = {
        "n_events": 10,
        "n_flows": 1,
        "total_bytes": 10 * 24,
        "unique_typeIDs": 1,
        "unique_cots": 2,
        "unique_ioas": 5,
        "unique_common_addresses": 1,
        "interrogation_count": 0,
        "events_per_second": 0.83,
        "command_vs_monitor_ratio": 1.0,
        "orig_event_ratio": 0.5,
        "command_rate": 0.42,
        "dominant_type_ratio": 1.0,
        "dominant_ioa_ratio": 0.2,
        "ioa_entropy": 2.32,
        "mean_asdu_length": 18,
        "typeID_entropy": 0.0,
        "cot_entropy": 1.0,
        "orig_command_count": 5,
    }
    return result


def stage_7_unauthorized_command(base_ts: float | None = None) -> StageResult:
    """Stage 7: Unauthorized Command Message (T0855) -- TypeID 45/46 without proper COT."""
    ts = (base_ts or _base_ts()) + 300
    seq = SequenceCounter()
    packets = []

    common_addr = 1

    attack_commands = [
        (500, TYPEID_C_SC_NA_1, COT_SPONT, "SC with spontaneous COT (wrong direction)"),
        (501, TYPEID_C_SC_NA_1, COT_ACT, "SC without prior session setup"),
        (502, TYPEID_C_DC_NA_1, COT_ACT, "DC on unauthorized IOA"),
        (503, TYPEID_C_SC_NA_1, COT_INROGEN, "SC with interrogation COT (invalid for commands)"),
        (504, TYPEID_C_DC_NA_1, COT_ACT, "DC rapid fire #1"),
        (504, TYPEID_C_DC_NA_1, COT_ACT, "DC rapid fire #2"),
        (505, TYPEID_C_SC_NA_1, COT_UNKNOWN_COT, "SC with error COT"),
        (600, TYPEID_C_DC_NA_1, COT_ACT, "DC on high-value IOA"),
        (601, TYPEID_C_SC_NA_1, COT_ACT, "SC on high-value IOA"),
        (602, TYPEID_C_DC_NA_1, COT_DEACT, "DC deactivation without prior activation"),
    ]

    for ioa, type_id, cot, desc in attack_commands:
        if type_id == TYPEID_C_SC_NA_1:
            sco = 0x01
            packets.append((ts, build_iframe(type_id, cot, common_addr, ioa, bytes([sco]), seq)))
        else:
            dco = 0x02
            packets.append((ts, build_iframe(type_id, cot, common_addr, ioa, bytes([dco]), seq)))
        ts += 0.5

    result = StageResult(
        stage=7,
        name="Unauthorized Command Message",
        mitre_technique="Unauthorized Command Message",
        mitre_id="T0855",
        packets=packets,
        event_count=len(attack_commands),
        description="10 command injections with invalid/missing COT sequences on IOAs 500-602",
    )
    result.features = {
        "n_events": len(attack_commands),
        "n_flows": 1,
        "total_bytes": len(attack_commands) * 22,
        "unique_typeIDs": 2,
        "unique_cots": 5,
        "unique_ioas": 8,
        "unique_common_addresses": 1,
        "interrogation_count": 0,
        "events_per_second": 2.0,
        "command_vs_monitor_ratio": 999.0,
        "orig_event_ratio": 1.0,
        "command_rate": 2.0,
        "dominant_type_ratio": 0.6,
        "dominant_ioa_ratio": 0.2,
        "ioa_entropy": 2.8,
        "mean_asdu_length": 15,
        "typeID_entropy": 0.97,
        "cot_entropy": 2.0,
        "orig_command_count": 10,
        "command_without_interrogation": 10,
        "unexpected_cot_sequence": 6,
        "cot_transition_count": 8,
        "is_missing_unique_ioas": 0,
    }
    return result


def stage_8_manipulation_of_control(base_ts: float | None = None) -> StageResult:
    """Stage 8: Manipulation of Control (T0831) -- Rapid contradictory open/close commands."""
    ts = (base_ts or _base_ts()) + 320
    seq = SequenceCounter()
    packets = []

    common_addr = 1
    target_ioas = [500, 501, 502]

    for cycle in range(20):
        for ioa in target_ioas:
            packets.append((ts, build_double_command(common_addr, ioa, 0x02, seq)))
            ts += 0.1
            packets.append((ts, build_double_command(common_addr, ioa, 0x01, seq)))
            ts += 0.1

    result = StageResult(
        stage=8,
        name="Manipulation of Control",
        mitre_technique="Manipulation of Control",
        mitre_id="T0831",
        packets=packets,
        event_count=20 * 3 * 2,
        description="Rapid contradictory open/close on 3 breaker IOAs (500-502), 20 cycles",
    )
    result.features = {
        "n_events": 120,
        "n_flows": 1,
        "total_bytes": 120 * 22,
        "unique_typeIDs": 1,
        "unique_cots": 1,
        "unique_ioas": 3,
        "unique_common_addresses": 1,
        "interrogation_count": 0,
        "events_per_second": 10.0,
        "command_vs_monitor_ratio": 999.0,
        "orig_event_ratio": 1.0,
        "command_rate": 10.0,
        "dominant_type_ratio": 1.0,
        "dominant_ioa_ratio": 0.33,
        "ioa_entropy": 1.58,
        "mean_asdu_length": 15,
        "typeID_entropy": 0.0,
        "cot_entropy": 0.0,
        "iat_mean": 0.1,
        "iat_std": 0.01,
        "iat_cv": 0.1,
        "orig_command_count": 120,
        "event_burstiness": 0.95,
        "burst_subinterval_count": 12,
    }
    return result


# ---------------------------------------------------------------------------
# Stage registry
# ---------------------------------------------------------------------------

STAGE_GENERATORS = {
    1: stage_1_discovery,
    2: stage_2_collection_monitor,
    3: stage_3_collection_automated,
    4: stage_4_command_control,
    5: stage_5_brute_force_io,
    6: stage_6_modify_parameter,
    7: stage_7_unauthorized_command,
    8: stage_8_manipulation_of_control,
}

STAGE_METADATA = {
    1: {"mitre_id": "T0888", "mitre_name": "Remote System Discovery", "tactic": "Discovery", "severity": 4},
    2: {"mitre_id": "T0801", "mitre_name": "Monitor Process State", "tactic": "Collection", "severity": 5},
    3: {"mitre_id": "T0802", "mitre_name": "Automated Collection", "tactic": "Collection", "severity": 5},
    4: {"mitre_id": "T0869", "mitre_name": "Standard Application Layer Protocol", "tactic": "Command and Control", "severity": 6},
    5: {"mitre_id": "T0806", "mitre_name": "Brute Force I/O", "tactic": "Impair Process Control", "severity": 8},
    6: {"mitre_id": "T0836", "mitre_name": "Modify Parameter", "tactic": "Impair Process Control", "severity": 9},
    7: {"mitre_id": "T0855", "mitre_name": "Unauthorized Command Message", "tactic": "Impair Process Control", "severity": 9},
    8: {"mitre_id": "T0831", "mitre_name": "Manipulation of Control", "tactic": "Impact", "severity": 10},
}


def run_all_stages(output_dir: Path | None = None) -> list[StageResult]:
    """Run all 8 stages and optionally write PCAPs."""
    results = []
    base_ts = _base_ts()

    for stage_num, gen_fn in sorted(STAGE_GENERATORS.items()):
        result = gen_fn(base_ts)
        results.append(result)
        logger.info("Stage %d (%s): %d packets, %d events",
                     stage_num, result.name, len(result.packets), result.event_count)

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

        for result in results:
            pcap_path = output_dir / f"stage_{result.stage}_{result.mitre_id}.pcap"
            write_pcap(pcap_path, result.packets)

        all_packets = []
        for result in results:
            all_packets.extend(result.packets)
        all_packets.sort(key=lambda x: x[0])
        write_pcap(output_dir / "all_stages_combined.pcap", all_packets)

    return results


def evaluate_rules(results: list[StageResult]):
    """Evaluate all stages through the protocol rule engine."""
    from protocol.rule_engine import RuleEngine

    engine = RuleEngine()
    summary = engine.get_rule_summary()
    print(f"\nRule engine: {summary['event_rules']} event rules, "
          f"{summary['window_rules']} window rules")

    print(f"\n{'Stage':<6} {'Name':<35} {'Rules':>5}  Matched Rules")
    print("-" * 90)

    for result in results:
        matches = engine.evaluate_window(result.features)
        rule_ids = ", ".join(m.rule_id for m in matches) if matches else "(none)"
        print(f"{result.stage:<6} {result.name:<35} {len(matches):>5}  {rule_ids}")

        for m in matches:
            mitre = m.mitre_ics.get("technique_id", "")
            print(f"       [{m.severity:>8}] {m.rule_name} ({mitre})")
            for k, v in m.matched_values.items():
                print(f"                 {k} = {v}")


def main():
    parser = argparse.ArgumentParser(
        description="8-Stage IEC-104 Attack Scenario Simulation",
        epilog="Based on: Threat Scenario Generation for IEC104 Cyber Defense "
               "(https://www.researchgate.net/publication/382158810)",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("output"),
                        help="Output directory for PCAPs and feature JSONs (default: output)")
    parser.add_argument("--stage", type=int, choices=range(1, 9),
                        help="Run a single stage (default: all)")
    parser.add_argument("--features-only", action="store_true",
                        help="Only generate feature vectors (no PCAPs)")
    parser.add_argument("--evaluate-rules", action="store_true",
                        help="Evaluate stages through the protocol rule engine")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.stage:
        gen_fn = STAGE_GENERATORS[args.stage]
        result = gen_fn()
        results = [result]
        print(f"Stage {result.stage}: {result.name} ({result.mitre_id})")
        print(f"  Events: {result.event_count}")
        print(f"  Packets: {len(result.packets)}")
        print(f"  Description: {result.description}")

        if not args.features_only:
            pcap_path = args.output_dir / f"stage_{result.stage}_{result.mitre_id}.pcap"
            write_pcap(pcap_path, result.packets)
            print(f"  PCAP: {pcap_path}")
    else:
        results = run_all_stages(args.output_dir if not args.features_only else None)

    # Always write feature JSONs
    args.output_dir.mkdir(parents=True, exist_ok=True)
    feature_dicts = []
    for result in results:
        entry = {
            "stage": result.stage,
            "name": result.name,
            "mitre_id": result.mitre_id,
            "mitre_technique": result.mitre_technique,
            "event_count": result.event_count,
            "description": result.description,
            "features": result.features,
        }
        feature_dicts.append(entry)

    with open(args.output_dir / "stage_features.json", "w") as f:
        json.dump(feature_dicts, f, indent=2, default=str)

    # Summary
    print(f"\n{'='*70}")
    print(f"{'Stage':<8} {'Name':<35} {'MITRE':<8} {'Events':<8} {'Packets'}")
    print(f"{'-'*70}")
    for r in results:
        print(f"{r.stage:<8} {r.name:<35} {r.mitre_id:<8} {r.event_count:<8} {len(r.packets)}")
    print(f"{'='*70}")
    print(f"Features saved: {args.output_dir / 'stage_features.json'}")

    if args.evaluate_rules:
        evaluate_rules(results)


if __name__ == "__main__":
    main()
