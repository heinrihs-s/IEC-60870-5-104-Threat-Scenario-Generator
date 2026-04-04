#!/usr/bin/env python3
"""Surgical IEC-104 Attack PCAP Generator.

Generates targeted attack PCAPs covering specific blind spots in
anomaly detection models. Each attack is designed to stress a known gap
rather than repeat obvious attack patterns.

Attack catalog:
  ATK-00  clean_baseline       -- Control PCAP (no attacks)
  ATK-01  short_burst          -- Single-window command burst (<30s)
  ATK-02  low_and_slow         -- Time-stretch parameter drift (2h)
  ATK-03  topology_new_peer    -- Unseen IP appears
  ATK-04  topology_lateral     -- Multi-station pivot
  ATK-05  legitimate_abuse     -- Protocol-compliant contextual abuse
  ATK-06  unseen_typeids       -- Novel TypeID injection
  ATK-07  partial_interrupted  -- Incomplete transactions
  ATK-08  slow_toggle          -- Sub-threshold contradictory commands
  ATK-09  chained_multi_stage  -- Full kill chain (1h)

Usage:
    python generate_attack_pcaps.py                        # All attacks
    python generate_attack_pcaps.py --attack short_burst   # Single
    python generate_attack_pcaps.py --list                 # List attacks
    python generate_attack_pcaps.py --output-dir /path     # Custom output
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from simulate_8_stages import (
    APCI_START, IEC104_PORT,
    COT_SPONT, COT_REQUEST, COT_ACT, COT_ACTCON, COT_ACTTERM, COT_INROGEN,
    TYPEID_M_SP_NA_1, TYPEID_M_ME_NA_1,
    TYPEID_C_SC_NA_1, TYPEID_C_DC_NA_1, TYPEID_C_SE_NA_1,
    TYPEID_C_IC_NA_1, TYPEID_C_RD_NA_1,
    UFRAME_STARTDT_ACT, UFRAME_STARTDT_CON,
    UFRAME_TESTFR_ACT, UFRAME_TESTFR_CON,
    SequenceCounter,
    build_uframe, build_iframe, build_interrogation,
    build_single_command, build_double_command,
    build_setpoint_normalized, build_monitor_response,
)
from generate_neg_confirm_pcap import (
    TcpStream, build_iframe_with_pn, write_pcap_stream,
)

# ---------------------------------------------------------------------------
# IP layout -- synthetic IPs for reproducibility.
# Uses private 192.168.10.0/24 addresses (not from any real environment).
# ---------------------------------------------------------------------------
HMI_IP = b"\xC0\xA8\x0A\x01"       # 192.168.10.1   (HMI / control station)
RTU1_IP = b"\xC0\xA8\x0A\x64"      # 192.168.10.100 (RTU-1, primary target)
RTU2_IP = b"\xC0\xA8\x0A\x65"      # 192.168.10.101 (RTU-2, lateral pivot)
ATTACKER_IP = b"\xC0\xA8\x0A\xC8"  # 192.168.10.200 (attacker, unseen peer)

BASE_TS = datetime(2026, 3, 26, 12, 0, 0, tzinfo=timezone.utc).timestamp()


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class AttackResult:
    name: str
    filename: str
    mitre_technique: str
    mitre_id: str
    expected_channels: list[str]
    difficulty: str
    duration_sec: float
    n_attack_packets: int
    n_total_packets: int
    description: str
    ablation_params: dict = field(default_factory=dict)
    records: list[bytes] = field(default_factory=list, repr=False)

    def to_manifest_entry(self) -> dict:
        d = asdict(self)
        d.pop("records", None)
        return d


# ---------------------------------------------------------------------------
# AttackSession -- wraps TcpStream + IEC-104 state
# ---------------------------------------------------------------------------
class AttackSession:
    """IEC-104 session over TCP with automatic sequence management."""

    def __init__(self, src_ip: bytes, dst_ip: bytes,
                 src_port: int, dst_port: int = IEC104_PORT,
                 ts: float = BASE_TS):
        self.stream = TcpStream(src_ip, dst_ip, src_port, dst_port)
        self.hmi_seq = SequenceCounter()
        self.rtu_seq = SequenceCounter()
        self.ts = ts
        self.records: list[bytes] = []
        self._attack_pkt_count = 0

    def handshake(self):
        self.records.extend(self.stream.handshake(self.ts))
        self.ts += 0.010

    def send_startdt(self):
        self.records.append(self.stream.send_client(
            self.ts, build_uframe(UFRAME_STARTDT_ACT)))
        self.ts += 0.050
        self.records.append(self.stream.send_server(
            self.ts, build_uframe(UFRAME_STARTDT_CON)))
        self.ts += 0.100

    def send_testfr(self, with_response: bool = True):
        self.records.append(self.stream.send_client(
            self.ts, build_uframe(UFRAME_TESTFR_ACT)))
        self.ts += 0.050
        if with_response:
            self.records.append(self.stream.send_server(
                self.ts, build_uframe(UFRAME_TESTFR_CON)))
        self.ts += 0.050

    def send_interrogation_cycle(self, common_addr: int = 1,
                                  n_responses: int = 10):
        """Full C_IC_NA_1 ACT -> ACTCON -> M_SP_NA_1 responses -> ACTTERM."""
        # HMI: C_IC_NA_1 ACT
        ic_act = build_iframe_with_pn(
            TYPEID_C_IC_NA_1, COT_ACT, common_addr, 0,
            bytes([20]), self.hmi_seq, pn=False)
        self.records.append(self.stream.send_client(self.ts, ic_act))
        self.ts += 0.050
        # RTU: ACTCON
        ic_actcon = build_iframe_with_pn(
            TYPEID_C_IC_NA_1, COT_ACTCON, common_addr, 0,
            bytes([20]), self.rtu_seq, pn=False)
        self.records.append(self.stream.send_server(self.ts, ic_actcon))
        self.ts += 0.010
        # RTU: monitoring responses
        for ioa in range(1, n_responses + 1):
            resp = build_iframe_with_pn(
                TYPEID_M_SP_NA_1, COT_INROGEN, common_addr, ioa,
                bytes([0x00]), self.rtu_seq, pn=False)
            self.records.append(self.stream.send_server(self.ts, resp))
            self.ts += 0.005
        # RTU: ACTTERM
        ic_actterm = build_iframe_with_pn(
            TYPEID_C_IC_NA_1, COT_ACTTERM, common_addr, 0,
            bytes([20]), self.rtu_seq, pn=False)
        self.records.append(self.stream.send_server(self.ts, ic_actterm))
        self.ts += 0.100

    def send_spontaneous_monitoring(self, common_addr: int = 1,
                                     ioa: int = 1):
        """M_SP_NA_1 spontaneous report from RTU."""
        resp = build_iframe_with_pn(
            TYPEID_M_SP_NA_1, COT_SPONT, common_addr, ioa,
            bytes([0x00]), self.rtu_seq, pn=False)
        self.records.append(self.stream.send_server(self.ts, resp))
        self.ts += 0.010

    def send_command_full(self, type_id: int, common_addr: int, ioa: int,
                          info_elements: bytes, pn: bool = False,
                          include_actterm: bool = True,
                          include_actcon: bool = True,
                          is_attack: bool = False):
        """Full command cycle: ACT -> ACTCON -> ACTTERM."""
        # HMI: ACT
        act = build_iframe_with_pn(
            type_id, COT_ACT, common_addr, ioa,
            info_elements, self.hmi_seq, pn=False)
        self.records.append(self.stream.send_client(self.ts, act))
        if is_attack:
            self._attack_pkt_count += 1
        self.ts += 0.200
        # RTU: ACTCON
        if include_actcon:
            actcon = build_iframe_with_pn(
                type_id, COT_ACTCON, common_addr, ioa,
                info_elements, self.rtu_seq, pn=pn)
            self.records.append(self.stream.send_server(self.ts, actcon))
            if is_attack:
                self._attack_pkt_count += 1
            self.ts += 0.200
        # RTU: ACTTERM
        if include_actterm and include_actcon:
            actterm = build_iframe_with_pn(
                type_id, COT_ACTTERM, common_addr, ioa,
                info_elements, self.rtu_seq, pn=False)
            self.records.append(self.stream.send_server(self.ts, actterm))
            if is_attack:
                self._attack_pkt_count += 1
            self.ts += 0.100

    def send_dc_command(self, common_addr: int, ioa: int, dcs_on: bool,
                        pn: bool = False, include_actcon: bool = True,
                        include_actterm: bool = True, is_attack: bool = False):
        """C_DC_NA_1 double command with full cycle."""
        dco = 0x02 if dcs_on else 0x01  # DCS=ON or DCS=OFF
        self.send_command_full(
            TYPEID_C_DC_NA_1, common_addr, ioa, bytes([dco]),
            pn=pn, include_actcon=include_actcon,
            include_actterm=include_actterm, is_attack=is_attack)

    def send_setpoint(self, common_addr: int, ioa: int, value: float,
                      pn: bool = False, is_attack: bool = False):
        """C_SE_NA_1 setpoint write with full cycle."""
        nva = int(max(-32768, min(32767, value * 32767)))
        info = struct.pack("<hB", nva, 0)
        self.send_command_full(
            TYPEID_C_SE_NA_1, common_addr, ioa, info,
            pn=pn, is_attack=is_attack)

    def send_sc_command(self, common_addr: int, ioa: int, on: bool,
                        is_attack: bool = False):
        """C_SC_NA_1 single command with full cycle."""
        sco = 0x01 if on else 0x00
        self.send_command_full(
            TYPEID_C_SC_NA_1, common_addr, ioa, bytes([sco]),
            is_attack=is_attack)

    def advance(self, seconds: float):
        self.ts += seconds


def _fill_baseline(session: AttackSession, duration_sec: float,
                   interrog_interval: float = 60.0,
                   testfr_interval: float = 30.0):
    """Fill a session with background traffic for a given duration."""
    end_ts = session.ts + duration_sec
    next_interrog = session.ts + interrog_interval
    next_testfr = session.ts + testfr_interval
    spont_counter = 1

    while session.ts < end_ts:
        # Next event: whichever comes first
        next_event = min(next_interrog, next_testfr, end_ts)
        if next_event >= end_ts:
            session.ts = end_ts
            break
        session.ts = next_event
        if next_event == next_testfr:
            session.send_testfr()
            next_testfr += testfr_interval
        if abs(next_event - next_interrog) < 0.001:
            session.send_interrogation_cycle()
            # Add a spontaneous monitoring event
            session.send_spontaneous_monitoring(ioa=spont_counter % 20 + 1)
            spont_counter += 1
            next_interrog += interrog_interval


def _merge_sessions(*sessions: AttackSession) -> list[bytes]:
    """Merge records from multiple sessions, sorted by timestamp.

    Each record starts with a PCAP record header whose first 4 bytes are
    ts_sec (uint32 LE). We extract that for sorting.
    """
    tagged: list[tuple[float, int, bytes]] = []
    for idx, sess in enumerate(sessions):
        for rec in sess.records:
            ts_sec = struct.unpack_from("<I", rec, 0)[0]
            ts_usec = struct.unpack_from("<I", rec, 4)[0]
            ts_full = ts_sec + ts_usec / 1_000_000.0
            tagged.append((ts_full, idx, rec))
    tagged.sort(key=lambda x: (x[0], x[1]))
    return [rec for _, _, rec in tagged]


# ---------------------------------------------------------------------------
# ATK-00: clean_baseline
# ---------------------------------------------------------------------------
def generate_clean_baseline(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36400)
    session.handshake()
    session.send_startdt()
    _fill_baseline(session, 600.0)

    filename = "atk00_clean_baseline.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="clean_baseline",
        filename=filename,
        mitre_technique="None",
        mitre_id="N/A",
        expected_channels=[],
        difficulty="control",
        duration_sec=600,
        n_attack_packets=0,
        n_total_packets=len(session.records),
        description="Pure legitimate traffic: interrogation every 60s, "
                    "TESTFR every 30s, spontaneous monitoring. Zero commands.",
    )


# ---------------------------------------------------------------------------
# ATK-01: short_burst
# ---------------------------------------------------------------------------
def generate_short_burst(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36401)
    session.handshake()
    session.send_startdt()

    # 90s clean baseline
    _fill_baseline(session, 90.0)

    # 15-second burst: 5 ON/OFF toggles on IOA 500
    n_commands = 5
    for i in range(n_commands):
        session.send_dc_command(1, 500, dcs_on=(i % 2 == 0), is_attack=True)
        session.advance(3.0)  # 3s between commands = 15s total

    # 75s more clean baseline
    _fill_baseline(session, 75.0)

    filename = "atk01_short_burst.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="short_burst",
        filename=filename,
        mitre_technique="Manipulation of Control",
        mitre_id="T0831",
        expected_channels=["ml_ensemble", "frequency"],
        difficulty="medium",
        duration_sec=180,
        n_attack_packets=session._attack_pkt_count,
        n_total_packets=len(session.records),
        description="5x C_DC_NA_1 ON/OFF toggles in 15s on IOA 500. "
                    "Single-window burst may be suppressed by min-2 case grouping.",
        ablation_params={"burst_duration_sec": 15, "n_commands": 5},
    )


# ---------------------------------------------------------------------------
# ATK-02: low_and_slow
# ---------------------------------------------------------------------------
def generate_low_and_slow(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36402)
    session.handshake()
    session.send_startdt()

    duration = 7200.0  # 2 hours
    interval = 300.0   # 5 minutes between commands
    n_commands = int(duration / interval)  # 24 commands
    target_ioas = [1001, 1002, 1003, 1004, 1005]
    end_ts = session.ts + duration
    next_cmd = session.ts + interval  # First command at 5 min

    interrog_interval = 60.0
    testfr_interval = 30.0
    next_interrog = session.ts + interrog_interval
    next_testfr = session.ts + testfr_interval
    spont_ctr = 1
    cmd_idx = 0

    while session.ts < end_ts:
        next_event = min(next_interrog, next_testfr, next_cmd, end_ts)
        if next_event >= end_ts:
            break
        session.ts = next_event

        if abs(next_event - next_cmd) < 0.5 and cmd_idx < n_commands:
            # Attack command: gradual value drift 0.50 -> 0.95
            value = 0.50 + (0.45 * cmd_idx / max(n_commands - 1, 1))
            ioa = target_ioas[cmd_idx % len(target_ioas)]
            session.send_setpoint(1, ioa, value, is_attack=True)
            cmd_idx += 1
            next_cmd += interval

        if abs(next_event - next_testfr) < 0.5:
            session.send_testfr()
            next_testfr += testfr_interval

        if abs(next_event - next_interrog) < 0.5:
            session.send_interrogation_cycle()
            session.send_spontaneous_monitoring(ioa=spont_ctr % 20 + 1)
            spont_ctr += 1
            next_interrog += interrog_interval

    filename = "atk02_low_and_slow.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="low_and_slow",
        filename=filename,
        mitre_technique="Modify Parameter",
        mitre_id="T0836",
        expected_channels=["ml_ensemble"],
        difficulty="hard",
        duration_sec=7200,
        n_attack_packets=session._attack_pkt_count,
        n_total_packets=len(session.records),
        description="1x C_SE_NA_1 every 5min to IOAs 1001-1005 (cycling). "
                    "Values drift 0.50->0.95. Per-window scores sub-threshold.",
        ablation_params={"interval_sec": 300, "total_commands": n_commands,
                         "value_drift_range": 0.45},
    )


# ---------------------------------------------------------------------------
# ATK-03: topology_new_peer
# ---------------------------------------------------------------------------
def generate_topology_new_peer(output_dir: Path) -> AttackResult:
    # Legitimate HMI session (continuous)
    legit = AttackSession(HMI_IP, RTU1_IP, 36403, ts=BASE_TS)
    legit.handshake()
    legit.send_startdt()
    _fill_baseline(legit, 120.0)

    # Attacker session (new peer, starts at t=30s)
    atk = AttackSession(ATTACKER_IP, RTU1_IP, 44000, ts=BASE_TS + 30)
    atk.handshake()
    atk.send_startdt()
    atk.send_interrogation_cycle()
    atk.advance(5.0)
    # 3 single commands from attacker
    for ioa in [100, 200, 300]:
        atk.send_sc_command(1, ioa, on=True, is_attack=True)
        atk.advance(5.0)

    merged = _merge_sessions(legit, atk)
    filename = "atk03_topology_new_peer.pcap"
    write_pcap_stream(output_dir / filename, merged)
    return AttackResult(
        name="topology_new_peer",
        filename=filename,
        mitre_technique="Remote System Discovery + Unauthorized Command",
        mitre_id="T0846+T0855",
        expected_channels=["ml_ensemble"],
        difficulty="easy",
        duration_sec=120,
        n_attack_packets=atk._attack_pkt_count,
        n_total_packets=len(merged),
        description="Attacker (192.168.10.200) opens new TCP to RTU-1 "
                    "(never-seen peer). Interrogates then sends 3x C_SC_NA_1. "
                    "Tests new-peer-pair detection.",
    )


# ---------------------------------------------------------------------------
# ATK-04: topology_lateral
# ---------------------------------------------------------------------------
def generate_topology_lateral(output_dir: Path) -> AttackResult:
    # HMI -> RTU-1 (continuous, 300s)
    sess1 = AttackSession(HMI_IP, RTU1_IP, 36404, ts=BASE_TS)
    sess1.handshake()
    sess1.send_startdt()
    _fill_baseline(sess1, 300.0)

    # HMI -> RTU-2 (starts at t=120s, common_addr=2)
    sess2 = AttackSession(HMI_IP, RTU2_IP, 36405, ts=BASE_TS + 120)
    sess2.handshake()
    sess2.send_startdt()
    sess2.send_interrogation_cycle(common_addr=2)
    sess2.advance(5.0)
    # Phase 3: mirror commands to RTU-2
    for ioa in [500, 501, 502]:
        sess2.send_dc_command(2, ioa, dcs_on=True, is_attack=True)
        sess2.advance(10.0)
    for ioa in [500, 501, 502]:
        sess2.send_setpoint(2, ioa, 0.75, is_attack=True)
        sess2.advance(10.0)

    merged = _merge_sessions(sess1, sess2)
    filename = "atk04_topology_lateral.pcap"
    write_pcap_stream(output_dir / filename, merged)
    return AttackResult(
        name="topology_lateral",
        filename=filename,
        mitre_technique="Multi-Station Communication",
        mitre_id="T0812",
        expected_channels=["ml_ensemble"],
        difficulty="medium",
        duration_sec=300,
        n_attack_packets=sess2._attack_pkt_count,
        n_total_packets=len(merged),
        description="HMI pivots to RTU-2 (192.168.10.101) at t=120s while "
                    "maintaining RTU-1 session. Mirrors commands to second station. "
                    "Tests new-peer + src_out_degree_2404 jump.",
    )


# ---------------------------------------------------------------------------
# ATK-05: legitimate_abuse
# ---------------------------------------------------------------------------
def generate_legitimate_abuse(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36405)
    session.handshake()
    session.send_startdt()
    session.send_interrogation_cycle()
    session.advance(5.0)

    # (a) Commands to IOAs outside normal range (9000-9005)
    for ioa in range(9000, 9006):
        session.send_setpoint(1, ioa, 0.75, is_attack=True)
        session.advance(5.0)

    # Normal interrogation cycle in between
    session.send_interrogation_cycle()
    session.advance(10.0)

    # (b) Extreme values on known-ish IOAs
    session.send_setpoint(1, 1001, 0.99, is_attack=True)
    session.advance(5.0)
    session.send_setpoint(1, 1002, -0.95, is_attack=True)
    session.advance(5.0)

    # Normal interrogation
    session.send_interrogation_cycle()
    session.advance(10.0)

    # (c) Opposing setpoints 30s apart on same IOA
    session.send_setpoint(1, 1001, 0.95, is_attack=True)
    session.advance(30.0)
    session.send_setpoint(1, 1001, -0.95, is_attack=True)
    session.advance(5.0)

    # Tail baseline
    _fill_baseline(session, 60.0)

    filename = "atk05_legitimate_abuse.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="legitimate_abuse",
        filename=filename,
        mitre_technique="Modify Parameter",
        mitre_id="T0836",
        expected_channels=["ml_ensemble"],
        difficulty="hard",
        duration_sec=180,
        n_attack_packets=session._attack_pkt_count,
        n_total_packets=len(session.records),
        description="Protocol-compliant C_SE_NA_1 with full ACT/ACTCON/ACTTERM "
                    "but: (a) IOAs 9000-9005 outside normal range, "
                    "(b) extreme values +/-0.95, (c) opposing setpoints 30s apart. "
                    "Tests ioa_entropy. Completeness should NOT fire.",
        ablation_params={"ioa_range_start": 9000, "value_extremity": 0.95,
                         "opposing_delay_sec": 30},
    )


# ---------------------------------------------------------------------------
# ATK-06: unseen_typeids
# ---------------------------------------------------------------------------
TYPEID_C_RC_NA_1 = 47   # Regulating step command
TYPEID_P_ME_NA_1 = 110  # Parameter of measured value, normalized
TYPEID_F_SC_NA_1 = 122  # Call directory/section/file
COT_FILE = 13


def generate_unseen_typeids(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36406)
    session.handshake()
    session.send_startdt()

    # Lead-in baseline (ensures I-frame data spans > 60s for windowing)
    _fill_baseline(session, 90.0)

    # (a) C_RC_NA_1 -- step command: RCS up/down
    for ioa in [200, 201, 202]:
        rcs = 0x01  # step up
        session.send_command_full(
            TYPEID_C_RC_NA_1, 1, ioa, bytes([rcs]), is_attack=True)
        session.advance(3.0)

    session.send_interrogation_cycle()
    session.advance(5.0)

    # (b) P_ME_NA_1 -- parameter setting
    nva = int(0.6 * 32767)
    param_info = struct.pack("<hB", nva, 0)
    session.send_command_full(
        TYPEID_P_ME_NA_1, 1, 300, param_info, is_attack=True)
    session.advance(5.0)

    session.send_interrogation_cycle()
    session.advance(5.0)

    # (c) F_SC_NA_1 -- file transfer call
    #     info: NOF (name of file, 2 bytes) + NOS (name of section, 1 byte) + SCQ (1 byte)
    file_info = struct.pack("<HBB", 1, 0, 1)  # file 1, section 0, select
    # File transfer uses COT=13 (file)
    act = build_iframe_with_pn(
        TYPEID_F_SC_NA_1, COT_FILE, 1, 0, file_info,
        session.hmi_seq, pn=False)
    session.records.append(session.stream.send_client(session.ts, act))
    session._attack_pkt_count += 1
    session.advance(2.0)

    # Tail baseline
    _fill_baseline(session, 60.0)

    filename = "atk06_unseen_typeids.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="unseen_typeids",
        filename=filename,
        mitre_technique="Unauthorized Command + Modify Parameter",
        mitre_id="T0855+T0836",
        expected_channels=["ml_ensemble"],
        difficulty="medium",
        duration_sec=120,
        n_attack_packets=session._attack_pkt_count,
        n_total_packets=len(session.records),
        description="Novel TypeIDs never seen in training: "
                    "(a) C_RC_NA_1 (47, step) on IOAs 200-202, "
                    "(b) P_ME_NA_1 (110, parameter) on IOA 300, "
                    "(c) F_SC_NA_1 (122, file). Tests typeID_entropy.",
        ablation_params={"include_typeids": [47, 110, 122]},
    )


# ---------------------------------------------------------------------------
# ATK-07: partial_interrupted
# ---------------------------------------------------------------------------
def generate_partial_interrupted(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36407)
    session.handshake()
    session.send_startdt()
    session.send_interrogation_cycle()
    session.advance(5.0)

    # (a) 5x C_DC_NA_1 ACT with NO ACTCON (orphan commands)
    for i in range(5):
        session.send_dc_command(
            1, 500 + i, dcs_on=True,
            include_actcon=False, include_actterm=False,
            is_attack=True)
        session.advance(2.0)

    session.advance(10.0)

    # (b) 4x rapid STARTDT_ACT without CON
    for _ in range(4):
        session.records.append(session.stream.send_client(
            session.ts, build_uframe(UFRAME_STARTDT_ACT)))
        session._attack_pkt_count += 1
        session.advance(0.5)

    session.advance(10.0)

    # (c) 10x TESTFR_ACT with only 2 CON (20% success)
    for i in range(10):
        session.records.append(session.stream.send_client(
            session.ts, build_uframe(UFRAME_TESTFR_ACT)))
        session._attack_pkt_count += 1
        session.advance(0.5)
        if i in (3, 7):  # Only 2 responses
            session.records.append(session.stream.send_server(
                session.ts, build_uframe(UFRAME_TESTFR_CON)))
        session.advance(2.5)

    # Tail baseline
    _fill_baseline(session, 120.0)

    filename = "atk07_partial_interrupted.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="partial_interrupted",
        filename=filename,
        mitre_technique="Unauthorized Command + Denial of Service",
        mitre_id="T0855+T0814",
        expected_channels=["completeness", "ml_ensemble"],
        difficulty="medium",
        duration_sec=180,
        n_attack_packets=session._attack_pkt_count,
        n_total_packets=len(session.records),
        description="(a) 5x C_DC_NA_1 ACT with NO ACTCON (orphan commands), "
                    "(b) 4x STARTDT_ACT without CON, "
                    "(c) 10x TESTFR_ACT with 20% response rate. "
                    "Tests completeness channel.",
        ablation_params={"n_orphan_commands": 5, "testfr_success_ratio": 0.2},
    )


# ---------------------------------------------------------------------------
# ATK-08: slow_toggle
# ---------------------------------------------------------------------------
def generate_slow_toggle(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36408)
    session.handshake()
    session.send_startdt()

    duration = 300.0
    toggle_interval = 10.0
    n_toggles = int(duration / toggle_interval)  # 30 toggles
    end_ts = session.ts + duration
    next_toggle = session.ts + toggle_interval

    interrog_interval = 60.0
    testfr_interval = 30.0
    next_interrog = session.ts + interrog_interval
    next_testfr = session.ts + testfr_interval
    toggle_idx = 0

    while session.ts < end_ts:
        next_event = min(next_interrog, next_testfr, next_toggle, end_ts)
        if next_event >= end_ts:
            break
        session.ts = next_event

        if abs(next_event - next_toggle) < 0.5 and toggle_idx < n_toggles:
            session.send_dc_command(
                1, 500, dcs_on=(toggle_idx % 2 == 0), is_attack=True)
            toggle_idx += 1
            next_toggle += toggle_interval

        if abs(next_event - next_testfr) < 0.5:
            session.send_testfr()
            next_testfr += testfr_interval

        if abs(next_event - next_interrog) < 0.5:
            session.send_interrogation_cycle()
            next_interrog += interrog_interval

    filename = "atk08_slow_toggle.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="slow_toggle",
        filename=filename,
        mitre_technique="Manipulation of Control",
        mitre_id="T0831",
        expected_channels=["frequency", "ml_ensemble"],
        difficulty="hard",
        duration_sec=300,
        n_attack_packets=session._attack_pkt_count,
        n_total_packets=len(session.records),
        description="ON/OFF C_DC_NA_1 toggle on IOA 500 every 10s "
                    f"({n_toggles} toggles). Full ACT/ACTCON/ACTTERM. "
                    "Sub-threshold command_rate but physically damaging.",
        ablation_params={"toggle_interval_sec": 10, "n_ioas": 1,
                         "total_toggles": n_toggles},
    )


# ---------------------------------------------------------------------------
# ATK-09: chained_multi_stage
# ---------------------------------------------------------------------------
def generate_chained_multi_stage(output_dir: Path) -> AttackResult:
    session = AttackSession(HMI_IP, RTU1_IP, 36409)
    session.handshake()
    session.send_startdt()

    duration = 3600.0  # 1 hour
    end_ts = session.ts + duration

    interrog_interval = 60.0
    testfr_interval = 30.0
    next_interrog = session.ts + interrog_interval
    next_testfr = session.ts + testfr_interval

    # Phase boundaries (relative to session start)
    phase_start = session.ts
    p1_start, p1_end = phase_start + 0, phase_start + 600       # Recon
    p2_start, p2_end = phase_start + 600, phase_start + 1200    # Collection
    p3_start, p3_end = phase_start + 1800, phase_start + 2400   # Parameter
    p4_start, p4_end = phase_start + 3000, phase_start + 3600   # Execution

    # Phase-specific event schedules
    p1_addrs = [2, 3]  # Probe station addresses 2, 3
    p1_next = p1_start + 120.0  # First probe at 2 min
    p1_idx = 0

    p2_ioas = [100, 101, 102, 103, 104, 105]
    p2_next = p2_start + 30.0  # First read at 30s into phase
    p2_idx = 0

    p3_targets = [(1001, 0.525), (1002, 0.530), (1003, 0.520)]
    p3_next = p3_start + 120.0  # First write at 2 min into phase
    p3_idx = 0

    p4_targets = [500, 501, 502, 500, 501]
    p4_next = p4_start + 60.0
    p4_idx = 0

    while session.ts < end_ts:
        candidates = [next_interrog, next_testfr, end_ts]
        if p1_idx < len(p1_addrs):
            candidates.append(p1_next)
        if p2_idx < len(p2_ioas) * 3:  # 3 rounds of 6 IOAs
            candidates.append(p2_next)
        if p3_idx < len(p3_targets):
            candidates.append(p3_next)
        if p4_idx < len(p4_targets):
            candidates.append(p4_next)

        next_event = min(candidates)
        if next_event >= end_ts:
            break
        session.ts = next_event

        # Phase 1: Recon -- 2 extra interrogations to different stations
        if p1_idx < len(p1_addrs) and abs(next_event - p1_next) < 0.5:
            addr = p1_addrs[p1_idx]
            session.send_interrogation_cycle(common_addr=addr, n_responses=5)
            session._attack_pkt_count += 8  # ~8 packets per cycle
            p1_idx += 1
            p1_next += 180.0

        # Phase 2: Collection -- read commands
        if p2_idx < len(p2_ioas) * 3 and abs(next_event - p2_next) < 0.5:
            ioa = p2_ioas[p2_idx % len(p2_ioas)]
            # C_RD_NA_1 read command
            rd = build_iframe_with_pn(
                TYPEID_C_RD_NA_1, COT_REQUEST, 1, ioa,
                b"", session.hmi_seq, pn=False)
            session.records.append(session.stream.send_client(session.ts, rd))
            session._attack_pkt_count += 1
            session.advance(0.200)
            # RTU responds with M_ME_NA_1
            nva_val = int(0.5 * 32767)
            resp_info = struct.pack("<hB", nva_val, 0)
            resp = build_iframe_with_pn(
                TYPEID_M_ME_NA_1, COT_REQUEST, 1, ioa,
                resp_info, session.rtu_seq, pn=False)
            session.records.append(session.stream.send_server(session.ts, resp))
            p2_idx += 1
            p2_next += 30.0

        # Phase 3: Parameter -- subtle setpoint shifts
        if p3_idx < len(p3_targets) and abs(next_event - p3_next) < 0.5:
            ioa, value = p3_targets[p3_idx]
            session.send_setpoint(1, ioa, value, is_attack=True)
            p3_idx += 1
            p3_next += 180.0

        # Phase 4: Execution -- commands
        if p4_idx < len(p4_targets) and abs(next_event - p4_next) < 0.5:
            ioa = p4_targets[p4_idx]
            session.send_dc_command(1, ioa, dcs_on=True, is_attack=True)
            p4_idx += 1
            p4_next += 60.0

        # Background: interrogation + TESTFR
        if abs(next_event - next_testfr) < 0.5:
            session.send_testfr()
            next_testfr += testfr_interval
        if abs(next_event - next_interrog) < 0.5:
            session.send_interrogation_cycle()
            session.send_spontaneous_monitoring()
            next_interrog += interrog_interval

    filename = "atk09_chained_multi_stage.pcap"
    write_pcap_stream(output_dir / filename, session.records)
    return AttackResult(
        name="chained_multi_stage",
        filename=filename,
        mitre_technique="Discovery -> Collection -> Parameter -> Control",
        mitre_id="T0888+T0801+T0836+T0831",
        expected_channels=["ml_ensemble"],
        difficulty="expert",
        duration_sec=3600,
        n_attack_packets=session._attack_pkt_count,
        n_total_packets=len(session.records),
        description="1-hour kill chain: Phase 1 (recon, 2 interrogations to "
                    "alt stations), Phase 2 (collection, reads every 30s), "
                    "Phase 3 (parameter, 5% setpoint drift), Phase 4 (execution, "
                    "5 commands). Each phase individually sub-threshold.",
        ablation_params={"phase_gap_sec": 600, "per_phase_intensity": "low"},
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
ATTACK_REGISTRY: dict[str, callable] = {
    "clean_baseline": generate_clean_baseline,
    "short_burst": generate_short_burst,
    "low_and_slow": generate_low_and_slow,
    "topology_new_peer": generate_topology_new_peer,
    "topology_lateral": generate_topology_lateral,
    "legitimate_abuse": generate_legitimate_abuse,
    "unseen_typeids": generate_unseen_typeids,
    "partial_interrupted": generate_partial_interrupted,
    "slow_toggle": generate_slow_toggle,
    "chained_multi_stage": generate_chained_multi_stage,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Surgical IEC-104 Attack PCAP Generator")
    parser.add_argument(
        "--attack", type=str, default=None,
        help="Generate a single attack (name from --list)")
    parser.add_argument(
        "--list", action="store_true",
        help="List available attack scenarios")
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path("output") / "attack_pcaps")
    parser.add_argument(
        "--manifest", action="store_true",
        help="Generate manifest.json only (requires PCAPs already generated)")
    args = parser.parse_args()

    if args.list:
        print("Available attack scenarios:")
        print(f"{'Name':<25} {'MITRE':<20} {'Difficulty':<10}")
        print("-" * 55)
        for name in ATTACK_REGISTRY:
            print(f"  {name:<23}", end="")
            labels = {
                "clean_baseline": ("N/A", "control"),
                "short_burst": ("T0831", "medium"),
                "low_and_slow": ("T0836", "hard"),
                "topology_new_peer": ("T0846+T0855", "easy"),
                "topology_lateral": ("T0812", "medium"),
                "legitimate_abuse": ("T0836", "hard"),
                "unseen_typeids": ("T0855+T0836", "medium"),
                "partial_interrupted": ("T0855+T0814", "medium"),
                "slow_toggle": ("T0831", "hard"),
                "chained_multi_stage": ("T0888+...", "expert"),
            }
            m, d = labels.get(name, ("?", "?"))
            print(f"{m:<20} {d:<10}")
        return

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.attack:
        if args.attack not in ATTACK_REGISTRY:
            print(f"Unknown attack: {args.attack}")
            print(f"Available: {', '.join(ATTACK_REGISTRY.keys())}")
            sys.exit(1)
        attacks_to_run = {args.attack: ATTACK_REGISTRY[args.attack]}
    else:
        attacks_to_run = ATTACK_REGISTRY

    results = []
    for name, func in attacks_to_run.items():
        print(f"\n[*] Generating {name}...")
        result = func(args.output_dir)
        results.append(result)
        print(f"    -> {result.filename}: {result.n_total_packets} pkts "
              f"({result.n_attack_packets} attack), "
              f"{result.duration_sec:.0f}s, {result.difficulty}")

    # Write manifest
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_dir": str(args.output_dir),
        "attacks": [r.to_manifest_entry() for r in results],
    }
    manifest_path = args.output_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)
    print(f"\n[+] Manifest: {manifest_path}")
    print(f"[+] Generated {len(results)} PCAPs in {args.output_dir}")

    # Summary table
    print(f"\n{'Attack':<25} {'Pkts':>6} {'Atk':>5} {'Duration':>10} {'Difficulty':<10}")
    print("-" * 60)
    for r in results:
        dur = f"{r.duration_sec:.0f}s"
        if r.duration_sec >= 3600:
            dur = f"{r.duration_sec/3600:.1f}h"
        print(f"  {r.name:<23} {r.n_total_packets:>6} {r.n_attack_packets:>5} "
              f"{dur:>10} {r.difficulty:<10}")


if __name__ == "__main__":
    main()
