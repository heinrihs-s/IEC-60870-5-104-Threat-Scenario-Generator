#!/usr/bin/env python3
"""Generate a minimal IEC-104 PCAP with C_DC negative confirmation.

Creates a valid IEC-104 conversation:
  1. STARTDT ACT/CON handshake
  2. C_DC_NA_1 ACT command (double command, IOA=500, DCS=ON)
  3. C_DC_NA_1 ACTCON response with P/N=1 (negative confirmation)

This validates polarity detection of control-command rejections
through the full pipeline path.

Usage:
    python generate_neg_confirm_pcap.py [--output-dir DIR]
"""
from __future__ import annotations

import argparse
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from simulate_8_stages import (
    APCI_START, IEC104_PORT,
    COT_ACT, COT_ACTCON, COT_ACTTERM,
    TYPEID_C_DC_NA_1, TYPEID_C_SE_NA_1,
    SequenceCounter,
    build_uframe, UFRAME_STARTDT_ACT, UFRAME_STARTDT_CON,
    write_pcap,
)


def build_iframe_with_pn(
    type_id: int,
    cot: int,
    common_addr: int,
    ioa: int,
    info_elements: bytes,
    seq: SequenceCounter,
    pn: bool = False,
    originator: int = 0,
) -> bytes:
    """Build an I-frame with explicit P/N (positive/negative) qualifier.

    The P/N bit is bit 6 of the COT byte in the ASDU header.
    pn=True means negative confirmation (command rejected).
    """
    send_n = seq.next_send()
    recv_n = seq.recv_seq
    ctrl = struct.pack("<HH", send_n << 1, recv_n << 1)

    # COT byte: bits 0-5 = cause, bit 6 = P/N, bit 7 = T (test)
    cot_byte = (cot & 0x3F) | (0x40 if pn else 0x00)

    vsq = 0x01  # SQ=0, num_objects=1
    asdu_header = struct.pack("<BBB", type_id, vsq, cot_byte)
    asdu_header += struct.pack("<B", originator)
    asdu_header += struct.pack("<H", common_addr)

    ioa_bytes = struct.pack("<I", ioa)[:3]

    apdu_payload = ctrl + asdu_header + ioa_bytes + info_elements
    length = len(apdu_payload)
    return bytes([APCI_START, length]) + apdu_payload


def _pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


class TcpStream:
    """Manages TCP sequence numbers and generates valid TCP segments."""

    def __init__(self, src_ip: bytes, dst_ip: bytes,
                 src_port: int, dst_port: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.client_seq = 1000
        self.server_seq = 2000
        self.ip_id = 1

    @staticmethod
    def _ip_checksum(header: bytes) -> int:
        """Compute IP header checksum (RFC 1071)."""
        if len(header) % 2:
            header += b"\x00"
        s = sum(struct.unpack(f">{len(header)//2}H", header))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    def _make_packet(self, ts: float, src_ip: bytes, dst_ip: bytes,
                     src_port: int, dst_port: int,
                     seq: int, ack: int, flags: int,
                     payload: bytes = b"") -> bytes:
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        eth = bytes(6) + bytes(6) + b"\x08\x00"
        ip_total_len = 20 + 20 + len(payload)
        # Build IP header with checksum = 0, then compute real checksum
        ip_header = struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0, ip_total_len, self.ip_id, 0x4000, 64, 6, 0,
            src_ip, dst_ip,
        )
        checksum = self._ip_checksum(ip_header)
        ip_header = struct.pack(
            ">BBHHHBBH4s4s",
            0x45, 0, ip_total_len, self.ip_id, 0x4000, 64, 6, checksum,
            src_ip, dst_ip,
        )
        self.ip_id += 1

        # Build TCP header with checksum = 0, then compute TCP checksum
        tcp_header = struct.pack(
            ">HHIIBBHHH",
            src_port, dst_port, seq, ack,
            0x50, flags, 65535, 0, 0,
        )
        # TCP checksum uses pseudo-header: src_ip + dst_ip + proto + tcp_len
        tcp_len = len(tcp_header) + len(payload)
        pseudo = src_ip + dst_ip + struct.pack(">BBH", 0, 6, tcp_len)
        tcp_cksum = self._ip_checksum(pseudo + tcp_header + payload)
        tcp_header = struct.pack(
            ">HHIIBBHHH",
            src_port, dst_port, seq, ack,
            0x50, flags, 65535, tcp_cksum, 0,
        )

        frame = eth + ip_header + tcp_header + payload
        return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame

    def handshake(self, ts: float) -> list[bytes]:
        """Generate TCP 3-way handshake. Returns raw PCAP records."""
        pkts = []
        # SYN
        pkts.append(self._make_packet(
            ts, self.src_ip, self.dst_ip,
            self.src_port, self.dst_port,
            self.client_seq, 0, 0x02))  # SYN
        self.client_seq += 1
        # SYN-ACK
        pkts.append(self._make_packet(
            ts + 0.001, self.dst_ip, self.src_ip,
            self.dst_port, self.src_port,
            self.server_seq, self.client_seq, 0x12))  # SYN+ACK
        self.server_seq += 1
        # ACK
        pkts.append(self._make_packet(
            ts + 0.002, self.src_ip, self.dst_ip,
            self.src_port, self.dst_port,
            self.client_seq, self.server_seq, 0x10))  # ACK
        return pkts

    def send_client(self, ts: float, payload: bytes) -> bytes:
        """Client -> Server data segment."""
        pkt = self._make_packet(
            ts, self.src_ip, self.dst_ip,
            self.src_port, self.dst_port,
            self.client_seq, self.server_seq, 0x18, payload)  # PSH+ACK
        self.client_seq += len(payload)
        return pkt

    def send_server(self, ts: float, payload: bytes) -> bytes:
        """Server -> Client data segment."""
        pkt = self._make_packet(
            ts, self.dst_ip, self.src_ip,
            self.dst_port, self.src_port,
            self.server_seq, self.client_seq, 0x18, payload)  # PSH+ACK
        self.server_seq += len(payload)
        return pkt


def write_pcap_stream(path: Path, raw_records: list[bytes]):
    """Write raw PCAP records (already including headers) to file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(_pcap_global_header())
        for rec in raw_records:
            f.write(rec)
    print(f"Wrote {len(raw_records)} packets to {path}")


# ---------------------------------------------------------------------------
# Synthetic IPs (not from any real environment)
# ---------------------------------------------------------------------------
_HMI_IP = b"\xC0\xA8\x0A\x01"    # 192.168.10.1  (HMI)
_RTU_IP = b"\xC0\xA8\x0A\x66"    # 192.168.10.102 (RTU)


def generate_c_dc_neg_confirm(output_dir: Path) -> Path:
    """Generate PCAP: C_DC_NA_1 with negative ActCon (pn=True).

    Includes proper TCP 3-way handshake so Zeek/Spicy can reassemble the
    stream and decode IEC-104 protocol fields including the P/N bit.

    Scenario:
    - HMI (192.168.10.1:36428) sends C_DC_NA_1 ACT to RTU (192.168.10.102:2404)
    - RTU responds with C_DC_NA_1 ACTCON with P/N=1 (negative = command rejected)
    - Then C_SE_NA_1 ACT -> ACTCON with P/N=1 (also negative)
    """
    base_ts = datetime(2026, 3, 14, 12, 0, 0, tzinfo=timezone.utc).timestamp()

    hmi_ip = _HMI_IP
    rtu_ip = _RTU_IP
    hmi_port = 36428
    rtu_port = 2404

    common_addr = 1
    ioa = 500
    dco_on = 0x02  # DCS=ON

    hmi_seq = SequenceCounter()
    rtu_seq = SequenceCounter()

    stream = TcpStream(hmi_ip, rtu_ip, hmi_port, rtu_port)
    records = []
    ts = base_ts

    # TCP 3-way handshake
    records.extend(stream.handshake(ts))
    ts += 0.010

    # 1. STARTDT ACT/CON (link activation)
    records.append(stream.send_client(ts, build_uframe(UFRAME_STARTDT_ACT)))
    ts += 0.050
    records.append(stream.send_server(ts, build_uframe(UFRAME_STARTDT_CON)))
    ts += 0.100

    # 2. Interrogation cycle (needed for Zeek protocol detection)
    ic_act = build_iframe_with_pn(
        100, COT_ACT, common_addr, 0, bytes([20]), hmi_seq, pn=False,
    )
    records.append(stream.send_client(ts, ic_act))
    ts += 0.050
    ic_actcon = build_iframe_with_pn(
        100, COT_ACTCON, common_addr, 0, bytes([20]), rtu_seq, pn=False,
    )
    records.append(stream.send_server(ts, ic_actcon))
    ts += 0.010
    for resp_ioa in range(1, 11):
        info = bytes([0x00])
        resp = build_iframe_with_pn(
            1, 20, common_addr, resp_ioa, info, rtu_seq, pn=False,
        )
        records.append(stream.send_server(ts, resp))
        ts += 0.005
    ic_actterm = build_iframe_with_pn(
        100, COT_ACTTERM, common_addr, 0, bytes([20]), rtu_seq, pn=False,
    )
    records.append(stream.send_server(ts, ic_actterm))
    ts += 0.500

    # 3. C_DC_NA_1 ACT (HMI -> RTU) -- the negative confirm test
    act_frame = build_iframe_with_pn(
        TYPEID_C_DC_NA_1, COT_ACT, common_addr, ioa,
        bytes([dco_on]), hmi_seq, pn=False,
    )
    records.append(stream.send_client(ts, act_frame))
    ts += 0.200

    # 3. C_DC_NA_1 ACTCON with P/N=1 (RTU -> HMI): NEGATIVE
    actcon_neg = build_iframe_with_pn(
        TYPEID_C_DC_NA_1, COT_ACTCON, common_addr, ioa,
        bytes([dco_on]), rtu_seq, pn=True,
    )
    records.append(stream.send_server(ts, actcon_neg))
    ts += 1.0

    # 4. C_SE_NA_1 ACT (HMI -> RTU)
    nva = int(0.5 * 32767)
    se_info = struct.pack("<hB", nva, 0)
    se_act = build_iframe_with_pn(
        TYPEID_C_SE_NA_1, COT_ACT, common_addr, 1001,
        se_info, hmi_seq, pn=False,
    )
    records.append(stream.send_client(ts, se_act))
    ts += 0.300

    # 5. C_SE_NA_1 ACTCON with P/N=1 (RTU -> HMI): NEGATIVE
    se_neg = build_iframe_with_pn(
        TYPEID_C_SE_NA_1, COT_ACTCON, common_addr, 1001,
        se_info, rtu_seq, pn=True,
    )
    records.append(stream.send_server(ts, se_neg))

    pcap_path = output_dir / "c_dc_c_se_neg_confirm.pcap"
    write_pcap_stream(pcap_path, records)
    return pcap_path


def generate_c_dc_positive_confirm(output_dir: Path) -> Path:
    """Generate PCAP: C_DC_NA_1 with POSITIVE ActCon (pn=False) for contrast."""
    base_ts = datetime(2026, 3, 14, 12, 5, 0, tzinfo=timezone.utc).timestamp()

    hmi_ip = _HMI_IP
    rtu_ip = _RTU_IP

    hmi_seq = SequenceCounter()
    rtu_seq = SequenceCounter()

    stream = TcpStream(hmi_ip, rtu_ip, 36429, 2404)
    records = []
    ts = base_ts

    # TCP handshake
    records.extend(stream.handshake(ts))
    ts += 0.010

    # STARTDT
    records.append(stream.send_client(ts, build_uframe(UFRAME_STARTDT_ACT)))
    ts += 0.050
    records.append(stream.send_server(ts, build_uframe(UFRAME_STARTDT_CON)))
    ts += 0.100

    # Interrogation cycle
    ic_act = build_iframe_with_pn(100, COT_ACT, 1, 0, bytes([20]), hmi_seq, pn=False)
    records.append(stream.send_client(ts, ic_act))
    ts += 0.050
    ic_actcon = build_iframe_with_pn(100, COT_ACTCON, 1, 0, bytes([20]), rtu_seq, pn=False)
    records.append(stream.send_server(ts, ic_actcon))
    ts += 0.010
    for resp_ioa in range(1, 11):
        resp = build_iframe_with_pn(1, 20, 1, resp_ioa, bytes([0x00]), rtu_seq, pn=False)
        records.append(stream.send_server(ts, resp))
        ts += 0.005
    ic_actterm = build_iframe_with_pn(100, COT_ACTTERM, 1, 0, bytes([20]), rtu_seq, pn=False)
    records.append(stream.send_server(ts, ic_actterm))
    ts += 0.500

    # C_DC ACT (positive)
    act = build_iframe_with_pn(
        TYPEID_C_DC_NA_1, COT_ACT, 1, 500,
        bytes([0x02]), hmi_seq, pn=False,
    )
    records.append(stream.send_client(ts, act))
    ts += 0.200

    # C_DC ACTCON (positive -- normal)
    actcon = build_iframe_with_pn(
        TYPEID_C_DC_NA_1, COT_ACTCON, 1, 500,
        bytes([0x02]), rtu_seq, pn=False,
    )
    records.append(stream.send_server(ts, actcon))
    ts += 0.500

    # C_DC ACTTERM (normal completion)
    actterm = build_iframe_with_pn(
        TYPEID_C_DC_NA_1, COT_ACTTERM, 1, 500,
        bytes([0x02]), rtu_seq, pn=False,
    )
    records.append(stream.send_server(ts, actterm))

    pcap_path = output_dir / "c_dc_positive_confirm.pcap"
    write_pcap_stream(pcap_path, records)
    return pcap_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path("output") / "pcaps",
    )
    args = parser.parse_args()

    neg_pcap = generate_c_dc_neg_confirm(args.output_dir)
    pos_pcap = generate_c_dc_positive_confirm(args.output_dir)

    print(f"\nGenerated PCAPs:")
    print(f"  Negative confirm: {neg_pcap}")
    print(f"  Positive confirm: {pos_pcap}")
