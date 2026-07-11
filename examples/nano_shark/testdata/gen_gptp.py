#!/usr/bin/env python3
"""Build a synthetic pcapng capture containing gPTP-over-Ethernet (ethertype 0x88F7) frames.

Copied from bindings/python/gptp/build_fixture.py (that file is untouched; this is a copy so
nano_shark's tests don't reach across into the Python-bindings tree) -- covers all 8 gPTP message
kinds, a Follow_Up Information TLV, and an Announce PATH_TRACE TLV with 3 entries, using the same
minimal pcapng SHB/IDB/EPB layout the rest of this repo's examples already use. EXPECTED holds
every value used to construct the messages, so a test can assert against ground truth it didn't
duplicate by hand.

    python gen_gptp.py [out.pcapng]     # default: gptp_fixture.pcapng next to this script
"""
import pathlib
import struct
import sys

# ---- big-endian field packers (gPTP/Ethernet wire bytes are always network byte order) ----
def _u8(x):  return struct.pack(">B", x)
def _i8(x):  return struct.pack(">b", x)
def _u16(x): return struct.pack(">H", x)
def _i16(x): return struct.pack(">h", x)
def _u32(x): return struct.pack(">I", x)
def _i32(x): return struct.pack(">i", x)
def _i64(x): return struct.pack(">q", x)
def _u48(x):
    assert 0 <= x < (1 << 48)
    return struct.pack(">Q", x)[2:]  # low 48 bits of the 64-bit big-endian encoding


# ---- message-type tags (must match nmgptp::kMsg* in gptp_rows.hpp) ----
MSG_SYNC, MSG_DELAY_REQ, MSG_PDELAY_REQ, MSG_PDELAY_RESP = 0x0, 0x1, 0x2, 0x3
MSG_FOLLOW_UP, MSG_DELAY_RESP, MSG_PDELAY_RESP_FOLLOW_UP, MSG_ANNOUNCE = 0x8, 0x9, 0xA, 0xB

TLV_ORG_EXTENSION = 0x0003
TLV_PATH_TRACE = 0x0008

ETHERTYPE_GPTP = 0x88F7


def _header(message_type, msg_length, seq, *, domain=0, correction=0,
            clock_id=bytes(range(0xA0, 0xA8)), port=1, log_interval=0):
    """The 34-byte common PTP/gPTP header (see nmgptp::GptpHeader)."""
    assert len(clock_id) == 8
    b = bytearray()
    b += _u8((0 << 4) | (message_type & 0xF))   # transportSpecific:4 | messageType:4
    b += _u8((0 << 4) | 2)                       # reserved:4 | versionPTP:4 (=2)
    b += _u16(msg_length)
    b += _u8(domain)
    b += _u8(0)                                   # reserved
    b += _u16(0)                                  # flags
    b += _i64(correction)
    b += _u32(0)                                  # reserved
    b += clock_id                                 # sourcePortIdentity.clockIdentity
    b += _u16(port)                                # sourcePortIdentity.portNumber
    b += _u16(seq)
    b += _u8(0)                                    # controlField
    b += _i8(log_interval)
    assert len(b) == 34
    return bytes(b)


def _timestamp(seconds, nanoseconds):
    return _u48(seconds) + _u32(nanoseconds)


def _port_identity(clock_id, port):
    assert len(clock_id) == 8
    return clock_id + _u16(port)


def build_messages():
    """Returns (messages: list[bytes], expected: dict) — one raw gPTP message per list entry."""
    messages = []
    exp = {"path_trace_entries": []}

    # ---- Sync ----
    seq, ts = 100, (1_700_000_000, 111_000_000)
    body = _timestamp(*ts)
    messages.append(_header(MSG_SYNC, 34 + len(body), seq) + body)
    exp["sync"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1]}

    # ---- Delay_Req ----
    seq, ts = 101, (1_700_000_001, 222_000_000)
    body = _timestamp(*ts)
    messages.append(_header(MSG_DELAY_REQ, 34 + len(body), seq) + body)
    exp["delay_req"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1]}

    # ---- Pdelay_Req (Timestamp + 10 reserved bytes) ----
    seq, ts = 102, (1_700_000_002, 333_000_000)
    body = _timestamp(*ts) + bytes(10)
    messages.append(_header(MSG_PDELAY_REQ, 34 + len(body), seq) + body)
    exp["pdelay_req"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1]}

    # ---- Pdelay_Resp (Timestamp + requestingPortIdentity) ----
    seq, ts = 103, (1_700_000_003, 444_000_000)
    req_clock, req_port = bytes(range(0xE0, 0xE8)), 7
    body = _timestamp(*ts) + _port_identity(req_clock, req_port)
    messages.append(_header(MSG_PDELAY_RESP, 34 + len(body), seq) + body)
    exp["pdelay_resp"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1],
                          "requesting_clock_identity": req_clock, "requesting_port_number": req_port}

    # ---- Follow_Up (Timestamp + Follow_Up Information TLV) ----
    seq, ts = 104, (1_700_000_004, 555_000_000)
    rate_offset, gm_time_base, freq_change = -100, 3, -55
    tlv_value = (b"\x00\x80\xC2" +          # organizationId (802.1 OUI)
                 b"\x00\x00\x01" +          # organizationSubType = 1 (follow-up information)
                 _i32(rate_offset) + _u16(gm_time_base) + bytes(12) + _i32(freq_change))
    assert len(tlv_value) == 28
    tlv = _u16(TLV_ORG_EXTENSION) + _u16(len(tlv_value)) + tlv_value
    body = _timestamp(*ts) + tlv
    messages.append(_header(MSG_FOLLOW_UP, 34 + len(body), seq) + body)
    exp["follow_up"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1],
                        "cumulative_scaled_rate_offset": rate_offset,
                        "gm_time_base_indicator": gm_time_base, "scaled_last_gm_freq_change": freq_change}

    # ---- Delay_Resp (Timestamp + requestingPortIdentity) ----
    seq, ts = 105, (1_700_000_005, 666_000_000)
    req_clock, req_port = bytes(range(0xF0, 0xF8)), 9
    body = _timestamp(*ts) + _port_identity(req_clock, req_port)
    messages.append(_header(MSG_DELAY_RESP, 34 + len(body), seq) + body)
    exp["delay_resp"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1],
                         "requesting_clock_identity": req_clock, "requesting_port_number": req_port}

    # ---- Pdelay_Resp_Follow_Up (Timestamp + requestingPortIdentity) ----
    seq, ts = 106, (1_700_000_006, 777_000_000)
    req_clock, req_port = bytes(range(0xF8, 0x100)), 11
    body = _timestamp(*ts) + _port_identity(req_clock, req_port)
    messages.append(_header(MSG_PDELAY_RESP_FOLLOW_UP, 34 + len(body), seq) + body)
    exp["pdelay_resp_follow_up"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1],
                                    "requesting_clock_identity": req_clock,
                                    "requesting_port_number": req_port}

    # ---- Announce, WITHOUT a PATH_TRACE TLV (proves the optional-TLV path when absent) ----
    seq, ts = 107, (1_700_000_007, 888_000_000)
    gm_identity = bytes(range(0xB0, 0xB8))
    fixed = (_timestamp(*ts) + _i16(37) + _u8(0) + _u8(128) +          # utcOffset, reserved, prio1
             _u8(248) + _u8(0xFE) + _u16(0xFFFF) +                     # clockQuality
             _u8(128) + gm_identity + _u16(0) + _u8(0xA0))              # prio2, gmIdentity, steps, source
    assert len(fixed) == 30
    messages.append(_header(MSG_ANNOUNCE, 34 + len(fixed), seq) + fixed)
    exp["announce_no_tlv"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1],
                              "grandmaster_identity": gm_identity}

    # ---- Announce, WITH a 3-entry PATH_TRACE TLV ----
    seq, ts = 108, (1_700_000_008, 999_000_000)
    gm_identity2 = bytes(range(0xC0, 0xC8))
    path = [bytes(range(0xD0 + 8 * i, 0xD8 + 8 * i)) for i in range(3)]
    fixed = (_timestamp(*ts) + _i16(-5) + _u8(0) + _u8(64) +
             _u8(6) + _u8(0x21) + _u16(0x1234) +
             _u8(64) + gm_identity2 + _u16(1) + _u8(0x20))
    assert len(fixed) == 30
    tlv = _u16(TLV_PATH_TRACE) + _u16(8 * len(path)) + b"".join(path)
    messages.append(_header(MSG_ANNOUNCE, 34 + len(fixed) + len(tlv), seq) + fixed + tlv)
    exp["announce_with_path_trace"] = {"sequence_id": seq, "seconds": ts[0], "nanoseconds": ts[1],
                                       "grandmaster_identity": gm_identity2, "path_trace": path}
    exp["path_trace_entries"] = path

    return messages, exp


# ---- Ethernet + pcapng framing (reuses the same minimal layout as bindings/python/example_pcapng.cpp
# and examples/nanotins_parity/nm_pcap.hpp: little-endian section, kEpb=6, no pcapng-level options) ----
ETH_DST = bytes.fromhex("010000000000")  # PTP/gPTP L2 multicast-ish placeholder addr
ETH_SRC = bytes.fromhex("0a0b0c0d0e0f")


def _ethernet_frame(gptp_message: bytes) -> bytes:
    return ETH_DST + ETH_SRC + _u16(ETHERTYPE_GPTP) + gptp_message


def _pad4(n):
    return (n + 3) & ~3


def _epb(packet: bytes, ts=0) -> bytes:
    caplen = origlen = len(packet)
    fixed = (struct.pack("<I", 0) +                       # interface_id
             struct.pack("<I", (ts >> 32) & 0xFFFFFFFF) +  # ts_high
             struct.pack("<I", ts & 0xFFFFFFFF) +          # ts_low
             struct.pack("<I", caplen) + struct.pack("<I", origlen))
    padded = packet + bytes(_pad4(caplen) - caplen)
    body = fixed + padded
    total = 8 + len(body) + 4
    return struct.pack("<II", 6, total) + body + struct.pack("<I", total)


def _shb() -> bytes:
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)  # byte_order_magic, major, minor, section_len=-1
    total = 8 + len(body) + 4
    return struct.pack("<II", 0x0A0D0D0A, total) + body + struct.pack("<I", total)


def _idb() -> bytes:
    body = struct.pack("<HHI", 1, 0, 65536)  # link_type=1 (Ethernet), reserved, snaplen
    total = 8 + len(body) + 4
    return struct.pack("<II", 1, total) + body + struct.pack("<I", total)


def build_fixture() -> tuple[bytes, dict]:
    messages, expected = build_messages()
    out = bytearray()
    out += _shb()
    out += _idb()
    for i, msg in enumerate(messages):
        out += _epb(_ethernet_frame(msg), ts=1_700_000_000_000_000 + i)
    expected["message_count"] = len(messages)
    expected["announce_count"] = 2
    return bytes(out), expected


if __name__ == "__main__":
    out_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).parent / "gptp_fixture.pcapng"
    data, expected = build_fixture()
    out_path.write_bytes(data)
    print(f"wrote {out_path}: {len(data)} bytes, {expected['message_count']} gPTP messages", file=sys.stderr)
