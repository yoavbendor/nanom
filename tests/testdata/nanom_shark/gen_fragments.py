#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthesizes classic-pcap fixtures with fragmented IPv4/IPv6 UDP datagrams.

No scapy dependency (not installed in this environment, and this project avoids external
dependencies everywhere else) -- just the stdlib `struct` module, building pcap global/record
headers and Ethernet/IPv4/IPv6/UDP bytes directly per RFC 791 / RFC 8200's own field layouts.

Regenerate with: python3 gen_fragments.py
"""
import struct

DST_MAC = bytes.fromhex("020000000002")
SRC_MAC = bytes.fromhex("020000000001")
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD


def eth(ethertype: int) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack(">H", ethertype)


def ipv4(*, ident: int, more_fragments: bool, frag_offset_units: int, ttl: int, proto: int,
        src: bytes, dst: bytes, payload: bytes) -> bytes:
    total_length = 20 + len(payload)
    flags = (1 if more_fragments else 0)  # DF=0, MF as given
    flags_frag = (flags << 13) | (frag_offset_units & 0x1FFF)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_length, ident, flags_frag, ttl, proto, 0,
                      src, dst)
    return hdr + payload


def ipv6_frag_ext(*, next_header: int, ident: int, more_fragments: bool, frag_offset_units: int,
                  src: bytes, dst: bytes, payload_after_ext: bytes) -> bytes:
    # Base header (40B) with next_header = 44 (Fragment) pointing at the 8B fragment ext header,
    # which itself carries the real next_header (e.g. 17 = UDP) for what follows it.
    offset_flags = (frag_offset_units << 3) | (1 if more_fragments else 0)
    frag_hdr = struct.pack(">BBHI", next_header, 0, offset_flags, ident)
    payload_length = len(frag_hdr) + len(payload_after_ext)
    base = struct.pack(">BBHHBB16s16s", (6 << 4), 0, 0, payload_length, 44, 64, src, dst)
    # RFC 8200 packs version(4)/traffic_class(8)/flow_label(20) into 4 bytes; approximate with
    # version=6 in the top nibble and zero the rest -- nano_shark's Ipv6 struct only reads
    # version/traffic_class/flow_label for display, none of which this fixture's tests assert on.
    return base + frag_hdr + payload_after_ext


def udp(*, src_port: int, dst_port: int, udp_length: int, data: bytes) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, udp_length, 0) + data


def write_pcap(path: str, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 0xA1B2C3D4))
        f.write(struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
        ts = 1_700_000_000
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", ts, i, len(frame), len(frame)))
            f.write(frame)


def build_ipv4_fixture():
    frames = []
    src, dst = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])

    # Flow A (ident 0x1111): 2 fragments, in order -> completes cleanly.
    app = b"FRAGMENTEDPAYLD!"  # 16 bytes
    udp_hdr_and_head = udp(src_port=1111, dst_port=2222, udp_length=8 + len(app), data=app[:8])
    frames.append(eth(ETH_IPV4) + ipv4(ident=0x1111, more_fragments=True, frag_offset_units=0,
                                       ttl=64, proto=17, src=src, dst=dst,
                                       payload=udp_hdr_and_head))
    frames.append(eth(ETH_IPV4) + ipv4(ident=0x1111, more_fragments=False, frag_offset_units=2,
                                       ttl=64, proto=17, src=src, dst=dst, payload=app[8:]))

    # Flow B (ident 0x2222): 3 fragments, delivered OUT OF ORDER (3rd, 1st, 2nd) -> still completes.
    appB = b"OUTOFORDERFRAGSAB"  # 18 bytes -> split 8/8/2
    udpB = udp(src_port=3333, dst_port=4444, udp_length=8 + len(appB), data=appB[:8])
    frag1 = eth(ETH_IPV4) + ipv4(ident=0x2222, more_fragments=True, frag_offset_units=0, ttl=64,
                                 proto=17, src=src, dst=dst, payload=udpB)
    frag2 = eth(ETH_IPV4) + ipv4(ident=0x2222, more_fragments=True, frag_offset_units=2, ttl=64,
                                 proto=17, src=src, dst=dst, payload=appB[8:16])
    # appB's app-payload byte 16 sits at IP-payload byte 8(UDP header)+16=24 -> offset_units=3.
    frag3 = eth(ETH_IPV4) + ipv4(ident=0x2222, more_fragments=False, frag_offset_units=3, ttl=64,
                                 proto=17, src=src, dst=dst, payload=appB[16:])
    frames += [frag3, frag1, frag2]

    # Flow C (ident 0x3333): 2 fragments whose 8-byte overlap disagrees -> conflict, never completes.
    udpC = udp(src_port=5555, dst_port=6666, udp_length=8 + 16, data=b"AAAAAAAABBBBBBBB")
    frames.append(eth(ETH_IPV4) + ipv4(ident=0x3333, more_fragments=True, frag_offset_units=0,
                                       ttl=64, proto=17, src=src, dst=dst, payload=udpC))
    # Second fragment claims offset 8 (overlapping the tail of fragment 1's 24-byte payload) but
    # with DIFFERENT bytes than what fragment 1 already has at that range.
    frames.append(eth(ETH_IPV4) + ipv4(ident=0x3333, more_fragments=False, frag_offset_units=1,
                                       ttl=64, proto=17, src=src, dst=dst, payload=b"CONFLICTBYTES!!!"))

    # Flow D (ident 0x4444): only the first fragment ever arrives -> times out.
    udpD = udp(src_port=7777, dst_port=8888, udp_length=8 + 8, data=b"NEVERFIN")
    frames.append(eth(ETH_IPV4) + ipv4(ident=0x4444, more_fragments=True, frag_offset_units=0,
                                       ttl=64, proto=17, src=src, dst=dst, payload=udpD))

    # Filler: plain non-fragmented packets so pid advances past a small test-configured timeout.
    for i in range(5):
        filler = udp(src_port=9000 + i, dst_port=9100, udp_length=8, data=b"")
        frames.append(eth(ETH_IPV4) + ipv4(ident=0, more_fragments=False, frag_offset_units=0,
                                           ttl=64, proto=17, src=src, dst=dst, payload=filler))

    write_pcap("ipv4_fragments_sample.pcap", frames)


def build_ipv6_fixture():
    frames = []
    # 2001:db8::aa and 2001:db8::bb
    src = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [0xaa])
    dst = bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [0xbb])

    app = b"IPV6FRAGPAYLOAD!"  # 16 bytes
    udp0 = udp(src_port=1111, dst_port=2222, udp_length=8 + len(app), data=app[:8])
    frames.append(eth(ETH_IPV6) + ipv6_frag_ext(next_header=17, ident=0xAABB, more_fragments=True,
                                                frag_offset_units=0, src=src, dst=dst,
                                                payload_after_ext=udp0))
    frames.append(eth(ETH_IPV6) + ipv6_frag_ext(next_header=17, ident=0xAABB, more_fragments=False,
                                                frag_offset_units=2, src=src, dst=dst,
                                                payload_after_ext=app[8:]))
    write_pcap("ipv6_fragments_sample.pcap", frames)


if __name__ == "__main__":
    build_ipv4_fixture()
    build_ipv6_fixture()
    print("wrote ipv4_fragments_sample.pcap, ipv6_fragments_sample.pcap")
