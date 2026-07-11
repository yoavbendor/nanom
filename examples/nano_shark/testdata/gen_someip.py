#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthesizes a classic-pcap fixture with SOME/IP traffic: a plain request/response pair, a
Service Discovery message (FindService + OfferService entries, one IPv4 endpoint option), and a
TLV-encoded message on a separate port. No scapy dependency (see gen_fragments.py's header
comment for why) -- stdlib struct only, byte layout cross-checked against
nano_shark/core/someip.hpp / someip_rows.hpp (which was itself cross-checked against nanotins'
protocol_specs_someip.hpp / someip_sd.hpp).

Regenerate with: python3 gen_someip.py
"""
import struct

DST_MAC = bytes.fromhex("020000000002")
SRC_MAC = bytes.fromhex("020000000001")
ETH_IPV4 = 0x0800

SD_PORT = 30490       # the well-known port DecodeOptions::someip_ports defaults to
TLV_PORT = 30509      # a second service port, configured as someip_tlv_ports in the test


def eth(ethertype: int) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack(">H", ethertype)


def ipv4(*, proto: int, src: bytes, dst: bytes, payload: bytes) -> bytes:
    total_length = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_length, 0, 0, 64, proto, 0, src, dst)
    return hdr + payload


def udp(*, src_port: int, dst_port: int, data: bytes) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(data), 0) + data


def someip_header(*, service_id: int, method_id: int, client_id: int, session_id: int,
                  message_type: int, return_code: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack(">HHIHHBBBB", service_id, method_id, length, client_id, session_id,
                      1, 1, message_type, return_code)
    return hdr + payload


def sd_entry(*, entry_type: int, index_1st: int, index_2nd: int, num_opt_1: int, num_opt_2: int,
            service_id: int, instance_id: int, major_version: int, ttl: int,
            minor_version: int) -> bytes:
    word = (major_version << 24) | (ttl & 0xFFFFFF)
    return struct.pack(">BBBBHHI", entry_type, index_1st, index_2nd,
                       (num_opt_1 << 4) | num_opt_2, service_id, instance_id, word) + \
        struct.pack(">I", minor_version)


def sd_option_ipv4_endpoint(*, addr: bytes, l4proto: int, port: int, opt_type: int = 0x04) -> bytes:
    # Wire layout: [length:2][type:1][reserved:1][addr:4][reserved:1][l4proto:1][port:2]. `length`
    # counts only the bytes AFTER the type octet (9 here), not the type byte itself.
    after_type = struct.pack(">B4sBBH", 0, addr, 0, l4proto, port)
    return struct.pack(">H", len(after_type)) + struct.pack(">B", opt_type) + after_type


def someip_tlv_member(*, wire_type: int, data_id: int, value: bytes) -> bytes:
    tag = struct.pack(">H", (0 << 13) | ((wire_type & 0x7) << 12) | (data_id & 0xFFF))
    if wire_type in (0, 1, 2, 3):
        return tag + value  # fixed width 1/2/4/8, caller supplies exactly that many bytes
    if wire_type == 6:
        return tag + struct.pack(">H", len(value)) + value
    raise ValueError("unsupported wire_type for this fixture")


def write_pcap(path: str, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 0xA1B2C3D4))
        f.write(struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
        ts = 1_700_100_000
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", ts, i, len(frame), len(frame)))
            f.write(frame)


def build():
    frames = []
    src, dst = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])

    # Plain request/response pair, ordinary (non-SD) service, on the default SD port so the test
    # can exercise dispatch without extra configuration (nanotins' own SomeipNode reaches ANY
    # SOME/IP message on a configured port, SD or not -- only SD entry/option EXTRACTION is
    # gated on the message actually being SD).
    req_payload = bytes([0x01, 0x02, 0x03, 0x04])
    req = someip_header(service_id=0x1234, method_id=0x0001, client_id=1, session_id=1,
                        message_type=0x00, return_code=0, payload=req_payload)  # kSomeipRequest
    frames.append(eth(ETH_IPV4) + ipv4(proto=17, src=src, dst=dst,
                                       payload=udp(src_port=40000, dst_port=SD_PORT, data=req)))

    resp_payload = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    resp = someip_header(service_id=0x1234, method_id=0x0001, client_id=1, session_id=1,
                         message_type=0x80, return_code=0, payload=resp_payload)  # kSomeipResponse
    frames.append(eth(ETH_IPV4) + ipv4(proto=17, src=dst, dst=src,
                                       payload=udp(src_port=SD_PORT, dst_port=40000, data=resp)))

    # Service Discovery: FindService + OfferService (with one IPv4 endpoint option).
    find_entry = sd_entry(entry_type=0x00, index_1st=0, index_2nd=0, num_opt_1=0, num_opt_2=0,
                          service_id=0x1234, instance_id=0x0001, major_version=1, ttl=3,
                          minor_version=0xFFFFFFFF)
    offer_entry = sd_entry(entry_type=0x01, index_1st=0, index_2nd=0, num_opt_1=1, num_opt_2=0,
                           service_id=0x1234, instance_id=0x0001, major_version=1, ttl=3,
                           minor_version=1)
    entries = find_entry + offer_entry
    option = sd_option_ipv4_endpoint(addr=bytes([192, 168, 1, 10]), l4proto=17, port=TLV_PORT)
    sd_payload = struct.pack(">BBBBI", 0, 0, 0, 0, len(entries)) + entries + \
        struct.pack(">I", len(option)) + option
    sd_msg = someip_header(service_id=0xFFFF, method_id=0x8100, client_id=0, session_id=1,
                           message_type=0x02, return_code=0, payload=sd_payload)
    frames.append(eth(ETH_IPV4) + ipv4(proto=17, src=src, dst=dst,
                                       payload=udp(src_port=SD_PORT, dst_port=SD_PORT, data=sd_msg)))

    # TLV-encoded message on a second port (the test configures this port as someip_tlv_ports).
    tlv_payload = someip_tlv_member(wire_type=2, data_id=0x001, value=struct.pack(">I", 42)) + \
        someip_tlv_member(wire_type=6, data_id=0x002, value=b"hello")
    tlv_msg = someip_header(service_id=0x5678, method_id=0x0002, client_id=2, session_id=1,
                            message_type=0x02, return_code=0, payload=tlv_payload)
    frames.append(eth(ETH_IPV4) + ipv4(proto=17, src=src, dst=dst,
                                       payload=udp(src_port=41000, dst_port=TLV_PORT, data=tlv_msg)))

    write_pcap("someip_fixture.pcap", frames)


if __name__ == "__main__":
    build()
    print("wrote someip_fixture.pcap")
