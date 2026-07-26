// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/someip.hpp — SOME/IP header + Service Discovery entry/option traversal + the
// optional TLV serialization cursor. SD traversal re-expressed nanom-natively from nanotins'
// someip_sd.hpp (bounds-checked byte reads, not copied); the TLV cursor is promoted from
// examples/nanotins_parity/dpar_lite.cpp's someip_tag/someip_member/p_someip_member.

#include "json_tree.hpp"
#include "someip_rows.hpp"

#include <nanom/nanom.hpp>

#include <algorithm>
#include <array>
#include <cstdint>

namespace nano_shark::someip {

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t;

// Well-known SOME/IP Service Discovery UDP port (AUTOSAR); additional service ports are dynamic
// and configured by the caller (see DecodeOptions::someip_ports in decode_pass.hpp).
inline constexpr u16 kSomeipSdPort = 30490;

// Service Discovery is itself a SOME/IP message with this reserved Message ID.
inline constexpr u16 kSomeipSdServiceId = 0xFFFF, kSomeipSdMethodId = 0x8100;

// Message Type (byte 14) values. The high bit (0x20) marks a SOME/IP-TP segment; reassembly of
// those is a stateful concern above this framing layer, out of scope here (distinct from IP-level
// fragmentation, which core/defrag.hpp already handles).
inline constexpr u8 kSomeipRequest = 0x00, kSomeipRequestNoReturn = 0x01, kSomeipNotification = 0x02,
                    kSomeipResponse = 0x80, kSomeipError = 0x81, kSomeipTpFlag = 0x20;

// SD entry Type octet values.
inline constexpr u8 kSdEntryFindService = 0x00, kSdEntryOfferService = 0x01,
                    kSdEntrySubscribeEventgroup = 0x06, kSdEntrySubscribeEventgroupAck = 0x07;

// SD option Type octet values.
inline constexpr u8 kSdOptConfiguration = 0x01, kSdOptLoadBalancing = 0x02, kSdOptIpv4Endpoint = 0x04,
                    kSdOptIpv6Endpoint = 0x06, kSdOptIpv4Multicast = 0x14, kSdOptIpv6Multicast = 0x16,
                    kSdOptIpv4SdEndpoint = 0x24, kSdOptIpv6SdEndpoint = 0x26;

inline constexpr std::size_t kSomeipHeaderLen = 16, kSomeipSdEntrySize = 16, kSomeipSdPreambleLen = 8;

inline u16 rd_be16(const std::byte* p) { return (u16(std::uint8_t(p[0])) << 8) | std::uint8_t(p[1]); }
inline u32 rd_be32(const std::byte* p) {
  return (u32(std::uint8_t(p[0])) << 24) | (u32(std::uint8_t(p[1])) << 16) |
         (u32(std::uint8_t(p[2])) << 8) | u32(std::uint8_t(p[3]));
}

// Decodes an endpoint option's address/L4-protocol/port (IPv4/IPv6, uni/multicast/SD option
// types). Returns false for non-endpoint option types (fields left zero). Every read is bounded by
// `end`; a truncated option leaves the unread fields zero rather than reading out of bounds.
inline bool sd_decode_endpoint(const std::byte* opt, u8 type, const std::byte* end,
                               std::array<u8, 16>& addr, u8& l4proto, u16& port) {
  addr.fill(0);
  l4proto = 0;
  port = 0;
  const bool v4 = (type == kSdOptIpv4Endpoint || type == kSdOptIpv4Multicast || type == kSdOptIpv4SdEndpoint);
  const bool v6 = (type == kSdOptIpv6Endpoint || type == kSdOptIpv6Multicast || type == kSdOptIpv6SdEndpoint);
  if (!v4 && !v6) return false;
  const std::size_t addr_n = v4 ? 4u : 16u;
  const std::byte* a = opt + 4;              // after [len:2][type:1][reserved:1]
  const std::byte* proto = a + addr_n + 1;   // skip address + 1 reserved byte
  const std::byte* prt = proto + 1;
  if (prt + 2 > end) return true;            // endpoint type, but truncated -> fields stay zero
  for (std::size_t i = 0; i < addr_n; ++i) addr[i] = std::uint8_t(a[i]);
  l4proto = std::uint8_t(proto[0]);
  port = rd_be16(prt);
  return true;
}

// Longest option prefix sd_decode_endpoint ever reads: [len:2][type:1][reserved:1] + 16-byte IPv6
// address + [reserved:1][l4proto:1][port:2] = 24 bytes. The option loop gathers at most this many
// bytes of each option onto the stack, so the endpoint decode runs over CONTIGUOUS memory even
// when the underlying SD payload is segmented (a reassembled datagram); the rest of the option is
// never materialized.
inline constexpr std::size_t kSdEndpointProbe = 24;

// Visits every SD entry/option in `payload_after_header` (does nothing unless `hdr` names the
// reserved SD Message ID). `payload` is a seg_input, so this walks a reassembled (segmented) SD
// message zero-copy: entries decode via strct_seg (which windows across seams itself), and each
// option's bounded header is gathered onto the stack before the endpoint decode. All variable
// reads are clamped to the payload's own bounds and to the SD region's declared lengths, so a
// truncated/over-claiming SD message yields a partial-but-bounded visit, never an OOB read.
template <class OnEntry, class OnOption>
inline void for_each_sd_child(const SomeipHeader& hdr, nm::seg_input payload, OnEntry on_entry,
                              OnOption on_option) {
  if (std::uint16_t(hdr.service_id) != kSomeipSdServiceId ||
      std::uint16_t(hdr.method_id) != kSomeipSdMethodId) {
    return;
  }
  const std::size_t size = payload.size();
  if (size < kSomeipSdPreambleLen) return;

  const auto el = nm::seg_be32(payload.advance(4));  // preamble: [flags:1][reserved:3][entries_len:4]
  if (!el) return;
  const u32 entries_len = el->value;
  const std::size_t entries_off = kSomeipSdPreambleLen;
  std::size_t entries_end = entries_off + entries_len;
  if (entries_end > size) entries_end = size;  // clamp an over-claiming entries_length
  const u32 n_entries = u32((entries_end - entries_off) / kSomeipSdEntrySize);
  for (u32 i = 0; i < n_entries; ++i) {
    const std::size_t eoff = entries_off + std::size_t(i) * kSomeipSdEntrySize;
    auto entry = nm::strct_seg<SomeipSdEntry>(std::endian::big)(payload.advance(eoff));
    if (entry) on_entry(std::uint8_t(i), entry->value);
  }

  const std::size_t opt_len_at = entries_off + entries_len;  // declared (not clamped) entries end
  if (opt_len_at + 4 > size) return;
  const auto ol = nm::seg_be32(payload.advance(opt_len_at));
  if (!ol) return;
  const u32 options_len = ol->value;
  std::size_t opt = opt_len_at + 4;
  std::size_t opt_end = opt + options_len;
  if (opt_end > size) opt_end = size;  // clamp an over-claiming options_length
  u32 oi = 0;
  while (opt + 3 <= opt_end) {  // need [length:2][type:1]
    const std::size_t probe = std::min<std::size_t>(kSdEndpointProbe, opt_end - opt);
    std::array<std::byte, kSdEndpointProbe> ob{};
    if (!payload.advance(opt).gather(std::span<std::byte>(ob.data(), probe))) break;
    const u16 len = rd_be16(ob.data());
    const u8 type = std::uint8_t(ob[2]);
    const std::size_t next = opt + 3u + len;  // Length counts the bytes after the type octet
    if (next > opt_end) break;                // truncated/over-claiming option -> stop (bounded)
    std::array<u8, 16> addr{};
    u8 l4 = 0;
    u16 port = 0;
    sd_decode_endpoint(ob.data(), type, ob.data() + probe, addr, l4, port);
    on_option(std::uint8_t(oi), len, type, addr, l4, port);
    ++oi;
    opt = next;
  }
}

// Pushes one row per SD entry/option found in `payload_after_header`, plus a JSON layer per row
// when a sink is attached (auto-promoted to arrays by PacketJson, one per entry/option).
template <class EntryTable, class OptionTable>
inline void emit_sd_children(packet_id_t pid, const SomeipHeader& hdr, nm::seg_input payload,
                             EntryTable& entry_table, OptionTable& option_table, PacketJson* json) {
  for_each_sd_child(
      hdr, payload,
      [&](u8 idx, const SomeipSdEntry& e) {
        SomeipSdEntryRow row{pid, idx, e};
        entry_table.push(row);
        if (json) json->add_layer("someip.sd_entry", row);
      },
      [&](u8 idx, u16 len, u8 type, const std::array<u8, 16>& addr, u8 l4, u16 port) {
        SomeipSdOptionRow row{pid, idx, len, type, l4, port, addr};
        option_table.push(row);
        if (json) json->add_layer("someip.sd_option", row);
      });
}

// --- the optional SOME/IP TLV serialization format's generic member cursor, promoted from
// dpar_lite.cpp's someip_tag/someip_member/p_someip_member ---

struct someip_tag {
  nm::ubits<1>  rsvd;
  nm::ubits<3>  wire_type;
  nm::ubits<12> data_id;
};

}  // namespace nano_shark::someip

NANOM_DESCRIBE(nano_shark::someip::someip_tag, rsvd, wire_type, data_id);

namespace nano_shark::someip {

// One decoded TLV member's metadata: the row stores only the value LENGTH, never the value bytes,
// so the segmented cursor never has to materialize a value spanning a fragment boundary.
struct someip_member_meta {
  u16 data_id;
  u8  wire_type;
  u32 length;  // value length in bytes (the data length, excluding any wire-type length prefix)
};

// Reads one TLV member off a seg_input cursor: the [wire_type:3|data_id:12] tag, then the value
// length implied by the wire type (fixed for wt 0-3, a length prefix for wt 5-7), and advances
// past the value without copying it. Matches the contiguous p_someip_member's wire semantics
// (wt 4's width is IDL-config-dependent, so it stops the walk like the original).
inline nm::seg_result<someip_member_meta> p_someip_member_seg(nm::seg_input in) {
  auto tag = nm::strct_seg<someip_tag>()(in);
  if (!tag) return nm::unexp(tag.error());
  const u8 wt = u8(tag->value.wire_type);
  nm::seg_input rest = tag->rest;
  std::size_t vlen = 0;
  switch (wt) {
    case 0: vlen = 1; break;
    case 1: vlen = 2; break;
    case 2: vlen = 4; break;
    case 3: vlen = 8; break;
    case 5: { auto n = nm::seg_u8(rest);   if (!n) return nm::unexp(n.error()); vlen = n->value; rest = n->rest; break; }
    case 6: { auto n = nm::seg_be16(rest); if (!n) return nm::unexp(n.error()); vlen = n->value; rest = n->rest; break; }
    case 7: { auto n = nm::seg_be32(rest); if (!n) return nm::unexp(n.error()); vlen = n->value; rest = n->rest; break; }
    default:  // wt 4: length width comes from IDL config -- not skippable
      return nm::seg_make_err(rest, "someip wire type 4 (config-dependent width)");
  }
  auto skipped = nm::seg_skip(rest, vlen);
  if (!skipped) return nm::unexp(skipped.error());
  return nm::seg_done{someip_member_meta{tag->value.data_id, wt, u32(vlen)}, skipped->rest};
}

// Walks `region` as a flat run of TLV members, pushing one row per member. A plain
// progress-guarded loop (not many0, which is a contiguous-only combinator): stop at the first
// decode error or a zero-consume, exactly like many0 would over the contiguous form.
template <class TlvTable>
inline void walk_tlv_members(nm::seg_input region, packet_id_t pid, TlvTable& table, PacketJson* json) {
  u32           idx = 0;
  nm::seg_input cur = region;
  while (!cur.empty()) {
    auto m = p_someip_member_seg(cur);
    if (!m) break;
    if (m->rest.offset() == cur.offset()) break;  // no progress -> done (many0 contract)
    SomeipTlvMemberRow row{pid, idx++, m->value.data_id, m->value.wire_type, m->value.length};
    table.push(row);
    if (json) json->add_layer("someip.tlv_member", row);
    cur = m->rest;
  }
}

// Parses the fixed 16-byte header from `payload`, pushes the SomeipNode row, and always attempts
// SD entry/option extraction (self-describing: for_each_sd_child no-ops unless the message really
// is SD) plus, when `assume_tlv` is set (the caller has configured this port as TLV-encoded --
// SOME/IP's flat serialization isn't self-describing, so this can't be inferred), walks the
// payload after the header as TLV members.
template <class SomeipTable, class EntryTable, class OptionTable, class TlvTable>
inline void maybe_dispatch(nm::seg_input payload, packet_id_t pid, bool assume_tlv,
                           SomeipTable& someip_table, EntryTable& sd_entry_table,
                           OptionTable& sd_option_table, TlvTable& tlv_table, PacketJson* json) {
  if (payload.size() < kSomeipHeaderLen) return;
  auto hdr = nm::strct_seg<SomeipHeader>(std::endian::big)(payload);
  if (!hdr) return;

  someip_table.push(SomeipNode{pid, 0, false, hdr->value});
  if (json) json->add_layer("someip", hdr->value);

  const nm::seg_input after_header = hdr->rest;  // == payload.advance(kSomeipHeaderLen)
  emit_sd_children(pid, hdr->value, after_header, sd_entry_table, sd_option_table, json);
  if (assume_tlv) walk_tlv_members(after_header, pid, tlv_table, json);
}

}  // namespace nano_shark::someip
