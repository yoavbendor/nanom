// SPDX-License-Identifier: Apache-2.0
// gPTP (IEEE 802.1AS) dispatch + TLV walking, built on nanom. Promoted from
// bindings/python/gptp/gptp_parse.hpp into nano_shark's decode core (that file is untouched); the
// only substantive change is dropping this file's own pcap/pcapng scanning (parse_pcapng_with_gptp
// and its detail::EthHdr/png_block_hdr/png_epb_body structs) since decode_pass.hpp's PacketVisitor
// already scans blocks and decodes Ethernet/VLAN via nmpcap/nm_protocols.hpp — parse_gptp_message
// is called directly from there once ethertype 0x88F7 is seen (see decode_pass.hpp).
//
// Tagged-union dispatch pattern: nanom's alt()/flat_map() both require ONE common return type across
// every branch (see include/nanom/nom.hpp — alt's `std::common_type_t<parsed_t<P>, parsed_t<Ps>...>`,
// flat_map's single deduced closure return type), so they cannot dispatch a tag byte into N
// *structurally different* row types. The proven pattern instead (the same one
// examples/nanotins_parity/nm_pcap.hpp uses for pcapng's SHB/IDB/EPB, and nanolance's
// pcapng2lance_nanom uses for its 10 PDU types): parse the common header once via strct<>(), plain C++
// `switch` on the discriminant field, call a separate function per kind, push into that kind's own
// soa<T>. See bindings/python/gptp/README.md for the full writeup of this pattern.
#pragma once

#include "gptp_rows.hpp"
#include "json_tree.hpp"

#include <nanom/nanom.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace nmgptp {

namespace nm = nanom;

// ---- a tiny field-at-a-time cursor over nanom's own read primitives (be_u8/be_u16/be_u48/take/...) --
// gPTP message bodies are flat runs of heterogeneous fields (not all reflectable via one strct<>() call,
// since e.g. the 48-bit timestamp seconds field has no struct-field wire type — see README). This is a
// thin convenience wrapper, not a new library abstraction: every read still goes through nanom's own
// combinators; `ok` just latches the first failure so callers can check it once at the end.
struct FieldReader {
  nm::input cur;
  bool      ok = true;

  template <class T>
  T take(nm::result<T> r) {
    if (!r) { ok = false; return T{}; }
    cur = r->rest;
    return r->value;
  }
  std::uint8_t  u8()  { return take(nm::u8(cur)); }
  std::int8_t   i8()  { return take(nm::be_i8(cur)); }
  std::uint16_t u16() { return take(nm::be_u16(cur)); }
  std::int16_t  i16() { return take(nm::be_i16(cur)); }
  std::uint32_t u32() { return take(nm::be_u32(cur)); }
  std::int32_t  i32() { return take(nm::be_i32(cur)); }
  std::uint64_t u48() { return take(nm::be_u48(cur)); }   // the 48-bit PTP timestamp-seconds field —
                                                            // nm::be_u48 already combines it into a
                                                            // uint64_t; no manual shifting, no
                                                            // reinterpret_cast anywhere in this file.
  std::int64_t  i64() { return take(nm::be_i64(cur)); }
  template <std::size_t N>
  std::array<std::uint8_t, N> arr() {
    std::array<std::uint8_t, N> out{};
    auto r = nm::take(N)(cur);
    if (!r) { ok = false; return out; }
    for (std::size_t i = 0; i < N; ++i) out[i] = static_cast<std::uint8_t>(r->value[i]);
    cur = r->rest;
    return out;
  }
  void skip(std::size_t n) { take(nm::take(n)(cur)); }
  std::size_t remaining() const { return cur.size(); }
};

struct PtpTimestamp { std::uint64_t seconds; std::uint32_t nanoseconds; };
inline PtpTimestamp read_timestamp(FieldReader& fr) {
  PtpTimestamp t;
  t.seconds = fr.u48();
  t.nanoseconds = fr.u32();
  return t;
}
inline PortIdentity read_port_identity(FieldReader& fr) {
  PortIdentity p;
  p.clock_identity = fr.arr<8>();
  p.port_number = fr.u16();
  return p;
}

// Organization-Extension TLV type (0x0003) carrying the 802.1AS Follow_Up Information; PATH_TRACE (0x8).
inline constexpr std::uint16_t kTlvOrganizationExtension = 0x0003;
inline constexpr std::uint16_t kTlvPathTrace             = 0x0008;

// ---- the 9 output tables + a running message-index join key ----
struct GptpTables {
  std::uint64_t next_msg_index = 0;
  nm::soa<SyncRow>                 sync{4096};
  nm::soa<FollowUpRow>             follow_up{4096};
  nm::soa<DelayReqRow>             delay_req{4096};
  nm::soa<DelayRespRow>            delay_resp{4096};
  nm::soa<PdelayReqRow>            pdelay_req{4096};
  nm::soa<PdelayRespRow>           pdelay_resp{4096};
  nm::soa<PdelayRespFollowUpRow>   pdelay_resp_follow_up{4096};
  nm::soa<AnnounceRow>             announce{4096};
  nm::soa<PathTraceEntryRow>       path_trace{4096};
};

inline RowCommon make_common(std::uint64_t msg_index, std::uint64_t packet_id, const GptpHeader& h) {
  RowCommon c;
  c.msg_index = msg_index;
  c.packet_id = packet_id;
  c.domain_number = h.domain_number;
  c.sequence_id = h.sequence_id;
  c.correction_field = h.correction_field;
  c.log_message_interval = h.log_message_interval;
  c.source_port_identity = h.source_port_identity;
  return c;
}

// ---- per-kind body parsers: each reads its own body (bounded to the header's declared
// message_length), builds its Row, and pushes it. Returns false only on a malformed/truncated body. ----

inline bool parse_sync(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  SyncRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.origin_timestamp_seconds = ts.seconds;
  row.origin_timestamp_nanoseconds = ts.nanoseconds;
  if (!fr.ok) return false;
  t.sync.push(row);
  if (json) json->add_layer("gptp.sync", row);
  return true;
}

inline bool parse_delay_req(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  DelayReqRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.origin_timestamp_seconds = ts.seconds;
  row.origin_timestamp_nanoseconds = ts.nanoseconds;
  if (!fr.ok) return false;
  t.delay_req.push(row);
  if (json) json->add_layer("gptp.delay_req", row);
  return true;
}

inline bool parse_pdelay_req(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  PdelayReqRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.origin_timestamp_seconds = ts.seconds;
  row.origin_timestamp_nanoseconds = ts.nanoseconds;
  // 10 reserved bytes follow; not read (nothing to extract), matching pdelay_req's wire shape.
  if (!fr.ok) return false;
  t.pdelay_req.push(row);
  if (json) json->add_layer("gptp.pdelay_req", row);
  return true;
}

inline bool parse_delay_resp(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  DelayRespRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.receive_timestamp_seconds = ts.seconds;
  row.receive_timestamp_nanoseconds = ts.nanoseconds;
  row.requesting_port_identity = read_port_identity(fr);
  if (!fr.ok) return false;
  t.delay_resp.push(row);
  if (json) json->add_layer("gptp.delay_resp", row);
  return true;
}

inline bool parse_pdelay_resp(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  PdelayRespRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.request_receipt_timestamp_seconds = ts.seconds;
  row.request_receipt_timestamp_nanoseconds = ts.nanoseconds;
  row.requesting_port_identity = read_port_identity(fr);
  if (!fr.ok) return false;
  t.pdelay_resp.push(row);
  if (json) json->add_layer("gptp.pdelay_resp", row);
  return true;
}

inline bool parse_pdelay_resp_follow_up(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  PdelayRespFollowUpRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.response_origin_timestamp_seconds = ts.seconds;
  row.response_origin_timestamp_nanoseconds = ts.nanoseconds;
  row.requesting_port_identity = read_port_identity(fr);
  if (!fr.ok) return false;
  t.pdelay_resp_follow_up.push(row);
  if (json) json->add_layer("gptp.pdelay_resp_follow_up", row);
  return true;
}

// Follow_Up: Timestamp, then TLV region — same bounded-manual-while-loop shape as the pcapng EPB
// option walk (bench/streaming_pcapng_bench.cpp): read a 4-byte [type,length] header, bound the value
// to what's declared, advance by the declared length (not by how much of it we actually decoded) so an
// unrecognized/future TLV can never desync the walk.
inline bool parse_follow_up(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  FollowUpRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.precise_origin_timestamp_seconds = ts.seconds;
  row.precise_origin_timestamp_nanoseconds = ts.nanoseconds;
  row.has_follow_up_info_tlv = false;
  if (!fr.ok) return false;

  while (fr.ok && fr.remaining() >= 4) {
    const std::uint16_t tlv_type = fr.u16();
    const std::uint16_t tlv_length = fr.u16();
    if (!fr.ok || tlv_length > fr.remaining()) break;  // malformed/truncated TLV -> stop
    nm::input value = fr.cur;                          // the TLV's own value region, length-bounded
    if (tlv_type == kTlvOrganizationExtension && tlv_length >= 16) {
      FieldReader vr{value};
      vr.skip(3);                                       // organizationId (0x0080C2 for 802.1AS)
      vr.skip(3);                                       // organizationSubType (1 = follow-up info)
      row.cumulative_scaled_rate_offset = vr.i32();
      row.gm_time_base_indicator = vr.u16();
      vr.skip(12);                                      // lastGmPhaseChange (96-bit scaled ns; raw)
      row.scaled_last_gm_freq_change = vr.i32();
      row.has_follow_up_info_tlv = vr.ok;
    }
    fr.skip(tlv_length);  // advance by the DECLARED length regardless of how much we parsed above
  }
  t.follow_up.push(row);
  if (json) json->add_layer("gptp.follow_up", row);
  return true;
}

// Announce: fixed body, then an optional PATH_TRACE TLV — one soa<PathTraceEntryRow> row per
// clockIdentity entry (a many-rows-per-message table, mirroring nanolance's Ipv6OptionRow pattern).
inline bool parse_announce(GptpTables& t, const RowCommon& common, nm::input body, nano_shark::PacketJson* json) {
  FieldReader fr{body};
  AnnounceRow row{};
  row.common = common;
  auto ts = read_timestamp(fr);
  row.origin_timestamp_seconds = ts.seconds;
  row.origin_timestamp_nanoseconds = ts.nanoseconds;
  row.current_utc_offset = fr.i16();
  fr.skip(1);  // reserved
  row.grandmaster_priority1 = fr.u8();
  row.grandmaster_clock_class = fr.u8();
  row.grandmaster_clock_accuracy = fr.u8();
  row.grandmaster_offset_scaled_log_variance = fr.u16();
  row.grandmaster_priority2 = fr.u8();
  row.grandmaster_identity = fr.arr<8>();
  row.steps_removed = fr.u16();
  row.time_source = fr.u8();
  row.has_path_trace_tlv = false;
  row.path_trace_count = 0;
  if (!fr.ok) return false;

  while (fr.ok && fr.remaining() >= 4) {
    const std::uint16_t tlv_type = fr.u16();
    const std::uint16_t tlv_length = fr.u16();
    if (!fr.ok || tlv_length > fr.remaining()) break;
    if (tlv_type == kTlvPathTrace) {
      row.has_path_trace_tlv = true;
      FieldReader vr{fr.cur};
      std::uint16_t entry = 0;
      for (std::size_t off = 0; off + 8 <= tlv_length; off += 8, ++entry) {
        PathTraceEntryRow pt{};
        pt.msg_index = common.msg_index;
        pt.entry_index = entry;
        pt.clock_identity = vr.arr<8>();
        if (!vr.ok) break;
        t.path_trace.push(pt);
        if (json) json->add_layer("gptp.path_trace", pt);
      }
      row.path_trace_count = entry;
    }
    fr.skip(tlv_length);
  }
  t.announce.push(row);
  if (json) json->add_layer("gptp.announce", row);
  return true;
}

// Parse one gPTP message (starting at its 34-byte common header) and dispatch on message_type. This —
// parse the shared header, switch on the tag, call a separate per-kind function — is the pattern; it is
// NOT expressed via alt()/flat_map() (see file header comment for why that's structurally impossible
// here without first unifying every kind into one wrapper type).
inline bool parse_gptp_message(GptpTables& t, std::uint64_t packet_id, nm::input msg,
                               nano_shark::PacketJson* json = nullptr) {
  auto hdr = nm::strct<GptpHeader>(std::endian::big)(msg);
  if (!hdr) return false;
  const GptpHeader& h = hdr->value;
  if (h.message_length < 34) return false;

  const std::size_t body_len = std::min<std::size_t>(h.message_length - 34, hdr->rest.size());
  auto clipped = nm::take(body_len)(hdr->rest);
  if (!clipped) return false;
  nm::input body = nm::from(clipped->value);

  const RowCommon common = make_common(t.next_msg_index++, packet_id, h);
  switch (std::uint8_t(h.message_type)) {
    case kMsgSync:               return parse_sync(t, common, body, json);
    case kMsgDelayReq:            return parse_delay_req(t, common, body, json);
    case kMsgPdelayReq:           return parse_pdelay_req(t, common, body, json);
    case kMsgPdelayResp:          return parse_pdelay_resp(t, common, body, json);
    case kMsgFollowUp:            return parse_follow_up(t, common, body, json);
    case kMsgDelayResp:           return parse_delay_resp(t, common, body, json);
    case kMsgPdelayRespFollowUp:  return parse_pdelay_resp_follow_up(t, common, body, json);
    case kMsgAnnounce:            return parse_announce(t, common, body, json);
    default: return false;  // Signaling/Management/reserved — out of scope for this example
  }
}

// gPTP rides directly on Ethernet (optionally under one VLAN tag) with this EtherType; the caller
// (decode_pass.hpp) checks it and calls parse_gptp_message with the bytes right after Ethernet/VLAN.
inline constexpr std::uint16_t kEtherTypeGptp = 0x88F7U;

}  // namespace nmgptp
