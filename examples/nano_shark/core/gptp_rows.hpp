// SPDX-License-Identifier: Apache-2.0
// gPTP (IEEE 802.1AS) row structs — promoted from bindings/python/gptp/gptp_rows.hpp into a
// first-class part of the nano_shark decode core (that file is untouched; this is a copy, not a
// move, since the Python bindings still use it).
//
// A comprehensive stress test of the pcapng example's claim ("change ~10 lines for your format"): gPTP
// has 8 message kinds with genuinely different bodies dispatched from a bit-packed tag byte, a 48-bit
// timestamp, and two kinds of TLV. Every row struct here is a plain NANOM_DESCRIBE'd struct — the same
// primitive nanom_arrow.hpp bridge (unmodified) turns each into a zero-copy Arrow table.
//
// Wire byte order: the gPTP message itself (like any captured Ethernet payload) is always network byte
// order (big-endian), independent of the pcapng file's own section endianness — so every strct<>() call
// in gptp.hpp passes std::endian::big explicitly rather than a file-derived order.
#pragma once

#include <nanom/nanom.hpp>

#include <array>
#include <cstdint>

namespace nmgptp {

namespace nm = nanom;

// ---- shared nested type: an 8-byte clockIdentity + 2-byte portNumber, used by the common header's
// sourcePortIdentity and by Delay_Resp/Pdelay_Resp/Pdelay_Resp_Follow_Up's requestingPortIdentity.
// Nesting this (rather than duplicating 2 fields everywhere) also exercises soa<T>'s automatic dotted-
// column flattening for nested Described members (e.g. "requesting_port_identity.port_number").
struct PortIdentity {
  std::array<std::uint8_t, 8> clock_identity;
  std::uint16_t                port_number;
};

// ---- the 34-byte common PTP/gPTP header, parsed once per message ----
// transportSpecific:4 | messageType:4 (byte 0, msb0) is the same bit-packed-tag-byte shape as the
// README's vlan_hdr pcp/dei/vid example; reserved:4 | versionPTP:4 (byte 1) is the same pattern again.
struct GptpHeader {
  nm::ubits<4>          transport_specific;
  nm::ubits<4>          message_type;
  nm::ubits<4>          reserved1;
  nm::ubits<4>          version_ptp;
  std::uint16_t         message_length;   // total message length incl. this header; bounds the TLV region
  std::uint8_t          domain_number;
  std::uint8_t          reserved2;
  std::uint16_t         flags;
  std::int64_t          correction_field;  // scaled nanoseconds
  std::uint32_t         reserved3;
  PortIdentity          source_port_identity;
  std::uint16_t         sequence_id;
  std::uint8_t          control_field;
  std::int8_t           log_message_interval;
};

// gPTP/PTP messageType tag values (IEEE 1588 Table 19 / 802.1AS).
enum : std::uint8_t {
  kMsgSync                 = 0x0,
  kMsgDelayReq             = 0x1,
  kMsgPdelayReq            = 0x2,
  kMsgPdelayResp           = 0x3,
  kMsgFollowUp             = 0x8,
  kMsgDelayResp            = 0x9,
  kMsgPdelayRespFollowUp   = 0xA,
  kMsgAnnounce             = 0xB,
};

// Every row carries these common-header fields flattened in. msg_index (assigned by the parser,
// not read from the wire) is the cross-gPTP-table join key, since gPTP bodies are heterogeneous
// and don't fit the Node<Body>/AllTables pattern the rest of nano_shark's protocols use;
// packet_id is additive context (which captured frame this message came from), not a key change.
struct RowCommon {
  std::uint64_t  msg_index;
  std::uint64_t  packet_id;
  std::uint8_t   domain_number;
  std::uint16_t  sequence_id;
  std::int64_t   correction_field;
  std::int8_t    log_message_interval;
  PortIdentity   source_port_identity;
};

// ---- per-kind rows (34-byte header fields flattened in, plus each kind's own body) ----

struct SyncRow {
  RowCommon      common;
  std::uint64_t  origin_timestamp_seconds;
  std::uint32_t  origin_timestamp_nanoseconds;
};

struct FollowUpRow {
  RowCommon      common;
  std::uint64_t  precise_origin_timestamp_seconds;
  std::uint32_t  precise_origin_timestamp_nanoseconds;
  // Follow_Up Information TLV (mandatory in 802.1AS) — organizationId/subType identify it as the
  // 802.1 TLV; the rest are the rate-ratio/GM-phase-change fields consumers actually want.
  bool           has_follow_up_info_tlv;
  std::int32_t   cumulative_scaled_rate_offset;
  std::uint16_t  gm_time_base_indicator;
  std::int32_t   scaled_last_gm_freq_change;
};

struct DelayReqRow {
  RowCommon      common;
  std::uint64_t  origin_timestamp_seconds;
  std::uint32_t  origin_timestamp_nanoseconds;
};

struct DelayRespRow {
  RowCommon      common;
  std::uint64_t  receive_timestamp_seconds;
  std::uint32_t  receive_timestamp_nanoseconds;
  PortIdentity   requesting_port_identity;
};

struct PdelayReqRow {
  RowCommon      common;
  std::uint64_t  origin_timestamp_seconds;
  std::uint32_t  origin_timestamp_nanoseconds;
};

struct PdelayRespRow {
  RowCommon      common;
  std::uint64_t  request_receipt_timestamp_seconds;
  std::uint32_t  request_receipt_timestamp_nanoseconds;
  PortIdentity   requesting_port_identity;
};

struct PdelayRespFollowUpRow {
  RowCommon      common;
  std::uint64_t  response_origin_timestamp_seconds;
  std::uint32_t  response_origin_timestamp_nanoseconds;
  PortIdentity   requesting_port_identity;
};

struct AnnounceRow {
  RowCommon      common;
  std::uint64_t  origin_timestamp_seconds;
  std::uint32_t  origin_timestamp_nanoseconds;
  std::int16_t   current_utc_offset;
  std::uint8_t   grandmaster_priority1;
  std::uint8_t   grandmaster_clock_class;
  std::uint8_t   grandmaster_clock_accuracy;
  std::uint16_t  grandmaster_offset_scaled_log_variance;
  std::uint8_t   grandmaster_priority2;
  std::array<std::uint8_t, 8> grandmaster_identity;
  std::uint16_t  steps_removed;
  std::uint8_t   time_source;
  bool           has_path_trace_tlv;
  std::uint16_t  path_trace_count;
};

// One row per clockIdentity entry in Announce's PATH_TRACE TLV — a many-rows-per-message table (like
// nanolance's Ipv6OptionRow), joined back to its Announce message via msg_index.
struct PathTraceEntryRow {
  std::uint64_t                msg_index;
  std::uint16_t                entry_index;
  std::array<std::uint8_t, 8>  clock_identity;
};

}  // namespace nmgptp

NANOM_DESCRIBE(nmgptp::PortIdentity, clock_identity, port_number);
NANOM_DESCRIBE(nmgptp::GptpHeader, transport_specific, message_type, reserved1, version_ptp,
               message_length, domain_number, reserved2, flags, correction_field, reserved3,
               source_port_identity, sequence_id, control_field, log_message_interval);
NANOM_DESCRIBE(nmgptp::RowCommon, msg_index, packet_id, domain_number, sequence_id, correction_field,
               log_message_interval, source_port_identity);
NANOM_DESCRIBE(nmgptp::SyncRow, common, origin_timestamp_seconds, origin_timestamp_nanoseconds);
NANOM_DESCRIBE(nmgptp::FollowUpRow, common, precise_origin_timestamp_seconds,
               precise_origin_timestamp_nanoseconds, has_follow_up_info_tlv,
               cumulative_scaled_rate_offset, gm_time_base_indicator, scaled_last_gm_freq_change);
NANOM_DESCRIBE(nmgptp::DelayReqRow, common, origin_timestamp_seconds, origin_timestamp_nanoseconds);
NANOM_DESCRIBE(nmgptp::DelayRespRow, common, receive_timestamp_seconds,
               receive_timestamp_nanoseconds, requesting_port_identity);
NANOM_DESCRIBE(nmgptp::PdelayReqRow, common, origin_timestamp_seconds, origin_timestamp_nanoseconds);
NANOM_DESCRIBE(nmgptp::PdelayRespRow, common, request_receipt_timestamp_seconds,
               request_receipt_timestamp_nanoseconds, requesting_port_identity);
NANOM_DESCRIBE(nmgptp::PdelayRespFollowUpRow, common, response_origin_timestamp_seconds,
               response_origin_timestamp_nanoseconds, requesting_port_identity);
NANOM_DESCRIBE(nmgptp::AnnounceRow, common, origin_timestamp_seconds, origin_timestamp_nanoseconds,
               current_utc_offset, grandmaster_priority1, grandmaster_clock_class,
               grandmaster_clock_accuracy, grandmaster_offset_scaled_log_variance,
               grandmaster_priority2, grandmaster_identity, steps_removed, time_source,
               has_path_trace_tlv, path_trace_count);
NANOM_DESCRIBE(nmgptp::PathTraceEntryRow, msg_index, entry_index, clock_identity);
