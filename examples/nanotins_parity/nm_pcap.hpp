// SPDX-License-Identifier: Apache-2.0
#pragma once

// pcap/pcapng block scanner built on nanom — the parity port of nanotins'
// pcap_blocks.hpp. Same job: Phase A walks block/record boundaries into flat
// BlockRefs, Phase B parses one EPB/record into a typed view. Zero-copy: all
// views point into the caller's buffer.
//
// Where nanotins hand-rolls rd16/rd32(le) readers, nanom declares the block
// headers once as structs and picks the byte order at parse time with
// strct<T>(order) — pcapng's per-section endianness (and classic pcap's
// swapped magics) become one runtime argument instead of a parallel reader
// set.

#include <nanom/nanom.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace nmpcap {

namespace nm = nanom;

// ---- wire structs: plain integral fields = byte order chosen at parse time ----
struct pcap_global_hdr {           // 24 bytes, after the 4-byte magic
  std::uint16_t major, minor;
  std::uint32_t thiszone, sigfigs, snaplen, link_type;
};
struct pcap_rec_hdr {              // 16 bytes
  std::uint32_t ts_sec, ts_frac, caplen, origlen;
};
struct png_block_hdr {             // every pcapng block: type + total length
  std::uint32_t type, total_len;
};
struct png_shb_body {              // after the block header
  std::uint32_t byte_order_magic;
  std::uint16_t major, minor;
  std::uint64_t section_len;
};
struct png_idb_body {
  std::uint16_t link_type;
  std::uint16_t reserved;
  std::uint32_t snaplen;
};
struct png_epb_body {
  std::uint32_t interface_id;
  std::uint32_t ts_high, ts_low;
  std::uint32_t caplen, origlen;
};
struct png_opt_hdr {              // a pcapng option TLV header: code + declared length
  std::uint16_t code, length;     // value follows, padded to a 32-bit boundary; code 0 = opt_endofopt
};

}  // namespace nmpcap

NANOM_DESCRIBE(nmpcap::pcap_global_hdr, major, minor, thiszone, sigfigs, snaplen, link_type);
NANOM_DESCRIBE(nmpcap::pcap_rec_hdr, ts_sec, ts_frac, caplen, origlen);
NANOM_DESCRIBE(nmpcap::png_block_hdr, type, total_len);
NANOM_DESCRIBE(nmpcap::png_shb_body, byte_order_magic, major, minor, section_len);
NANOM_DESCRIBE(nmpcap::png_idb_body, link_type, reserved, snaplen);
NANOM_DESCRIBE(nmpcap::png_epb_body, interface_id, ts_high, ts_low, caplen, origlen);
NANOM_DESCRIBE(nmpcap::png_opt_hdr, code, length);

namespace nmpcap {

enum class Kind : std::uint8_t { Shb, Idb, Epb, PcapRecord, SimplePacket, Other };

struct BlockRef {
  std::uint64_t file_offset;   // start of the block/record in the buffer
  std::uint32_t length;        // total length incl. framing/padding
  std::uint32_t type_or_link;  // pcapng block type, or pcap link type for PcapRecord
  Kind          kind;
  bool          little_endian;
};

struct IdbView { std::uint16_t link_type; std::uint32_t snaplen; };
struct EpbView {
  std::uint32_t interface_id = 0;
  std::uint64_t ts_raw = 0;
  std::uint32_t caplen = 0, origlen = 0;
  std::uint64_t payload_file_offset = 0;
};

// pcap magics (read as little-endian u32) — value tells both order and tick unit.
inline constexpr std::uint32_t kMagicUsLE = 0xA1B2C3D4U, kMagicUsBE = 0xD4C3B2A1U;
inline constexpr std::uint32_t kMagicNsLE = 0xA1B23C4DU, kMagicNsBE = 0x4D3CB2A1U;
inline constexpr std::uint32_t kByteOrderMagic = 0x1A2B3C4DU;
inline constexpr std::uint32_t kShb = 0x0A0D0D0AU, kIdb = 1, kEpb = 6, kSpb = 3;

inline constexpr std::endian order_of(bool little) {
  return little ? std::endian::little : std::endian::big;
}
inline constexpr std::size_t pad4(std::size_t n) { return (n + 3U) & ~std::size_t{3}; }

// ---- Phase A: boundary scan (whole buffer). Same contract as nanotins
// scan_blocks: BlockRefs out, false + error on a malformed frame. ----
inline bool scan_blocks(nm::bytes file, std::vector<BlockRef>& out, std::string& error) {
  nm::input whole = nm::from(file);
  if (whole.size() < 4) return (error = "file too small", false);

  const std::uint32_t magic = nm::le_u32(whole)->value;

  if (magic == kShb) {  // ---- pcapng: SHB / IDB / EPB / SPB / other blocks ----
    bool little = true;
    nm::input cur = whole;
    while (!cur.empty()) {
      const std::uint64_t off = cur.offset();
      // The SHB's own header endianness is revealed by its byte_order_magic —
      // peek it before deciding how to read total_len.
      if (auto t = nm::peek(nm::le_u32)(cur); t && t->value == kShb) {
        auto bom = nm::preceded(nm::take(8), nm::le_u32)(cur);
        if (!bom) return (error = "truncated SHB", false);
        little = (bom->value == kByteOrderMagic);
      }
      auto hdr = nm::strct<png_block_hdr>(order_of(little))(cur);
      if (!hdr) return (error = "truncated block header at offset " + std::to_string(off), false);
      const std::uint32_t total = hdr->value.total_len;
      if (total < 12 || total % 4 != 0 || total > cur.size())
        return (error = "bad block length " + std::to_string(total) + " at offset " + std::to_string(off), false);
      Kind k = Kind::Other;
      switch (hdr->value.type) {
        case kShb: k = Kind::Shb; break;
        case kIdb: k = Kind::Idb; break;
        case kEpb: k = Kind::Epb; break;
        case kSpb: k = Kind::SimplePacket; break;
        default: break;
      }
      out.push_back(BlockRef{off, total, hdr->value.type, k, little});
      cur = cur.advance(total);
    }
    return true;
  }

  if (magic == kMagicUsLE || magic == kMagicNsLE || magic == kMagicUsBE || magic == kMagicNsBE) {
    // ---- classic pcap: global header + records ----
    const bool little = (magic == kMagicUsLE || magic == kMagicNsLE);
    auto gh = nm::preceded(nm::take(4), nm::strct<pcap_global_hdr>(order_of(little)))(whole);
    if (!gh) return (error = "truncated pcap global header", false);
    const std::uint32_t link = gh->value.link_type;
    // parity with nanotins: expose the global header as a synthetic IDB so
    // downstream interface/link bookkeeping is format-agnostic
    out.push_back(BlockRef{0, 24, kIdb, Kind::Idb, little});
    nm::input cur = gh->rest;
    while (!cur.empty()) {
      const std::uint64_t off = cur.offset();
      auto rh = nm::strct<pcap_rec_hdr>(order_of(little))(cur);
      if (!rh) return (error = "truncated pcap record header at offset " + std::to_string(off), false);
      const std::uint64_t total = 16 + std::uint64_t(rh->value.caplen);
      if (rh->value.caplen > rh->rest.size())
        return (error = "truncated pcap record at offset " + std::to_string(off), false);
      out.push_back(BlockRef{off, std::uint32_t(total), link, Kind::PcapRecord, little});
      cur = rh->rest.advance(rh->value.caplen);
    }
    return true;
  }

  return (error = "not a pcap or pcapng file (unknown magic)", false);
}

// ---- Phase B: parse one IDB / EPB / pcap record (pure; callable per-ref) ----
inline bool parse_idb(nm::bytes file, const BlockRef& ref, IdbView& out) {
  if (ref.kind != Kind::Idb) return false;
  nm::input at = nm::from(file).advance(std::size_t(ref.file_offset));
  // synthetic IDB over a classic-pcap global header (see scan_blocks)
  if (ref.length == 24) {
    auto m = nm::le_u32(at);
    if (m && (m->value == kMagicUsLE || m->value == kMagicNsLE ||
              m->value == kMagicUsBE || m->value == kMagicNsBE)) {
      auto g = nm::strct<pcap_global_hdr>(order_of(ref.little_endian))(m->rest);
      if (!g) return false;
      out = IdbView{std::uint16_t(g->value.link_type), g->value.snaplen};
      return true;
    }
  }
  auto r = nm::strct<png_idb_body>(order_of(ref.little_endian))(at.advance(8));
  if (!r) return false;
  out = IdbView{r->value.link_type, r->value.snaplen};
  return true;
}

inline bool parse_epb(nm::bytes file, const BlockRef& ref, EpbView& out) {
  if (ref.kind == Kind::Epb) {
    nm::input body = nm::from(file).advance(std::size_t(ref.file_offset) + 8);
    auto r = nm::strct<png_epb_body>(order_of(ref.little_endian))(body);
    if (!r) return false;
    if (28 + std::uint64_t(r->value.caplen) + 4 > ref.length) return false;  // caplen must fit the block
    out.interface_id = r->value.interface_id;
    out.ts_raw = (std::uint64_t(r->value.ts_high) << 32) | r->value.ts_low;
    out.caplen = r->value.caplen;
    out.origlen = r->value.origlen;
    out.payload_file_offset = ref.file_offset + 28;
    return true;
  }
  if (ref.kind == Kind::PcapRecord) {
    nm::input body = nm::from(file).advance(std::size_t(ref.file_offset));
    auto r = nm::strct<pcap_rec_hdr>(order_of(ref.little_endian))(body);
    if (!r) return false;
    out.interface_id = 0;
    out.ts_raw = (std::uint64_t(r->value.ts_sec) << 32) | r->value.ts_frac;
    out.caplen = r->value.caplen;
    out.origlen = r->value.origlen;
    out.payload_file_offset = ref.file_offset + 16;
    return true;
  }
  return false;
}

}  // namespace nmpcap
