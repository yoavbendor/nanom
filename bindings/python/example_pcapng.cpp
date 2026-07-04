// SPDX-License-Identifier: Apache-2.0
// nanom_pcap — a ~1-file example of "nanom from Python": parse a pcapng capture in C++ with nanom,
// accumulate packet rows into an soa<>, and hand Python a zero-copy Arrow stream (via the Arrow
// PyCapsule protocol) that polars / pyarrow / pandas / duckdb all import without a copy.
//
// The point for a Python dev: to parse YOUR binary format, change ONLY the `pkt_row` struct + the
// small fill loop below — the Arrow bridge (nanom_arrow.hpp) and the Python side stay identical.
#include "nanom_arrow.hpp"

#include <nanom/nanom.hpp>

#include <nanobind/nanobind.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>

namespace nb = nanobind;
namespace nm = nanom;

// ---- the row you want as columns (edit this + the fill loop to parse a different format) ---------
struct pkt_row {
  std::uint32_t               interface_id;
  std::uint64_t               ts;        // pcapng raw 64-bit timestamp
  std::uint32_t               caplen, origlen;
  std::array<std::uint8_t, 6> eth_dst, eth_src;  // -> Arrow fixed_size_binary(6)
  std::uint16_t               ethertype;         // decoded to host order
};
NANOM_DESCRIBE(pkt_row, interface_id, ts, caplen, origlen, eth_dst, eth_src, ethertype);

// ---- minimal pcapng wire structs (endianness chosen at parse time via strct<T>(order)) ----------
namespace {
struct png_block_hdr { std::uint32_t type, total_len; };
struct png_epb_body  { std::uint32_t interface_id, ts_high, ts_low, caplen, origlen; };
}  // namespace
NANOM_DESCRIBE(png_block_hdr, type, total_len);
NANOM_DESCRIBE(png_epb_body, interface_id, ts_high, ts_low, caplen, origlen);

namespace {
constexpr std::uint32_t kShb = 0x0A0D0D0AU, kEpb = 6, kByteOrderMagic = 0x1A2B3C4DU;
constexpr std::endian order_of(bool little) {
  return little ? std::endian::little : std::endian::big;
}

std::shared_ptr<nm::soa<pkt_row>> parse_pcapng(const std::uint8_t* data, std::size_t n) {
  auto tbl = std::make_shared<nm::soa<pkt_row>>();
  bool little = true;
  std::size_t pos = 0;
  while (pos + 8 <= n) {
    auto hdr = nm::strct<png_block_hdr>(order_of(little))(nm::from(data + pos, n - pos));
    if (!hdr) break;
    std::uint32_t type = hdr->value.type, total = hdr->value.total_len;
    if (type == kShb) {                       // SHB type is a byte-order-independent palindrome
      if (pos + 12 > n) break;
      std::uint32_t bom;
      std::memcpy(&bom, data + pos + 8, 4);   // byte-order magic is read little-endian
      little = (bom == kByteOrderMagic);
      auto h2 = nm::strct<png_block_hdr>(order_of(little))(nm::from(data + pos, n - pos));
      if (!h2) break;
      total = h2->value.total_len;
    }
    if (total < 12 || total % 4 != 0 || pos + total > n) break;
    if (type == kEpb) {
      auto e = nm::strct<png_epb_body>(order_of(little))(nm::from(data + pos + 8, total - 8));
      if (e) {
        pkt_row r{};
        r.interface_id = e->value.interface_id;
        r.ts = (std::uint64_t(e->value.ts_high) << 32) | e->value.ts_low;
        r.caplen = e->value.caplen;
        r.origlen = e->value.origlen;
        const std::uint8_t* pd = data + pos + 28;   // packet data starts after the 20-byte fixed body
        if (e->value.caplen >= 14 && 28 + 14 <= total) {
          std::copy(pd, pd + 6, r.eth_dst.begin());
          std::copy(pd + 6, pd + 12, r.eth_src.begin());
          r.ethertype = std::uint16_t((pd[12] << 8) | pd[13]);  // big-endian on the wire
        }
        tbl->push(r);
      }
    }
    pos += total;
  }
  return tbl;
}

// A tiny handle exposing the Arrow PyCapsule protocol; holding it keeps the soa (and its buffers)
// alive for as long as Python references the table.
struct PcapTable {
  std::shared_ptr<nm::soa<pkt_row>> soa;

  std::size_t num_rows() const { return soa->rows(); }

  // __arrow_c_stream__ -> a PyCapsule named "arrow_array_stream" that the consumer moves out and
  // releases; our capsule cleanup releases it only if the consumer didn't (release still set).
  nb::capsule arrow_c_stream(nb::object /*requested_schema*/) const {
    auto* c_stream = static_cast<ArrowArrayStream*>(std::malloc(sizeof(ArrowArrayStream)));
    nm::arrow::export_stream(soa, c_stream);
    return nb::capsule(c_stream, "arrow_array_stream", [](void* p) noexcept {
      auto* s = static_cast<ArrowArrayStream*>(p);
      if (s->release) s->release(s);
      std::free(s);
    });
  }
};
}  // namespace

NB_MODULE(nanom_pcap, m) {
  m.doc() = "nanom pcapng parser -> zero-copy Arrow (example of using nanom from Python)";

  nb::class_<PcapTable>(m, "PcapTable")
      .def("__len__", &PcapTable::num_rows)
      .def_prop_ro("num_rows", &PcapTable::num_rows)
      .def("__arrow_c_stream__", &PcapTable::arrow_c_stream, nb::arg("requested_schema") = nb::none(),
           "Arrow PyCapsule protocol: import with pa.table(t) / pl.from_arrow(t) (zero-copy).");

  m.def(
      "parse",
      [](nb::bytes buf) {
        return PcapTable{parse_pcapng(reinterpret_cast<const std::uint8_t*>(buf.c_str()), buf.size())};
      },
      nb::arg("pcapng_bytes"),
      "Parse pcapng bytes and return a PcapTable (one row per Enhanced Packet Block).");
}
