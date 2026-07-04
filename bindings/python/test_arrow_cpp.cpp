// SPDX-License-Identifier: Apache-2.0
// Pure-C++ consumer of nanom::arrow::export_stream — no Python. Drives the ArrowArrayStream exactly
// like pyarrow would (get_schema, get_next until end, release each) and reads values back, so the
// Arrow C Data Interface plumbing and the release/keepalive lifetime are checked under ASan/UBSan
// before any Python enters the picture.
//
// build (from repo root):
//   g++-13 -std=c++23 -fsanitize=address,undefined -I include -I bindings/python
//   bindings/python/test_arrow_cpp.cpp -o /tmp/test_arrow_cpp && /tmp/test_arrow_cpp
#include "nanom_arrow.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <cstdint>

namespace nm = nanom;

struct pkt_row {
  std::uint32_t              interface_id;
  std::uint64_t              ts;
  std::uint32_t              caplen, origlen;
  std::array<std::uint8_t, 6> eth_dst, eth_src;
  std::uint16_t              ethertype;
};
NANOM_DESCRIBE(pkt_row, interface_id, ts, caplen, origlen, eth_dst, eth_src, ethertype);

int main() {
  // small chunk size so we exercise MULTIPLE batches (streaming, not a single array)
  auto tbl = std::make_shared<nm::soa<pkt_row>>(/*chunk_rows=*/100);
  const int N = 250;
  std::uint64_t sum_caplen = 0, sum_ethertype = 0;
  for (int i = 0; i < N; ++i) {
    pkt_row r{};
    r.interface_id = 0;
    r.ts = 1'000'000ULL + std::uint64_t(i);
    r.caplen = r.origlen = std::uint32_t(60 + i);
    r.eth_dst = {0, 1, 2, 3, 4, std::uint8_t(i)};
    r.eth_src = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, std::uint8_t(i)};
    r.ethertype = std::uint16_t(0x0800 + (i & 1));  // alternate 0x0800 / 0x0801
    sum_caplen += r.caplen;
    sum_ethertype += r.ethertype;
    tbl->push(r);
  }
  const std::size_t ncol = tbl->columns().size();

  ArrowArrayStream stream;
  nm::arrow::export_stream(tbl, &stream);

  // Drop our own reference NOW: the stream + its batches must keep the soa (and its buffers) alive.
  tbl.reset();

  // ---- schema ----
  ArrowSchema schema;
  assert(stream.get_schema(&stream, &schema) == 0);
  assert(schema.n_children == (int64_t)ncol);
  assert(std::string(schema.format) == "+s");
  std::printf("schema: %lld columns:", (long long)schema.n_children);
  for (int64_t i = 0; i < schema.n_children; ++i)
    std::printf(" %s(%s)", schema.children[i]->name, schema.children[i]->format);
  std::printf("\n");
  schema.release(&schema);
  assert(schema.release == nullptr);

  // ---- batches ----
  std::uint64_t got_rows = 0, got_caplen = 0, got_ethertype = 0;
  int batches = 0;
  for (;;) {
    ArrowArray arr;
    assert(stream.get_next(&stream, &arr) == 0);
    if (arr.release == nullptr) break;  // end of stream
    ++batches;
    got_rows += std::uint64_t(arr.length);
    assert(arr.n_children == (int64_t)ncol);
    // caplen is column index 2, ethertype the last column — read straight from the borrowed buffers.
    const auto* caplen = static_cast<const std::uint32_t*>(arr.children[2]->buffers[1]);
    const auto* etype = static_cast<const std::uint16_t*>(arr.children[ncol - 1]->buffers[1]);
    for (int64_t r = 0; r < arr.length; ++r) {
      got_caplen += caplen[r];
      got_ethertype += etype[r];
    }
    arr.release(&arr);
    assert(arr.release == nullptr);
  }
  stream.release(&stream);

  std::printf("batches=%d rows=%llu caplen_sum=%llu ethertype_sum=%llu\n",
              batches, (unsigned long long)got_rows, (unsigned long long)got_caplen,
              (unsigned long long)got_ethertype);
  assert(got_rows == (std::uint64_t)N);
  assert(batches == 3);  // 250 rows / 100 per chunk -> 100,100,50
  assert(got_caplen == sum_caplen);
  assert(got_ethertype == sum_ethertype);
  std::printf("OK: stream drained, values match, no leaks/UB (under sanitizers)\n");
  return 0;
}
