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

// An soa<T> that is only reachable as a `const soa<T>&` sub-object of a larger owning aggregate --
// exactly the shape nanom_shark's `table_set` has (fixed, privately-inherited table slots handed out
// by `for_each_table` as `const soa<Row>&`), which is what the keepalive overload of export_stream
// exists for.
struct owning_aggregate {
  nm::soa<pkt_row> table{/*chunk_rows=*/100};
  const nm::soa<pkt_row>& view() const { return table; }
};

// Fill helper shared by both drivers, so the two exports are compared on identical data.
static void fill(nm::soa<pkt_row>& t, int n, std::uint64_t& sum_caplen, std::uint64_t& sum_ethertype) {
  for (int i = 0; i < n; ++i) {
    pkt_row r{};
    r.interface_id = 0;
    r.ts = 1'000'000ULL + std::uint64_t(i);
    r.caplen = r.origlen = std::uint32_t(60 + i);
    r.eth_dst = {0, 1, 2, 3, 4, std::uint8_t(i)};
    r.eth_src = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, std::uint8_t(i)};
    r.ethertype = std::uint16_t(0x0800 + (i & 1));  // alternate 0x0800 / 0x0801
    sum_caplen += r.caplen;
    sum_ethertype += r.ethertype;
    t.push(r);
  }
}

// Drive a stream exactly as pyarrow would and return (batches, rows, caplen sum, ethertype sum).
struct drained { int batches; std::uint64_t rows, caplen, ethertype; };
static drained drain(ArrowArrayStream& stream, std::size_t ncol) {
  drained d{0, 0, 0, 0};
  for (;;) {
    ArrowArray arr;
    assert(stream.get_next(&stream, &arr) == 0);
    if (arr.release == nullptr) break;  // end of stream
    ++d.batches;
    d.rows += std::uint64_t(arr.length);
    assert(arr.n_children == (int64_t)ncol);
    const auto* caplen = static_cast<const std::uint32_t*>(arr.children[2]->buffers[1]);
    const auto* etype = static_cast<const std::uint16_t*>(arr.children[ncol - 1]->buffers[1]);
    for (int64_t r = 0; r < arr.length; ++r) {
      d.caplen += caplen[r];
      d.ethertype += etype[r];
    }
    arr.release(&arr);
    assert(arr.release == nullptr);
  }
  stream.release(&stream);
  return d;
}

// ---- the export_stream(const soa<T>&, shared_ptr<const void> keepalive, ...) overload ------------
// Same data, same expected numbers as the by-value overload below, but the table is borrowed and the
// lifetime comes from a separately-supplied keepalive owning the ENCLOSING aggregate. The aggregate's
// own shared_ptr is dropped before the stream is drained, so ASan sees a use-after-free if the
// keepalive is not actually holding it. Also exports TWICE from one table (independent cursors), the
// property the Python binding's "fresh stream per __arrow_c_stream__ call" relies on.
static void test_const_ref_keepalive_overload() {
  auto agg = std::make_shared<owning_aggregate>();
  const int N = 250;
  std::uint64_t sum_caplen = 0, sum_ethertype = 0;
  fill(agg->table, N, sum_caplen, sum_ethertype);
  const std::size_t ncol = agg->table.columns().size();

  // const access only -- no const_cast, no aliasing shared_ptr, no non-const member pointer.
  const owning_aggregate& cagg = *agg;
  std::shared_ptr<const void> keepalive = agg;

  ArrowArrayStream s1, s2;
  nm::arrow::export_stream(cagg.view(), keepalive, &s1);
  nm::arrow::export_stream(cagg.view(), keepalive, &s2);  // second, independent stream

  ArrowSchema schema;
  assert(s1.get_schema(&s1, &schema) == 0);
  assert(schema.n_children == (int64_t)ncol);
  assert(std::string(schema.format) == "+s");
  schema.release(&schema);

  // Drop every non-stream reference: only the streams' keepalives hold the aggregate now.
  agg.reset();
  keepalive.reset();

  const drained d1 = drain(s1, ncol);
  const drained d2 = drain(s2, ncol);
  std::printf("keepalive overload: stream1 batches=%d rows=%llu caplen=%llu ethertype=%llu\n",
              d1.batches, (unsigned long long)d1.rows, (unsigned long long)d1.caplen,
              (unsigned long long)d1.ethertype);
  std::printf("keepalive overload: stream2 batches=%d rows=%llu caplen=%llu ethertype=%llu\n",
              d2.batches, (unsigned long long)d2.rows, (unsigned long long)d2.caplen,
              (unsigned long long)d2.ethertype);
  assert(d1.rows == (std::uint64_t)N && d2.rows == (std::uint64_t)N);
  assert(d1.batches == 3 && d2.batches == 3);  // 250 rows / 100 per chunk -> 100,100,50
  assert(d1.caplen == sum_caplen && d2.caplen == sum_caplen);
  assert(d1.ethertype == sum_ethertype && d2.ethertype == sum_ethertype);
  std::printf("OK: const-ref + keepalive overload -- borrowed table outlives its owner's own "
              "shared_ptr, two independent streams both drain fully\n");
}

int main() {
  test_const_ref_keepalive_overload();

  // small chunk size so we exercise MULTIPLE batches (streaming, not a single array)
  auto tbl = std::make_shared<nm::soa<pkt_row>>(/*chunk_rows=*/100);
  const int N = 250;
  std::uint64_t sum_caplen = 0, sum_ethertype = 0;
  fill(*tbl, N, sum_caplen, sum_ethertype);
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
