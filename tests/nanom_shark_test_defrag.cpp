// SPDX-License-Identifier: Apache-2.0
// Phase 2 tests: IPv4/IPv6 fragment reassembly, cross-checked against examples/nanom_shark/
// testdata/gen_fragments.py's known fragment patterns (in-order, out-of-order, overlap-conflict,
// missing-final-fragment/timeout), plus a NANOM_GENERATION-backed use-after-evict check.

#include <nanom_shark/decode_pass.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

namespace {

int failures = 0;
#define CHECK(cond)                                                \
  do {                                                              \
    if (!(cond)) {                                                  \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      ++failures;                                                   \
    }                                                                \
  } while (0)

bool read_file(const std::string& path, std::vector<std::uint8_t>& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  return true;
}

// Finds the (unique, by construction) PacketJson whose serialized form contains `needle`.
const nanom_shark::PacketJson* find_with(const std::vector<nanom_shark::PacketJson>& packets,
                                        const std::string& needle) {
  for (const auto& p : packets) {
    if (p.to_json().find(needle) != std::string::npos) return &p;
  }
  return nullptr;
}

void test_ipv4_defrag() {
  const char* testdata = NANOM_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/ipv4_fragments_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nanom_shark::AllTables tables;
  std::vector<nanom_shark::PacketJson> json_packets;
  nanom_shark::SinkHub sink{&json_packets};
  nanom_shark::DecodeOptions opts{};
  opts.ipv4_defrag.timeout_ticks = 3;  // force flow D's lone fragment to age out within this capture
  std::string error;

  CHECK(nanom_shark::run_decode_pass(file, tables, sink, opts, error));

  // Flow A (identification 0x1111): 2 in-order fragments -> completes, UDP length 24 (8-byte
  // header + 16-byte app payload), byte-exact through the reassembly.
  {
    const auto* pj = find_with(json_packets, "\"src_port\":1111");
    CHECK(pj != nullptr);
    if (pj) {
      const std::string j = pj->to_json();
      CHECK(j.find("\"completion_status\":0") != std::string::npos);
      CHECK(j.find("\"total_length\":24") != std::string::npos);
      CHECK(j.find("\"fragment_count\":2") != std::string::npos);
      CHECK(j.find("\"dst_port\":2222") != std::string::npos);
    }
  }

  // Flow B (identification 0x2222): 3 fragments delivered OUT OF ORDER (3rd, 1st, 2nd in capture
  // order) -> still completes once the middle one arrives; total 25 bytes (8 + 17).
  {
    const auto* pj = find_with(json_packets, "\"src_port\":3333");
    CHECK(pj != nullptr);
    if (pj) {
      const std::string j = pj->to_json();
      CHECK(j.find("\"completion_status\":0") != std::string::npos);
      CHECK(j.find("\"total_length\":25") != std::string::npos);
      CHECK(j.find("\"fragment_count\":3") != std::string::npos);
    }
  }

  // Flow C (identification 0x3333): the second fragment overlaps the first with DIFFERING bytes,
  // so it must never complete -- verified via AllTables below (exactly 2 completions total, and a
  // status-3 conflict entry present, neither of which flow C's packets could produce if it had
  // wrongly completed).

  // Cross-check via AllTables directly: exactly 2 completions (flow A, flow B) among the pushed
  // DatagramRow entries so far (flow C never completes, flow D hasn't been evicted yet at this
  // point in the loop -- eviction happens per-packet inside run_decode_pass, checked next).
  std::size_t complete_count = 0;
  tables.get<"datagram">().soa().for_each_chunk([&](const auto& chunk) {
    auto statuses = chunk.template as<std::uint8_t>(6);  // completion_status is column index 6
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (statuses[i] == 0) ++complete_count;
    }
  });
  CHECK(complete_count == 2);

  // Flow D (identification 0x4444): only ever sees its first fragment; with timeout_ticks=3 and
  // enough filler packets afterward, evict_stale() must age it out as timed_out (status 1), not
  // silently drop it.
  bool saw_timed_out = false;
  tables.get<"datagram">().soa().for_each_chunk([&](const auto& chunk) {
    auto statuses = chunk.template as<std::uint8_t>(6);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (statuses[i] == 1) saw_timed_out = true;
    }
  });
  CHECK(saw_timed_out);

  // And the overlap conflict (flow C) must be reported as status 3, distinct from a plain timeout.
  bool saw_conflict = false;
  tables.get<"datagram">().soa().for_each_chunk([&](const auto& chunk) {
    auto statuses = chunk.template as<std::uint8_t>(6);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (statuses[i] == 3) saw_conflict = true;
    }
  });
  CHECK(saw_conflict);
}

void test_ipv6_defrag() {
  const char* testdata = NANOM_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/ipv6_fragments_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nanom_shark::AllTables tables;
  std::vector<nanom_shark::PacketJson> json_packets;
  nanom_shark::SinkHub sink{&json_packets};
  nanom_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nanom_shark::run_decode_pass(file, tables, sink, opts, error));
  CHECK(json_packets.size() == 2);

  const auto* pj = find_with(json_packets, "\"src_port\":1111");
  CHECK(pj != nullptr);
  if (pj) {
    const std::string j = pj->to_json();
    CHECK(j.find("\"completion_status\":0") != std::string::npos);
    CHECK(j.find("\"total_length\":24") != std::string::npos);
    CHECK(j.find("\"dst_port\":2222") != std::string::npos);
  }
}

// Regression: a fuzzer (fuzz/fuzz_defrag.cpp) found that evict_stale() removed the timed-out entry
// from by_id_ but never cleaned up the matching key_to_id_ entry, so the SAME 4-tuple key reused
// after its previous reassembly aged out would resolve to the now-freed id and by_id_.at(id) would
// throw std::out_of_range. Exercises ReassemblyTable directly (not through a full decode pass) since
// this only needs one key, timed out once, then reused.
void test_key_reuse_after_eviction() {
  using nanom_shark::defrag::Ipv4Key;
  using nanom_shark::defrag::ReassemblyTable;

  ReassemblyTable<Ipv4Key>::Config cfg;
  cfg.timeout_ticks = 2;
  ReassemblyTable<Ipv4Key> table(cfg);
  const Ipv4Key key{{1, 2, 3, 4}, {5, 6, 7, 8}, 17, 42};
  const std::byte payload[4] = {};

  // First attempt: only ever sees one (non-terminal) fragment, then ages out.
  const auto r1 = table.add_fragment(key, /*pid=*/0, /*offset_bytes=*/0, /*more_fragments=*/true,
                                     std::span<const std::byte>(payload, 4));
  CHECK(!r1.completed);
  const auto evicted = table.evict_stale(/*now_packet_id=*/10);  // well past timeout_ticks=2
  CHECK(evicted.size() == 1);
  CHECK(evicted[0].completion_status == 1);  // timed_out, not complete

  // Second attempt, SAME key: must not throw, and must be treated as a brand-new reassembly (a
  // fresh datagram_id, not the stale one from the first attempt).
  const auto r2 = table.add_fragment(key, /*pid=*/11, /*offset_bytes=*/0, /*more_fragments=*/false,
                                     std::span<const std::byte>(payload, 4));
  CHECK(r2.completed);
  CHECK(r2.datagram_id != evicted[0].datagram_id);
}

// Zero-copy proof: a completed reassembly's Result::parts must be VIEWS into the caller's source
// buffer (fragment spans), not a fresh owned copy -- that's the whole point of the segmented
// completion path. Also checks the overlap-trim semantics and that materialize() reconstructs the
// same bytes lazily as the old eager stitch would have.
void test_zero_copy_completion() {
  using nanom_shark::defrag::Ipv4Key;
  using nanom_shark::defrag::ReassemblyTable;

  // A 24-byte "source file"; two fragments are non-overlapping views into it (offsets 0..12 and
  // 12..24). Byte value == index so reconstruction is easy to verify.
  std::array<std::byte, 24> src{};
  for (std::size_t i = 0; i < src.size(); ++i) src[i] = std::byte(i);
  const std::byte* base = src.data();

  ReassemblyTable<Ipv4Key> table;
  const Ipv4Key key{{10, 0, 0, 1}, {10, 0, 0, 2}, 17, 7};
  const auto r1 = table.add_fragment(key, 0, /*offset=*/0, /*more=*/true,
                                     std::span<const std::byte>(base, 12));
  CHECK(!r1.completed);
  const auto r2 = table.add_fragment(key, 1, /*offset=*/12, /*more=*/false,
                                     std::span<const std::byte>(base + 12, 12));
  CHECK(r2.completed);
  CHECK(r2.parts.size() == 24);

  // every returned part must alias the source buffer (zero-copy), never an owned copy
  bool all_alias = true;
  for (std::size_t i = 0; i < r2.parts.parts(); ++i) {
    const auto p = r2.parts.part(i);
    if (p.data() < base || p.data() + p.size() > base + src.size()) all_alias = false;
  }
  CHECK(all_alias);

  // parsing over the segment list yields the same bytes as the source
  nanom::seg_input in = nanom::from(r2.parts);
  for (std::size_t i = 0; i < 24; ++i) CHECK(in[i] == std::uint8_t(i));

  // materialize() is the opt-in stitch escape hatch: same bytes, and it's the ONLY owned copy
  const auto* mat = table.materialize(r2.datagram_id);
  CHECK(mat != nullptr);
  if (mat) {
    CHECK(mat->size() == 24);
    for (std::size_t i = 0; i < mat->size(); ++i) CHECK((*mat)[i] == std::byte(i));
  }
}

// Overlap-trim + conflict semantics must match the old eager stitch exactly.
void test_overlap_semantics() {
  using nanom_shark::defrag::Ipv4Key;
  using nanom_shark::defrag::ReassemblyTable;

  std::array<std::byte, 16> src{};
  for (std::size_t i = 0; i < src.size(); ++i) src[i] = std::byte(i);
  const std::byte* base = src.data();

  // agreeing overlap: frag [0,10) then [6,16); the [6,10) overlap is byte-identical -> completes,
  // trimmed (no conflict).
  {
    ReassemblyTable<Ipv4Key> table;
    const Ipv4Key key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 1};
    CHECK(!table.add_fragment(key, 0, 0, true, std::span<const std::byte>(base, 10)).completed);
    const auto r = table.add_fragment(key, 1, 6, false, std::span<const std::byte>(base + 6, 10));
    CHECK(r.completed);
    CHECK(r.parts.size() == 16);
    nanom::seg_input in = nanom::from(r.parts);
    for (std::size_t i = 0; i < 16; ++i) CHECK(in[i] == std::uint8_t(i));
  }

  // conflicting overlap: second fragment's overlapping bytes DIFFER -> never completes (the
  // decode pass reports this as completion_status 3 via evict_stale).
  {
    ReassemblyTable<Ipv4Key> table;
    const Ipv4Key key{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 2};
    std::array<std::byte, 10> other{};
    for (auto& b : other) b = std::byte(0xEE);  // different content in the overlap
    CHECK(!table.add_fragment(key, 0, 0, true, std::span<const std::byte>(base, 10)).completed);
    const auto r = table.add_fragment(key, 1, 6, false, std::span<const std::byte>(other.data(), 10));
    CHECK(!r.completed);  // conflict -> incomplete
  }
}

// ---------------------------------------------------------------------------------------------
// The Token / retire() release contract (defrag.hpp's file header). Three properties, each of
// which the streaming session's buffer-reuse safety rests on:
//   (a) an IN-FLIGHT reassembly never gives its tokens back -- not from retire(), not from
//       evict_stale() -- until it genuinely completes or ages out;
//   (b) retire()'s tokens are EXACTLY the fragments that contributed to THAT datagram, not some
//       other datagram's in-flight ones;
//   (c) after retire() the entry's span storage is GENUINELY empty -- inspected directly through
//       find(), because a returned token list proves nothing about whether the spans are gone.
// ---------------------------------------------------------------------------------------------

void test_retire_does_not_release_in_flight_tokens() {
  using nanom_shark::defrag::Ipv4Key;
  using nanom_shark::defrag::ReassemblyTable;

  std::array<std::byte, 64> src{};
  for (std::size_t i = 0; i < src.size(); ++i) src[i] = std::byte(i);

  ReassemblyTable<Ipv4Key>::Config cfg;
  cfg.timeout_ticks = 5;
  ReassemblyTable<Ipv4Key> table(cfg);
  const Ipv4Key key{{1, 2, 3, 4}, {5, 6, 7, 8}, 17, 900};

  // One non-terminal fragment: the datagram cannot complete, so token 77 stays pinned.
  const auto r1 = table.add_fragment(key, 0, 0, /*more=*/true,
                                     std::span<const std::byte>(src.data(), 8), /*token=*/77);
  CHECK(!r1.completed);
  CHECK(r1.retained);  // the span WAS stored, so the buffer is pinned

  // retire() on an incomplete datagram must be a no-op: nothing released, spans untouched.
  CHECK(table.retire(r1.datagram_id).empty());
  const auto* e1 = table.find(r1.datagram_id);
  CHECK(e1 != nullptr);
  if (e1) CHECK(e1->fragments.size() == 1);  // still holding the span -- correctly

  // A too-early eviction sweep (well inside the timeout) must not release it either.
  CHECK(table.evict_stale(/*now=*/1).empty());
  CHECK(table.find(r1.datagram_id) != nullptr);

  // Only when it genuinely ages out does the token come back, on the eviction summary.
  const auto evicted = table.evict_stale(/*now=*/50);
  CHECK(evicted.size() == 1);
  if (evicted.size() == 1) {
    CHECK(evicted[0].completion_status == 1);  // timed_out, never completed
    CHECK(evicted[0].tokens.size() == 1);
    if (evicted[0].tokens.size() == 1) CHECK(evicted[0].tokens[0] == 77);
    CHECK(evicted[0].fragment_count == 1);  // summary integers survive without the spans
  }
  CHECK(table.find(r1.datagram_id) == nullptr);  // really erased
}

void test_retire_tokens_match_contributing_fragments() {
  using nanom_shark::defrag::Ipv4Key;
  using nanom_shark::defrag::ReassemblyTable;

  std::array<std::byte, 64> src{};
  for (std::size_t i = 0; i < src.size(); ++i) src[i] = std::byte(i);

  ReassemblyTable<Ipv4Key> table;
  const Ipv4Key finishing{{10, 0, 0, 1}, {10, 0, 0, 2}, 17, 11};
  const Ipv4Key in_flight{{10, 0, 0, 3}, {10, 0, 0, 4}, 17, 22};

  // Interleave a SECOND, never-completing datagram between the first one's fragments, so a
  // retire() that mixed up whose fragments are whose would be caught.
  CHECK(!table.add_fragment(finishing, 0, 0, true, std::span<const std::byte>(src.data(), 8), 101)
             .completed);
  CHECK(!table.add_fragment(in_flight, 1, 0, true, std::span<const std::byte>(src.data(), 8), 202)
             .completed);
  CHECK(!table.add_fragment(finishing, 2, 8, true, std::span<const std::byte>(src.data() + 8, 8), 103)
             .completed);
  const auto done =
      table.add_fragment(finishing, 3, 16, false, std::span<const std::byte>(src.data() + 16, 8), 104);
  CHECK(done.completed);
  CHECK(done.parts.size() == 24);

  // Dispatch first (this is what the streaming session does), THEN retire.
  nanom::seg_input in = nanom::from(done.parts);
  for (std::size_t i = 0; i < 24; ++i) CHECK(in[i] == std::uint8_t(i));

  auto freed = table.retire(done.datagram_id);
  std::sort(freed.begin(), freed.end());
  CHECK(freed.size() == 3);
  if (freed.size() == 3) {
    CHECK(freed[0] == 101);
    CHECK(freed[1] == 103);
    CHECK(freed[2] == 104);
  }
  // 202 belongs to the still-open datagram and must NOT be in there.
  CHECK(std::find(freed.begin(), freed.end(), nanom_shark::defrag::Token{202}) == freed.end());

  // retire() is idempotent: a second call releases nothing (no double-free of a token).
  CHECK(table.retire(done.datagram_id).empty());

  // The other datagram is untouched and still pinning its buffer.
  const auto* open_entry = table.find(2);  // datagram ids are handed out 1,2,... in creation order
  CHECK(open_entry != nullptr);
  if (open_entry) {
    CHECK(open_entry->fragments.size() == 1);
    CHECK(open_entry->fragments[0].token == 202);
  }
}

void test_retire_actually_clears_spans() {
  using nanom_shark::defrag::Ipv4Key;
  using nanom_shark::defrag::ReassemblyTable;

  std::array<std::byte, 32> src{};
  for (std::size_t i = 0; i < src.size(); ++i) src[i] = std::byte(i);

  ReassemblyTable<Ipv4Key> table;
  const Ipv4Key key{{7, 7, 7, 7}, {8, 8, 8, 8}, 17, 33};
  CHECK(!table.add_fragment(key, 0, 0, true, std::span<const std::byte>(src.data(), 16), 5)
             .completed);
  const auto done =
      table.add_fragment(key, 1, 16, false, std::span<const std::byte>(src.data() + 16, 16), 6);
  CHECK(done.completed);

  // Before retire: the entry holds two fragment spans and a two-part parts list.
  {
    const auto* e = table.find(done.datagram_id);
    CHECK(e != nullptr);
    if (e) {
      CHECK(e->fragments.size() == 2);
      CHECK(!e->parts.empty());
      CHECK(!e->retired);
    }
  }

  const auto freed = table.retire(done.datagram_id);
  CHECK(freed.size() == 2);

  // After retire: inspect the ENTRY, not the returned token list -- the spans must be gone, so
  // there is nothing left in this table that could read the caller's buffer.
  {
    const auto* e = table.find(done.datagram_id);
    CHECK(e != nullptr);
    if (e) {
      CHECK(e->fragments.empty());
      CHECK(e->parts.empty());
      CHECK(e->retired);
      CHECK(e->completed);              // still known to have completed
      CHECK(e->fragment_count == 2);    // summary integers deliberately survive
      CHECK(e->total_length == 32);
    }
  }

  // materialize() must refuse rather than silently report a 0-byte datagram now that the source
  // spans it would stitch from are gone.
  CHECK(table.materialize(done.datagram_id) == nullptr);

  // Eviction of an already-retired entry reports no tokens (they were released at retire time),
  // but still reports the correct summary.
  const auto evicted = table.evict_stale(/*now=*/1000);
  CHECK(evicted.size() == 1);
  if (evicted.size() == 1) {
    CHECK(evicted[0].tokens.empty());
    CHECK(evicted[0].completion_status == 0);
    CHECK(evicted[0].fragment_count == 2);
    CHECK(evicted[0].gap_bytes == 0);
  }
}

// A fragment that add_fragment DROPS (at capacity, or oversized) must report retained == false --
// the streaming session relies on that to know the buffer was never pinned.
void test_dropped_fragment_is_not_retained() {
  using nanom_shark::defrag::Ipv4Key;
  using nanom_shark::defrag::ReassemblyTable;

  std::array<std::byte, 64> src{};

  ReassemblyTable<Ipv4Key>::Config cfg;
  cfg.max_concurrent = 1;
  cfg.max_datagram_bytes = 16;
  ReassemblyTable<Ipv4Key> table(cfg);

  const Ipv4Key a{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 1};
  const Ipv4Key b{{1, 1, 1, 1}, {2, 2, 2, 2}, 17, 2};

  const auto r1 = table.add_fragment(a, 0, 0, true, std::span<const std::byte>(src.data(), 8), 1);
  CHECK(r1.retained);
  // second key: at capacity (max_concurrent == 1) -> dropped, nothing stored, token 2 free
  const auto r2 = table.add_fragment(b, 1, 0, true, std::span<const std::byte>(src.data(), 8), 2);
  CHECK(!r2.retained);
  CHECK(r2.datagram_id == 0);
  // oversized for the existing datagram (8 stored + 32 > max_datagram_bytes 16) -> dropped too
  const auto r3 = table.add_fragment(a, 2, 8, false, std::span<const std::byte>(src.data(), 32), 3);
  CHECK(!r3.retained);

  const auto evicted = table.evict_stale(/*now=*/1000);
  CHECK(evicted.size() == 1);
  if (evicted.size() == 1) {
    CHECK(evicted[0].tokens.size() == 1);  // only the fragment that was actually stored
    if (evicted[0].tokens.size() == 1) CHECK(evicted[0].tokens[0] == 1);
  }
}

}  // namespace

int main() {
  test_ipv4_defrag();
  test_ipv6_defrag();
  test_key_reuse_after_eviction();
  test_zero_copy_completion();
  test_overlap_semantics();
  test_retire_does_not_release_in_flight_tokens();
  test_retire_tokens_match_contributing_fragments();
  test_retire_actually_clears_spans();
  test_dropped_fragment_is_not_retained();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nanom_shark_defrag_tests: OK\n");
  return 0;
}
