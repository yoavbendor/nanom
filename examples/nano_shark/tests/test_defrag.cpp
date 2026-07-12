// SPDX-License-Identifier: Apache-2.0
// Phase 2 tests: IPv4/IPv6 fragment reassembly, cross-checked against examples/nano_shark/
// testdata/gen_fragments.py's known fragment patterns (in-order, out-of-order, overlap-conflict,
// missing-final-fragment/timeout), plus a NANOM_GENERATION-backed use-after-evict check.

#include "decode_pass.hpp"

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
const nano_shark::PacketJson* find_with(const std::vector<nano_shark::PacketJson>& packets,
                                        const std::string& needle) {
  for (const auto& p : packets) {
    if (p.to_json().find(needle) != std::string::npos) return &p;
  }
  return nullptr;
}

void test_ipv4_defrag() {
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/ipv4_fragments_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};
  opts.ipv4_defrag.timeout_ticks = 3;  // force flow D's lone fragment to age out within this capture
  std::string error;

  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));

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
  tables.datagram.soa().for_each_chunk([&](const auto& chunk) {
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
  tables.datagram.soa().for_each_chunk([&](const auto& chunk) {
    auto statuses = chunk.template as<std::uint8_t>(6);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (statuses[i] == 1) saw_timed_out = true;
    }
  });
  CHECK(saw_timed_out);

  // And the overlap conflict (flow C) must be reported as status 3, distinct from a plain timeout.
  bool saw_conflict = false;
  tables.datagram.soa().for_each_chunk([&](const auto& chunk) {
    auto statuses = chunk.template as<std::uint8_t>(6);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (statuses[i] == 3) saw_conflict = true;
    }
  });
  CHECK(saw_conflict);
}

void test_ipv6_defrag() {
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/ipv6_fragments_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));
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
  using nano_shark::defrag::Ipv4Key;
  using nano_shark::defrag::ReassemblyTable;

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
  using nano_shark::defrag::Ipv4Key;
  using nano_shark::defrag::ReassemblyTable;

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
  using nano_shark::defrag::Ipv4Key;
  using nano_shark::defrag::ReassemblyTable;

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

}  // namespace

int main() {
  test_ipv4_defrag();
  test_ipv6_defrag();
  test_key_reuse_after_eviction();
  test_zero_copy_completion();
  test_overlap_semantics();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nano_shark_defrag_tests: OK\n");
  return 0;
}
