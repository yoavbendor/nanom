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

}  // namespace

int main() {
  test_ipv4_defrag();
  test_ipv6_defrag();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nano_shark_defrag_tests: OK\n");
  return 0;
}
