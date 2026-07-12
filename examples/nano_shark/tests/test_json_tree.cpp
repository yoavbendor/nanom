// SPDX-License-Identifier: Apache-2.0
// nano_shark Phase 1 tests: PacketJson layer-promotion logic + an end-to-end decode of a real
// fixture, with expected values cross-checked by hand against
// examples/nanotins_parity/testdata/ipv4_options_sample.ndjson (the nanotins-parity golden for the
// same capture) -- same decoded values, different JSON shape (nm::to_json's hex/decimal rendering
// vs that file's hand-written colon-MAC/dotted-IPv4 rendering).

#include "decode_pass.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {

int failures = 0;
#define CHECK(cond)                                                 \
  do {                                                              \
    if (!(cond)) {                                                  \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      ++failures;                                                   \
    }                                                                \
  } while (0)
#define CHECK_CONTAINS(haystack, needle)                                                       \
  do {                                                                                          \
    if ((haystack).find(needle) == std::string::npos) {                                        \
      std::printf("FAIL %s:%d: expected to find %s in: %s\n", __FILE__, __LINE__, needle,       \
                  (haystack).c_str());                                                          \
      ++failures;                                                                               \
    }                                                                                            \
  } while (0)

bool read_file(const std::string& path, std::vector<std::uint8_t>& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  return true;
}

void test_layer_promotion() {
  nano_shark::PacketJson pj(42);
  CHECK(pj.empty());
  pj.add_layer_json("vlan", "{\"vid\":10}");
  CHECK(pj.to_json() == "{\"_index\":42,\"_source\":{\"layers\":{\"vlan\":{\"vid\":10}}}}");

  // second occurrence of the same layer name promotes it to an array
  pj.add_layer_json("vlan", "{\"vid\":20}");
  CHECK(pj.to_json() ==
        "{\"_index\":42,\"_source\":{\"layers\":{\"vlan\":[{\"vid\":10},{\"vid\":20}]}}}");

  // a third occurrence appends within the array
  pj.add_layer_json("vlan", "{\"vid\":30}");
  CHECK_CONTAINS(pj.to_json(), "[{\"vid\":10},{\"vid\":20},{\"vid\":30}]");

  // a different layer name stays a plain object and preserves decode order (vlan first)
  pj.add_layer_json("ip", "{\"src\":1}");
  const std::string j = pj.to_json();
  CHECK(j.find("\"vlan\":") < j.find("\"ip\":"));
}

void test_ipv4_options_sample() {
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/ipv4_options_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));
  CHECK(json_packets.size() == 5);
  CHECK(tables.eth.rows() == 5);
  CHECK(tables.ipv4.rows() == 5);

  // packets: one row per captured frame regardless of decode outcome, in file order (byte offsets
  // strictly increasing) with a real (non-zero) captured length -- the anchor a byte-level sink
  // (the sibling `nanoshark` repo's Lance bridge) needs to resolve raw file bytes per packet.
  CHECK(tables.packets.rows() == 5);
  {
    std::uint64_t prev_offset = 0;
    bool first = true, offsets_increasing = true, caplens_positive = true;
    tables.packets.soa().for_each_chunk([&](const auto& c) {
      auto file_offsets = c.template as<std::uint64_t>(1);
      auto caplens = c.template as<std::uint32_t>(2);
      for (std::size_t i = 0; i < c.rows; ++i) {
        if (!first && file_offsets[i] <= prev_offset) offsets_increasing = false;
        if (caplens[i] == 0) caplens_positive = false;
        prev_offset = file_offsets[i];
        first = false;
      }
    });
    CHECK(offsets_increasing);
    CHECK(caplens_positive);
  }

  // packet 0: eth dst 02:00:00:00:00:02 (hex, no colons, per nm::to_json's byte-array rendering),
  // ethertype 0x0800 == 2048 decimal; ipv4 10.0.0.1 -> 10.0.0.2, protocol 17 (UDP), ttl 64,
  // total_length 32; udp 1111 -> 2222 -- all cross-checked against ipv4_options_sample.ndjson.
  const std::string p0 = json_packets.at(0).to_json();
  CHECK_CONTAINS(p0, "\"_index\":0");
  CHECK_CONTAINS(p0, "\"dst\":\"020000000002\"");
  CHECK_CONTAINS(p0, "\"src\":\"020000000001\"");
  CHECK_CONTAINS(p0, "\"ethertype\":2048");
  CHECK_CONTAINS(p0, "\"ip\":{");
  CHECK_CONTAINS(p0, "\"src\":\"0a000001\"");
  CHECK_CONTAINS(p0, "\"dst\":\"0a000002\"");
  CHECK_CONTAINS(p0, "\"protocol\":17");
  CHECK_CONTAINS(p0, "\"ttl\":64");
  CHECK_CONTAINS(p0, "\"total_length\":32");
  CHECK_CONTAINS(p0, "\"udp\":{");
  CHECK_CONTAINS(p0, "\"src_port\":1111");
  CHECK_CONTAINS(p0, "\"dst_port\":2222");

  // packet 1 is TCP (protocol 6), src_port 3333 -> dst_port 80
  const std::string p1 = json_packets.at(1).to_json();
  CHECK_CONTAINS(p1, "\"protocol\":6");
  CHECK_CONTAINS(p1, "\"tcp\":{");
  CHECK_CONTAINS(p1, "\"src_port\":3333");
  CHECK_CONTAINS(p1, "\"dst_port\":80");
}

void test_srv6_sample_ext_headers() {
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/srv6_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));
  CHECK(json_packets.size() == 7);

  // At least one packet in this fixture carries an SRv6 Routing header + segment list (the whole
  // point of walk_packet_ext over the plain walk_packet used by pcapng2json) -- confirm the JSON
  // sink surfaces both the SRH itself and its per-segment rows, which AllTables does not yet
  // tabulate (see decode_pass.hpp's header comment).
  bool saw_routing = false, saw_segment = false;
  for (const auto& pj : json_packets) {
    const std::string j = pj.to_json();
    if (j.find("\"ipv6.routing\":") != std::string::npos) saw_routing = true;
    if (j.find("\"ipv6.srh_segment\":") != std::string::npos) saw_segment = true;
  }
  CHECK(saw_routing);
  CHECK(saw_segment);
}

}  // namespace

int main() {
  test_layer_promotion();
  test_ipv4_options_sample();
  test_srv6_sample_ext_headers();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nano_shark_tests: OK\n");
  return 0;
}
