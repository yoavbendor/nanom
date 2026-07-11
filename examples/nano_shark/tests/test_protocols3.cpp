// SPDX-License-Identifier: Apache-2.0
// Phase 3 tests: SOME/IP (header + SD entries/options + optional TLV members), gPTP (all 8
// message kinds + PATH_TRACE), and LLDP (reusing the already-tested dpar_sample.pcap fixture).

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

void test_gptp_all_kinds() {
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/gptp_fixture.pcapng", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));
  CHECK(json_packets.size() == 9);  // 8 kinds + a second Announce (with PATH_TRACE)

  // All 9 gPTP tables populated (the 8 message kinds' 1-row-each, Announce x2, path_trace x3).
  CHECK(tables.gptp.sync.rows() == 1);
  CHECK(tables.gptp.delay_req.rows() == 1);
  CHECK(tables.gptp.pdelay_req.rows() == 1);
  CHECK(tables.gptp.pdelay_resp.rows() == 1);
  CHECK(tables.gptp.follow_up.rows() == 1);
  CHECK(tables.gptp.delay_resp.rows() == 1);
  CHECK(tables.gptp.pdelay_resp_follow_up.rows() == 1);
  CHECK(tables.gptp.announce.rows() == 2);
  CHECK(tables.gptp.path_trace.rows() == 3);

  // Every kind is also visible in the JSON sink (one layer per message, from the same decode pass).
  bool saw[8] = {};
  const char* kinds[8] = {"gptp.sync",   "gptp.delay_req",  "gptp.pdelay_req", "gptp.pdelay_resp",
                          "gptp.follow_up", "gptp.delay_resp", "gptp.pdelay_resp_follow_up",
                          "gptp.announce"};
  for (const auto& pj : json_packets) {
    const std::string j = pj.to_json();
    for (int i = 0; i < 8; ++i) {
      if (j.find(std::string("\"") + kinds[i] + "\":") != std::string::npos) saw[i] = true;
    }
  }
  for (int i = 0; i < 8; ++i) CHECK(saw[i]);

  // The second Announce carries a 3-entry PATH_TRACE, visible as a promoted JSON array.
  bool saw_path_trace_array = false;
  for (const auto& pj : json_packets) {
    const std::string j = pj.to_json();
    if (j.find("\"gptp.path_trace\":[") != std::string::npos) saw_path_trace_array = true;
  }
  CHECK(saw_path_trace_array);
}

void test_someip_default_ports() {
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/someip_fixture.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};  // default someip_ports = {30490}; someip_tlv_ports empty

  std::string error;
  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));

  // request, response, SD message all ride on port 30490 -> 3 SomeipNode rows; the 4th packet (a
  // TLV message on port 30509) is NOT on a configured port, so it must be invisible by default.
  CHECK(tables.someip.rows() == 3);
  CHECK(tables.someip_tlv.rows() == 0);

  // Exactly one SD message -> FindService + OfferService entries, one IPv4 endpoint option.
  CHECK(tables.someip_sd_entry.rows() == 2);
  CHECK(tables.someip_sd_option.rows() == 1);

  bool saw_someip = false, saw_sd_entry = false, saw_sd_option = false;
  for (const auto& pj : json_packets) {
    const std::string j = pj.to_json();
    if (j.find("\"someip\":{") != std::string::npos) saw_someip = true;
    if (j.find("\"someip.sd_entry\":") != std::string::npos) saw_sd_entry = true;
    if (j.find("\"someip.sd_option\":") != std::string::npos) saw_sd_option = true;
  }
  CHECK(saw_someip);
  CHECK(saw_sd_entry);
  CHECK(saw_sd_option);

  // The endpoint option decodes to l4proto=17 (UDP), port=30509, address 192.168.1.10.
  bool found_option = false;
  tables.someip_sd_option.soa().for_each_chunk([&](const auto& chunk) {
    auto l4 = chunk.template as<std::uint8_t>(4);   // packet_id,option_index,length,type,l4proto,...
    auto port = chunk.template as<std::uint16_t>(5);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (l4[i] == 17 && port[i] == 30509) found_option = true;
    }
  });
  CHECK(found_option);
}

void test_someip_tlv_opt_in() {
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/someip_fixture.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};
  opts.someip_ports.push_back(30509);
  opts.someip_tlv_ports.push_back(30509);

  std::string error;
  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));

  CHECK(tables.someip.rows() == 4);       // now includes the TLV message
  CHECK(tables.someip_tlv.rows() == 2);   // its two TLV members

  bool saw_data_id_1 = false, saw_data_id_2 = false;
  tables.someip_tlv.soa().for_each_chunk([&](const auto& chunk) {
    auto data_id = chunk.template as<std::uint16_t>(2);  // packet_id,tlv_index,data_id,...
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (data_id[i] == 0x001) saw_data_id_1 = true;
      if (data_id[i] == 0x002) saw_data_id_2 = true;
    }
  });
  CHECK(saw_data_id_1);
  CHECK(saw_data_id_2);
}

void test_lldp_dpar_sample() {
  // Reuses the already-tested examples/nanotins_parity/testdata/dpar_sample.pcap fixture (proven
  // to contain LLDP frames via the existing parity_lldp ctest), rather than a new one.
  const char* testdata = NANO_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/../../nanotins_parity/testdata/dpar_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{&json_packets};
  nano_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nano_shark::run_decode_pass(file, tables, sink, opts, error));
  CHECK(tables.lldp.rows() > 0);

  // Cross-checked against nanotins_parity/testdata/lldp_sample.ndjson's first row (packet 0's
  // Chassis ID TLV: type 1, length 7, subtype 4).
  bool found = false;
  tables.lldp.soa().for_each_chunk([&](const auto& chunk) {
    auto tlv_type = chunk.template as<std::uint16_t>(2);
    auto tlv_length = chunk.template as<std::uint16_t>(3);
    auto subtype = chunk.template as<std::uint8_t>(4);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (tlv_type[i] == 1 && tlv_length[i] == 7 && subtype[i] == 4) found = true;
    }
  });
  CHECK(found);
}

}  // namespace

int main() {
  test_gptp_all_kinds();
  test_someip_default_ports();
  test_someip_tlv_opt_in();
  test_lldp_dpar_sample();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nano_shark_protocols3_tests: OK\n");
  return 0;
}
