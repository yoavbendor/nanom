// SPDX-License-Identifier: Apache-2.0
// Phase 3 tests: SOME/IP (header + SD entries/options + optional TLV members), gPTP (all 8
// message kinds + PATH_TRACE), and LLDP (reusing the already-tested dpar_sample.pcap fixture).

#include <nanom_shark/decode_pass.hpp>

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
  const char* testdata = NANOM_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/gptp_fixture.pcapng", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nanom_shark::AllTables tables;
  std::vector<nanom_shark::PacketJson> json_packets;
  nanom_shark::SinkHub sink{&json_packets};
  nanom_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nanom_shark::run_decode_pass(file, tables, sink, opts, error));
  CHECK(json_packets.size() == 9);  // 8 kinds + a second Announce (with PATH_TRACE)

  // All 9 gPTP tables populated (the 8 message kinds' 1-row-each, Announce x2, path_trace x3).
  CHECK(tables.get<"gptp_sync">().soa().rows() == 1);
  CHECK(tables.get<"gptp_delay_req">().soa().rows() == 1);
  CHECK(tables.get<"gptp_pdelay_req">().soa().rows() == 1);
  CHECK(tables.get<"gptp_pdelay_resp">().soa().rows() == 1);
  CHECK(tables.get<"gptp_follow_up">().soa().rows() == 1);
  CHECK(tables.get<"gptp_delay_resp">().soa().rows() == 1);
  CHECK(tables.get<"gptp_pdelay_resp_follow_up">().soa().rows() == 1);
  CHECK(tables.get<"gptp_announce">().soa().rows() == 2);
  CHECK(tables.get<"gptp_path_trace">().soa().rows() == 3);

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
  const char* testdata = NANOM_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/someip_fixture.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nanom_shark::AllTables tables;
  std::vector<nanom_shark::PacketJson> json_packets;
  nanom_shark::SinkHub sink{&json_packets};
  nanom_shark::DecodeOptions opts{};  // default someip_ports = {30490}; someip_tlv_ports empty

  std::string error;
  CHECK(nanom_shark::run_decode_pass(file, tables, sink, opts, error));

  // request, response, SD message all ride on port 30490 -> 3 SomeipNode rows; the 4th packet (a
  // TLV message on port 30509) is NOT on a configured port, so it must be invisible by default.
  CHECK(tables.get<"someip">().rows() == 3);
  CHECK(tables.get<"someip_tlv">().rows() == 0);

  // Exactly one SD message -> FindService + OfferService entries, one IPv4 endpoint option.
  CHECK(tables.get<"someip_sd_entry">().rows() == 2);
  CHECK(tables.get<"someip_sd_option">().rows() == 1);

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
  tables.get<"someip_sd_option">().soa().for_each_chunk([&](const auto& chunk) {
    auto l4 = chunk.template as<std::uint8_t>(4);   // packet_id,option_index,length,type,l4proto,...
    auto port = chunk.template as<std::uint16_t>(5);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (l4[i] == 17 && port[i] == 30509) found_option = true;
    }
  });
  CHECK(found_option);
}

void test_someip_tlv_opt_in() {
  const char* testdata = NANOM_SHARK_TESTDATA;
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(testdata) + "/someip_fixture.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nanom_shark::AllTables tables;
  std::vector<nanom_shark::PacketJson> json_packets;
  nanom_shark::SinkHub sink{&json_packets};
  nanom_shark::DecodeOptions opts{};
  opts.someip_ports.push_back(30509);
  opts.someip_tlv_ports.push_back(30509);

  std::string error;
  CHECK(nanom_shark::run_decode_pass(file, tables, sink, opts, error));

  CHECK(tables.get<"someip">().rows() == 4);       // now includes the TLV message
  CHECK(tables.get<"someip_tlv">().rows() == 2);   // its two TLV members

  bool saw_data_id_1 = false, saw_data_id_2 = false;
  tables.get<"someip_tlv">().soa().for_each_chunk([&](const auto& chunk) {
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
  std::vector<std::uint8_t> bytes;
  CHECK(read_file(std::string(NANOM_PARITY_TESTDATA) + "/dpar_sample.pcap", bytes));
  if (bytes.empty()) return;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());
  nanom_shark::AllTables tables;
  std::vector<nanom_shark::PacketJson> json_packets;
  nanom_shark::SinkHub sink{&json_packets};
  nanom_shark::DecodeOptions opts{};
  std::string error;

  CHECK(nanom_shark::run_decode_pass(file, tables, sink, opts, error));
  CHECK(tables.get<"lldp">().rows() > 0);

  // Cross-checked against nanotins_parity/testdata/lldp_sample.ndjson's first row (packet 0's
  // Chassis ID TLV: type 1, length 7, subtype 4).
  bool found = false;
  tables.get<"lldp">().soa().for_each_chunk([&](const auto& chunk) {
    auto tlv_type = chunk.template as<std::uint16_t>(2);
    auto tlv_length = chunk.template as<std::uint16_t>(3);
    auto subtype = chunk.template as<std::uint8_t>(4);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (tlv_type[i] == 1 && tlv_length[i] == 7 && subtype[i] == 4) found = true;
    }
  });
  CHECK(found);
}

// ---------------------------------------------------------------------------
// LLDP over a SEGMENTED payload: the seam-crossing differential test.
//
// lldp.hpp's Protocol::parse used to accept a nanom::seg_input, ignore it, and re-derive contiguous
// bytes from decode_ctx::eth_payload_bytes() before running the contiguous nm::many0 over those --
// so a genuinely segmented LLDPDU was silently parsed from the wrong bytes. It now walks the cursor
// it is handed with nm::many0_seg. These two tests pin that down: (1) an exhaustive split-point
// differential over lldp::walk, and (2) the protocol entry point itself, fed a segmented payload
// while decode_ctx carries a DECOY contiguous packet -- which the pre-fix code would have decoded
// instead.
// ---------------------------------------------------------------------------

void put_u16be(std::vector<std::uint8_t>& v, std::uint16_t x) {
  v.push_back(std::uint8_t(x >> 8));
  v.push_back(std::uint8_t(x));
}

// One LLDP TLV: [type:7][length:9] big-endian, then the value.
void append_tlv(std::vector<std::uint8_t>& out, std::uint16_t type,
                const std::vector<std::uint8_t>& value) {
  const std::uint16_t len = std::uint16_t(value.size());
  put_u16be(out, std::uint16_t((type << 9) | (len & 0x1FF)));
  out.insert(out.end(), value.begin(), value.end());
}

// A golden LLDPDU exercising every column decode_row() fills in: chassis/port id subtypes, TTL,
// a long value (40 bytes, past the 32-byte value_head snapshot), system capabilities, and a
// management address TLV -- then the End TLV that stops the walk.
std::vector<std::uint8_t> golden_lldpdu() {
  std::vector<std::uint8_t> p;
  append_tlv(p, 1, {4, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C});          // chassis id, subtype 4 (MAC)
  append_tlv(p, 2, {5, 'e', 't', 'h', '0'});                          // port id, subtype 5
  append_tlv(p, 3, {0x00, 0x78});                                     // TTL = 120
  std::vector<std::uint8_t> name(40);
  for (std::size_t i = 0; i < name.size(); ++i) name[i] = std::uint8_t('A' + (i % 26));
  append_tlv(p, 5, name);                                             // system name, 40 bytes
  append_tlv(p, 7, {0x00, 0x1C, 0x00, 0x14});                         // system capabilities
  append_tlv(p, 8, {5, 1, 10, 0, 0, 7, 2, 0x00, 0x00, 0x00, 0x2A, 0});  // management address
  append_tlv(p, 0, {});                                               // End of LLDPDU
  return p;
}

// A stand-in for the SoA table: lldp::walk only needs push().
struct RowSink {
  std::vector<nanom_shark::LldpTlvRow> rows;
  void push(const nanom_shark::LldpTlvRow& r) { rows.push_back(r); }
};

std::vector<std::string> walk_rows(nanom::seg_input in) {
  RowSink sink;
  nanom_shark::lldp::walk(in, /*pid=*/7, sink, nullptr);
  std::vector<std::string> out;
  for (const auto& r : sink.rows) out.push_back(nanom::to_json(r));
  return out;
}

void test_lldp_segmented_seam_parity() {
  const std::vector<std::uint8_t> pdu = golden_lldpdu();
  const auto* bytes = reinterpret_cast<const std::byte*>(pdu.data());
  const std::span<const std::byte> whole(bytes, pdu.size());

  // reference: the whole LLDPDU in one segment (the contiguous case the goldens already cover)
  const nanom::single_segment one{nanom::bytes(bytes, pdu.size())};
  const std::vector<std::string> want = walk_rows(nanom::from(one.view()));

  // not vacuous: the six real TLVs decoded, with the values built above
  CHECK(want.size() == 6);
  if (want.size() != 6) return;
  CHECK_CONTAINS(want[0], "\"tlv_type\":1");
  CHECK_CONTAINS(want[0], "\"subtype\":4");
  CHECK_CONTAINS(want[2], "\"ttl_seconds\":120");
  CHECK_CONTAINS(want[3], "\"tlv_length\":40");
  CHECK_CONTAINS(want[4], "\"caps_supported\":28");
  CHECK_CONTAINS(want[5], "\"mgmt_iface_number\":42");

  // ...and the identical rows come out for EVERY 2-way split of the same bytes: seams inside a
  // TLV header (cut 1), inside a short value (cut 5), inside the 40-byte value, and exactly on
  // TLV boundaries are all in this sweep.
  for (std::size_t cut = 0; cut <= pdu.size(); ++cut) {
    const std::array<std::span<const std::byte>, 2> parts{whole.subspan(0, cut),
                                                          whole.subspan(cut)};
    const nanom::segments segs{
        std::span<const std::span<const std::byte>>(parts.data(), parts.size())};
    const std::vector<std::string> got = walk_rows(nanom::from(segs));
    if (got != want) {
      std::printf("FAIL %s:%d: LLDP rows differ at split %zu (%zu rows vs %zu)\n", __FILE__,
                  __LINE__, cut, got.size(), want.size());
      ++failures;
      break;
    }
  }

  // one byte per segment: every TLV straddles seams, and the rows are still identical
  std::vector<std::span<const std::byte>> ones;
  for (std::size_t i = 0; i < pdu.size(); ++i) ones.emplace_back(bytes + i, 1);
  const nanom::segments s1{std::span<const std::span<const std::byte>>(ones.data(), ones.size())};
  CHECK(walk_rows(nanom::from(s1)) == want);
}

void test_lldp_protocol_entry_uses_its_cursor() {
  // The payload the protocol is HANDED: the golden LLDPDU, split across two disjoint buffers so it
  // cannot be reconstructed by pointer arithmetic (the seam falls inside the first TLV's value).
  const std::vector<std::uint8_t> pdu = golden_lldpdu();
  const std::size_t seam = 5;  // inside the chassis-id TLV's value
  const std::vector<std::uint8_t> lo(pdu.begin(), pdu.begin() + seam);
  const std::vector<std::uint8_t> hi(pdu.begin() + seam, pdu.end());
  const std::array<std::span<const std::byte>, 2> parts{
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(lo.data()), lo.size()),
      std::span<const std::byte>(reinterpret_cast<const std::byte*>(hi.data()), hi.size())};
  const nanom::segments segs{
      std::span<const std::span<const std::byte>>(parts.data(), parts.size())};

  // The DECOY the pre-fix code would have decoded instead: decode_ctx's contiguous packet, holding
  // a DIFFERENT LLDPDU (chassis subtype 9, TTL 99) behind a 14-byte Ethernet header.
  std::vector<std::uint8_t> decoy(14, 0x00);
  append_tlv(decoy, 1, {9, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01});
  append_tlv(decoy, 3, {0x00, 0x63});  // TTL = 99
  append_tlv(decoy, 0, {});

  nanom_shark::decode_ctx ctx{};
  ctx.packet_id = 3;
  ctx.ethertype = nanom_shark::lldp::kEtherTypeLldp;
  ctx.pkt = nanom::bytes(reinterpret_cast<const std::byte*>(decoy.data()), decoy.size());
  ctx.l2_end = 14;

  nanom_shark::tables_of<nanom_shark::decoder<nanom_shark::Lldp>> tables;
  nanom_shark::no_state state{};
  nanom_shark::Lldp::parse(ctx, nanom::from(segs), state, tables, nullptr);

  // Six TLVs from the SEGMENTED payload, not three from the decoy -- and their decoded values are
  // the segmented payload's (subtype 4, TTL 120), not the decoy's (subtype 9, TTL 99).
  CHECK(tables.get<"lldp">().rows() == 6);
  bool saw_real_chassis = false, saw_real_ttl = false, saw_decoy = false;
  tables.get<"lldp">().soa().for_each_chunk([&](const auto& chunk) {
    auto tlv_type = chunk.template as<std::uint16_t>(2);
    auto subtype = chunk.template as<std::uint8_t>(4);
    auto ttl = chunk.template as<std::uint16_t>(6);
    for (std::size_t i = 0; i < chunk.rows; ++i) {
      if (tlv_type[i] == 1 && subtype[i] == 4) saw_real_chassis = true;
      if (tlv_type[i] == 3 && ttl[i] == 120) saw_real_ttl = true;
      if ((tlv_type[i] == 1 && subtype[i] == 9) || (tlv_type[i] == 3 && ttl[i] == 99))
        saw_decoy = true;
    }
  });
  CHECK(saw_real_chassis);
  CHECK(saw_real_ttl);
  CHECK(!saw_decoy);
}

}  // namespace

int main() {
  test_gptp_all_kinds();
  test_someip_default_ports();
  test_someip_tlv_opt_in();
  test_lldp_dpar_sample();
  test_lldp_segmented_seam_parity();
  test_lldp_protocol_entry_uses_its_cursor();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nanom_shark_protocols3_tests: OK\n");
  return 0;
}
