// SPDX-License-Identifier: Apache-2.0
//
// THE PHASE 2 ACCEPTANCE TEST: adding a protocol to nanom_shark is ONE new file and ZERO edits to
// any library header.
//
// Everything needed to teach nanom_shark a brand-new protocol -- its wire struct, its trigger, its
// output table, its parse function, and its registration -- is in THIS FILE. Nothing under
// include/nanom_shark/ was touched to make it work: no new entry in a table struct, no new branch
// in a dispatch function, no new line in the Avro sink, no new option field. Before Phase 2 the
// same protocol cost ~8 edit points across 5 library headers (decode_options.hpp, l2l3_nodes.hpp,
// l4_dispatch.hpp, decode_pass.hpp, avro_dump.hpp) plus 2 new files.
//
// It also proves the OTHER Phase 2 claim -- that there is exactly ONE dispatch path -- by feeding
// FooProto the same message twice: once as a plain UDP packet, and once split across two IPv4
// fragments so that the Foo header itself STRADDLES the fragment seam. A protocol author writes no
// reassembly-aware code whatsoever; the reassembled datagram arrives through the same
// `dispatch<layer::l4_payload>` as the normal packet, as a zero-copy segmented input.

#include <nanom_shark/decode_pass.hpp>  // the library, exactly as shipped

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

// ===========================================================================
// ---- BEGIN: everything a user writes to add a protocol --------------------
// ===========================================================================

namespace foo {

// 1. The wire struct, described the ordinary nanom way. 12 bytes on the wire.
struct FooHeader {
  nanom::be<std::uint32_t> id;
  nanom::be<std::uint16_t> len;
  nanom::be<std::uint32_t> flags;  // deliberately lands ACROSS the fragment seam below
  nanom::be<std::uint16_t> tag;
};

}  // namespace foo

NANOM_DESCRIBE(foo::FooHeader, id, len, flags, tag);

namespace foo {

// 2. The row: reuse nanom_shark's Node<> envelope so the wire struct's own fields flatten into
//    "body.<field>" columns -- no field is retyped.
using FooNode = nanom_shark::Node<FooHeader>;

// 3. The protocol.
struct FooProto {
  using trigger = nanom_shark::udp_port<1234>;  // compile-time constant -> a plain `==` chain
  using state   = nanom_shark::no_state;        // stateless

  static constexpr auto tables = nanom_shark::table_spec<nanom_shark::table_decl<"foo", FooNode>>{};

  static void parse(const nanom_shark::decode_ctx& c, nanom::seg_input in, state&, auto& t,
                    nanom_shark::PacketJson* json) {
    // strct_seg windows across segment seams itself, so this one line works for a contiguous UDP
    // payload and for a reassembled datagram alike.
    auto r = nanom::strct_seg<FooHeader>()(in);
    if (!r) return;
    t.template get<"foo">().push(
        FooNode{c.packet_id, c.datagram_id, c.is_reassembled, r->value});
    if (json) json->add_layer("foo", r->value);
  }
};

}  // namespace foo

// 4. Registration: the type list IS the registry.
using foo_decoder = nanom_shark::decoder<nanom_shark::CoreL2L3, nanom_shark::Someip,
                                         nanom_shark::Gptp, nanom_shark::Lldp, foo::FooProto>;

// ...and a decoder that registers ONLY the core walk plus FooProto, to show the type list really is
// the whole registry: this build has no SOME/IP, gPTP or LLDP tables at all.
using lean_decoder = nanom_shark::decoder<nanom_shark::CoreL2L3, foo::FooProto>;

// ===========================================================================
// ---- END: everything a user writes ----------------------------------------
// ===========================================================================

namespace {

int failures = 0;
#define CHECK(cond)                                                \
  do {                                                             \
    if (!(cond)) {                                                 \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
      ++failures;                                                  \
    }                                                              \
  } while (0)

// ---- a minimal classic-pcap builder, so this test needs no fixture file ----

void put_u16be(std::vector<std::uint8_t>& v, std::uint16_t x) {
  v.push_back(std::uint8_t(x >> 8));
  v.push_back(std::uint8_t(x));
}
void put_u32be(std::vector<std::uint8_t>& v, std::uint32_t x) {
  v.push_back(std::uint8_t(x >> 24));
  v.push_back(std::uint8_t(x >> 16));
  v.push_back(std::uint8_t(x >> 8));
  v.push_back(std::uint8_t(x));
}
void put_u32le(std::vector<std::uint8_t>& v, std::uint32_t x) {
  v.push_back(std::uint8_t(x));
  v.push_back(std::uint8_t(x >> 8));
  v.push_back(std::uint8_t(x >> 16));
  v.push_back(std::uint8_t(x >> 24));
}

std::vector<std::uint8_t> pcap_header() {
  std::vector<std::uint8_t> v;
  put_u32le(v, 0xa1b2c3d4);  // magic, microsecond resolution, host (little) endian
  v.push_back(2); v.push_back(0);   // version_major 2
  v.push_back(4); v.push_back(0);   // version_minor 4
  put_u32le(v, 0);                  // thiszone
  put_u32le(v, 0);                  // sigfigs
  put_u32le(v, 65535);              // snaplen
  put_u32le(v, 1);                  // network = LINKTYPE_ETHERNET
  return v;
}

void append_record(std::vector<std::uint8_t>& out, std::uint32_t ts_sec,
                   const std::vector<std::uint8_t>& pkt) {
  put_u32le(out, ts_sec);
  put_u32le(out, 0);
  put_u32le(out, std::uint32_t(pkt.size()));
  put_u32le(out, std::uint32_t(pkt.size()));
  out.insert(out.end(), pkt.begin(), pkt.end());
}

std::vector<std::uint8_t> ethernet_ipv4(std::uint16_t ident, std::uint16_t frag_off_units,
                                        bool more_fragments,
                                        const std::vector<std::uint8_t>& l3_payload) {
  std::vector<std::uint8_t> p;
  for (int i = 0; i < 6; ++i) p.push_back(std::uint8_t(0x02));  // dst MAC
  for (int i = 0; i < 6; ++i) p.push_back(std::uint8_t(0x04));  // src MAC
  put_u16be(p, 0x0800);                                          // ethertype IPv4

  p.push_back(0x45);                                             // version 4, ihl 5
  p.push_back(0x00);                                             // tos
  put_u16be(p, std::uint16_t(20 + l3_payload.size()));           // total_length
  put_u16be(p, ident);
  put_u16be(p, std::uint16_t((more_fragments ? 0x2000 : 0) | frag_off_units));
  p.push_back(64);                                               // ttl
  p.push_back(17);                                               // protocol = UDP
  put_u16be(p, 0);                                               // header checksum (unchecked)
  put_u32be(p, 0x0a000001);                                      // src 10.0.0.1
  put_u32be(p, 0x0a000002);                                      // dst 10.0.0.2
  p.insert(p.end(), l3_payload.begin(), l3_payload.end());
  return p;
}

// UDP header (dst port 1234, FooProto's trigger) + a 12-byte Foo message + 4 bytes of trailer.
std::vector<std::uint8_t> udp_with_foo(std::uint32_t foo_id, std::uint16_t foo_len) {
  std::vector<std::uint8_t> body;
  put_u32be(body, foo_id);
  put_u16be(body, foo_len);
  put_u32be(body, 0xBEEFCAFE);  // flags -- occupies datagram bytes 14..17, i.e. across the seam
  put_u16be(body, 0xC0FF);      // tag
  for (int i = 0; i < 4; ++i) body.push_back(0xAA);  // trailer, ignored by FooProto

  std::vector<std::uint8_t> u;
  put_u16be(u, 40000);                                  // src port
  put_u16be(u, 1234);                                   // dst port -> FooProto's trigger
  put_u16be(u, std::uint16_t(8 + body.size()));         // length (header + body)
  put_u16be(u, 0);                                      // checksum (unchecked)
  u.insert(u.end(), body.begin(), body.end());
  return u;
}

nanom::bytes as_bytes(const std::vector<std::uint8_t>& v) {
  return nanom::bytes(reinterpret_cast<const std::byte*>(v.data()), v.size());
}

// ---------------------------------------------------------------------------

// Packet 0: a plain UDP/1234 packet carrying one Foo message.
// Packets 1+2: the SAME UDP datagram, split into two IPv4 fragments at datagram offset 16. The Foo
//              header occupies datagram bytes 8..19, and its `flags` field bytes 14..17 -- so the
//              seam falls INSIDE a field, and the reassembled parse must window across it.
std::vector<std::uint8_t> build_capture() {
  std::vector<std::uint8_t> file = pcap_header();

  append_record(file, 1, ethernet_ipv4(0x1000, 0, false, udp_with_foo(0x11223344, 0x0102)));

  const std::vector<std::uint8_t> datagram = udp_with_foo(0x55667788, 0x0304);
  const std::vector<std::uint8_t> frag_a(datagram.begin(), datagram.begin() + 16);
  const std::vector<std::uint8_t> frag_b(datagram.begin() + 16, datagram.end());
  append_record(file, 2, ethernet_ipv4(0x2000, 0, /*more_fragments=*/true, frag_a));
  append_record(file, 3, ethernet_ipv4(0x2000, 16 / 8, /*more_fragments=*/false, frag_b));

  return file;
}

// The FooProto rows, read back out of the columnar table.
struct FooSeen {
  std::uint64_t packet_id;
  std::uint32_t datagram_id;
  bool          is_reassembled;
  std::uint32_t id;
  std::uint16_t len;
  std::uint32_t flags;
  std::uint16_t tag;
};

template <class Table>
std::vector<FooSeen> read_foo(const Table& t) {
  std::vector<FooSeen> out;
  // Node<FooHeader> flattens to: packet_id, datagram_id, is_reassembled, body.id, body.len,
  // body.flags, body.tag -- the wire struct's own fields, never retyped.
  t.soa().for_each_chunk([&](const auto& c) {
    auto pid   = c.template as<std::uint64_t>(0);
    auto dgid  = c.template as<std::uint32_t>(1);
    auto reasm = c.template as<bool>(2);
    auto id    = c.template as<std::uint32_t>(3);
    auto len   = c.template as<std::uint16_t>(4);
    auto flags = c.template as<std::uint32_t>(5);
    auto tag   = c.template as<std::uint16_t>(6);
    for (std::size_t i = 0; i < c.rows; ++i) {
      out.push_back(FooSeen{pid[i], dgid[i], reasm[i], id[i], len[i], flags[i], tag[i]});
    }
  });
  return out;
}

void test_new_protocol_in_one_file() {
  const std::vector<std::uint8_t> capture = build_capture();

  nanom_shark::tables_of<foo_decoder>  tables;   // <- the ONLY change at the call site
  std::vector<nanom_shark::PacketJson> json_packets;
  nanom_shark::SinkHub                 sink{&json_packets};
  nanom_shark::DecodeOptions           opts{};
  std::string                          error;

  CHECK(nanom_shark::run_decode_pass(as_bytes(capture), tables, sink, opts, error));
  CHECK(json_packets.size() == 3);

  // The core L2/L3/L4 walk still tabulates exactly as it does for the builtin decoder...
  CHECK(tables.get<"eth">().rows() == 3);
  CHECK(tables.get<"ipv4">().rows() == 3);
  CHECK(tables.get<"packets">().rows() == 3);
  // ...one normal UDP row, plus one from the completed reassembly.
  CHECK(tables.get<"udp">().rows() == 2);
  CHECK(tables.get<"datagram">().rows() == 1);
  CHECK(tables.get<"ipv4_frag">().rows() == 2);

  // ...and FooProto tabulated BOTH messages: the plain packet and the reassembled datagram, the
  // latter parsed straight across the fragment seam with no reassembly-aware code in FooProto.
  const std::vector<FooSeen> seen = read_foo(tables.get<"foo">());
  CHECK(seen.size() == 2);
  if (seen.size() != 2) return;

  CHECK(seen[0].packet_id == 0);
  CHECK(seen[0].is_reassembled == false);
  CHECK(seen[0].datagram_id == 0);
  CHECK(seen[0].id == 0x11223344u);
  CHECK(seen[0].len == 0x0102u);
  CHECK(seen[0].flags == 0xBEEFCAFEu);
  CHECK(seen[0].tag == 0xC0FFu);

  CHECK(seen[1].packet_id == 2);           // the packet that COMPLETED the reassembly
  CHECK(seen[1].is_reassembled == true);   // came in through defrag's re-entry...
  CHECK(seen[1].datagram_id != 0);
  CHECK(seen[1].id == 0x55667788u);        // ...and the 12-byte header still decoded correctly
  CHECK(seen[1].len == 0x0304u);           //    even though it straddles the fragment boundary
  CHECK(seen[1].flags == 0xBEEFCAFEu);  // this 4-byte field spans BOTH fragments
  CHECK(seen[1].tag == 0xC0FFu);

  // The JSON sink picked the new layer up with no edit either -- it renders whatever the protocol
  // hands PacketJson.
  CHECK(json_packets[0].to_json().find("\"foo\":") != std::string::npos);
  CHECK(json_packets[2].to_json().find("\"foo\":") != std::string::npos);

  // ...and so does the Avro sink: for_each_table walks the tables the type list declared, so
  // "foo" is in the enumeration without avro_dump.hpp knowing it exists.
  bool saw_foo_table = false, saw_eth_table = false;
  tables.for_each_table([&](std::string_view name, const auto&) {
    if (name == "foo") saw_foo_table = true;
    if (name == "eth") saw_eth_table = true;
  });
  CHECK(saw_foo_table);
  CHECK(saw_eth_table);
}

// The type list is the WHOLE registry: a decoder that does not register SOME/IP, gPTP or LLDP has
// no such tables and never runs their triggers, from the same unmodified library headers.
void test_lean_decoder() {
  const std::vector<std::uint8_t> capture = build_capture();

  nanom_shark::tables_of<lean_decoder> tables;
  nanom_shark::SinkHub                 sink{};
  nanom_shark::DecodeOptions           opts{};
  std::string                          error;

  CHECK(nanom_shark::run_decode_pass(as_bytes(capture), tables, sink, opts, error));
  CHECK(tables.get<"foo">().rows() == 2);

  // CoreL2L3 declares 10 tables, FooProto one; SOME/IP's 4, gPTP's 9 and LLDP's 1 are simply absent.
  CHECK(decltype(tables)::table_count == 11);

  std::size_t counted = 0;
  tables.for_each_table([&](std::string_view, const auto&) { ++counted; });
  CHECK(counted == 11);
}

}  // namespace

int main() {
  test_new_protocol_in_one_file();
  test_lean_decoder();
  if (failures == 0) std::printf("nanom_shark ergonomics tests: all passed\n");
  return failures == 0 ? 0 : 1;
}
