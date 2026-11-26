// SPDX-License-Identifier: Apache-2.0
// nanom example (write side): craft an Ethernet / 802.1Q / IPv4 / UDP / SOME-IP notification,
// check it against bytes produced by an independent tool, patch it in place, and parse it back.
//
//   1. describe the headers once (NANOM_DESCRIBE): the same structs parse AND write;
//   2. computed fields (nm::computed<T>): IPv4 total length + header checksum, UDP length +
//      checksum over the RFC 768 pseudo-header (a custom emit context), SOME/IP length;
//   3. craft the frame inside-out with the nanom::craft combinators:
//        put_bytes(payload) | framed_by(someip) | framed_by(udp, ctx) | framed_by(ip) | ...
//   4. compare with golden bytes from scapy;
//   5. patch the IPv4 id and the SOME/IP session id through overlay_mut<T>, update both
//      checksums incrementally (RFC 1624, nm::inet::update16) and check that equals a full
//      recompute (mut_view::recompute) and the second scapy frame;
//   6. parse the frame back with nm::strct<T>() and verify_computed<T>().
// Built and run by ctest (example_craft_frame): an API change that breaks any step fails here.
#include <nanom/checksum.hpp>
#include <nanom/craft.hpp>
#include <nanom/nanom.hpp>

#include <cstdio>
#include <string_view>
#include <vector>

namespace nm = nanom;
namespace nc = nanom::craft;
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using bspan = std::span<const std::byte>;

// --- wire structs: field order and widths straight from the RFC / spec diagrams ---------------
struct eth_hdr {
  std::array<u8, 6> dst, src;
  nm::be<u16> eth_type;
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);

struct vlan_hdr {  // 802.1Q tag (the TPID 0x8100 is the Ethernet type before it)
  nm::ubits<3> pcp;
  nm::ubits<1> dei;
  nm::ubits<12> vid;
  nm::be<u16> eth_type;
};
NANOM_DESCRIBE(vlan_hdr, pcp, dei, vid, eth_type);

struct ipv4_hdr {
  nm::ubits<4> version;
  nm::ubits<4> ihl;
  nm::ubits<6> dscp;
  nm::ubits<2> ecn;
  nm::be<u16> total_len;
  nm::be<u16> ident;
  nm::ubits<3> flags;
  nm::ubits<13> frag_off;
  u8 ttl;
  u8 proto;
  nm::be<u16> checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4_hdr, version, ihl, dscp, ecn, total_len, ident, flags, frag_off, ttl, proto, checksum,
               src, dst);

struct udp_hdr {
  nm::be<u16> src_port, dst_port, length, checksum;
};
NANOM_DESCRIBE(udp_hdr, src_port, dst_port, length, checksum);

struct someip_hdr {  // AUTOSAR PRS_SOMEIPProtocol: 16 bytes, big-endian
  nm::be<u16> service_id, method_id;
  nm::be<u32> length;  // bytes after this field: request id (4) + 4 version/type bytes + payload
  nm::be<u16> client_id, session_id;
  u8 protocol_version, interface_version, message_type, return_code;
};
NANOM_DESCRIBE(someip_hdr, service_id, method_id, length, client_id, session_id, protocol_version,
               interface_version, message_type, return_code);

// --- computed fields ----------------------------------------------------------------------
// The UDP checksum covers a pseudo-header (IPv4 src, dst, protocol, UDP length) that the UDP
// header itself does not carry, so the UDP fields get a custom context. nanom fills `payload`
// (the bytes after the header) when crafting; the addresses are ours.
struct udp_v4_ctx {
  bspan payload{};
  std::array<u8, 4> src{}, dst{};
};

template <>
struct nm::computed<ipv4_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"total_len">([](const ipv4_hdr&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      // runs over the encoded header with `checksum` zeroed
      nm::checksum<"checksum">([](bspan hdr, const nm::emit_ctx&) { return nm::inet::checksum(hdr); }),
  };
};
template <>
struct nm::computed<udp_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"length">([](const udp_hdr&, const udp_v4_ctx& c) { return 8 + c.payload.size(); }),
      nm::checksum<"checksum">([](bspan hdr, const udp_v4_ctx& c) {
        const auto ph = nm::inet::pseudo_header_v4(c.src, c.dst, 17, u16(hdr.size() + c.payload.size()));
        return nm::inet::udp_checksum({ph, hdr, c.payload});  // a computed 0 is sent as 0xFFFF
      }),
  };
};
template <>
struct nm::computed<someip_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"length">([](const someip_hdr&, const nm::emit_ctx& c) { return 8 + c.payload.size(); })};
};

// A header without computed fields or narrow bit fields encodes infallibly at compile time.
static_assert(nm::to_bytes_exact(eth_hdr{{2, 0, 0, 0, 0, 2}, {2, 0, 0, 0, 0, 1}, 0x8100})[12] == std::byte{0x81});
static_assert(nm::wire_size_v<someip_hdr> == 16 && nm::wire_size_v<ipv4_hdr> == 20);

static int failures = 0;
#define CHECK(c)                                                    \
  do {                                                              \
    if (!(c)) {                                                     \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);      \
      ++failures;                                                   \
    }                                                               \
  } while (0)

static std::vector<std::byte> unhex(std::string_view h) {
  std::vector<std::byte> v;
  auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) v.push_back(std::byte(nib(h[i]) << 4 | nib(h[i + 1])));
  return v;
}

// Golden frames, produced once with scapy 2.8.0 (scapy.contrib.automotive.someip):
//   Ether(dst="02:00:00:00:00:02", src="02:00:00:00:00:01") / Dot1Q(prio=3, vlan=100)
//   / IP(id=ID, flags="DF", ttl=64, src="10.0.0.1", dst="10.0.0.2") / UDP(sport=30501, dport=30509)
//   / SOMEIP(srv_id=0x1234, sub_id=0x8001, client_id=1, session_id=S, proto_ver=1, iface_ver=1,
//            msg_type=SOMEIP.TYPE_NOTIFICATION) / Raw(bytes.fromhex("deadbeef0102030405"))
// with (ID, S) = (0x1c46, 1) and (0x1c47, 2); bytes(pkt).hex().
static constexpr std::string_view kGolden1 =
    "020000000002020000000001810060640800450000351c46400040110a700a0000010a0000027725772d0021c169"
    "12348001000000110001000101010200deadbeef0102030405";
static constexpr std::string_view kGolden2 =
    "020000000002020000000001810060640800450000351c47400040110a6f0a0000010a0000027725772d0021c168"
    "12348001000000110001000201010200deadbeef0102030405";
constexpr std::size_t kIp = 14 + 4, kUdp = kIp + 20, kSomeip = kUdp + 8, kPayload = kSomeip + 16;

int main() {
  const std::array<u8, 4> src_ip{10, 0, 0, 1}, dst_ip{10, 0, 0, 2};
  const auto payload = unhex("deadbeef0102030405");

  // 1. the header values; computed fields (lengths, checksums) are left zero ------------------
  const eth_hdr eth{{2, 0, 0, 0, 0, 2}, {2, 0, 0, 0, 0, 1}, 0x8100};
  const vlan_hdr vlan{.pcp = 3, .dei = 0, .vid = 100, .eth_type = 0x0800};
  ipv4_hdr ip{};
  ip.version = 4;
  ip.ihl = 5;
  ip.ident = 0x1c46;
  ip.flags = 2;  // DF
  ip.ttl = 64;
  ip.proto = 17;
  ip.src = src_ip;
  ip.dst = dst_ip;
  const udp_hdr udp{.src_port = 30501, .dst_port = 30509, .length = 0, .checksum = 0};
  someip_hdr sip{};
  sip.service_id = 0x1234;
  sip.method_id = 0x8001;  // event 0x8001
  sip.client_id = 1;
  sip.session_id = 1;
  sip.protocol_version = 1;
  sip.interface_version = 1;
  sip.message_type = 0x02;  // NOTIFICATION

  // 2. craft inside-out: each framed_by() reserves its header, writes the body, then back-patches
  //    the header with the body as its context payload (lengths, checksums) -----------------------
  auto frame = nc::put_bytes(bspan(payload))  //
               | nc::framed_by(sip)           //
               | nc::framed_by(udp, udp_v4_ctx{{}, src_ip, dst_ip}) | nc::framed_by(ip) | nc::framed_by(vlan) |
               nc::framed_by(eth);
  auto size = nc::size_of(frame);
  CHECK(size && *size == kPayload + payload.size());  // exact size without writing

  std::array<std::byte, 128> buf{};
  nm::span_sink sink{buf};  // fixed buffer: overflow is an error, never a write past the end
  auto n = nc::write(frame, sink);
  CHECK(n && *n == 71 && sink.used == 71);
  const std::span<std::byte> wire = sink.written();

  // 3. byte-for-byte equal to scapy ------------------------------------------------------------
  const auto golden1 = unhex(kGolden1), golden2 = unhex(kGolden2);
  CHECK(std::ranges::equal(wire, golden1));
  auto vec = nc::to_vector(frame);  // the same crafter into a growable vector
  CHECK(vec && std::ranges::equal(*vec, golden1));

  // One header on its own: emit() into a buffer, emit_frame() header + payload into a sink.
  std::array<std::byte, 16> sip_only{};
  const auto one = nm::emit(sip, sip_only, nm::emit_ctx{payload});
  CHECK(one && *one == 16);
  CHECK(std::ranges::equal(sip_only, wire.subspan(kSomeip, 16)));
  std::vector<std::byte> sip_frame;
  nm::vector_sink vs{&sip_frame};
  const auto framed = nm::emit_frame(sip, payload, vs);
  CHECK(framed && *framed == 16 + payload.size());
  CHECK(std::ranges::equal(sip_frame, wire.subspan(kSomeip)));

  // 4. patch in place: the next notification (IPv4 id + 1, SOME/IP session + 1) -----------------
  std::vector<std::byte> next(wire.begin(), wire.end());
  const std::span<std::byte> nx(next);
  auto ipm = nm::overlay_mut<ipv4_hdr>(nx.subspan(kIp));
  auto udpm = nm::overlay_mut<udp_hdr>(nx.subspan(kUdp));
  auto sipm = nm::overlay_mut<someip_hdr>(nx.subspan(kSomeip));
  CHECK(ipm && udpm && sipm);
  if (ipm && udpm && sipm) {
    const u16 old_id = ipm->get<"ident">(), old_session = sipm->get<"session_id">();
    const u16 ip_csum = ipm->get<"checksum">(), udp_csum = udpm->get<"checksum">();
    CHECK(ipm->set<"ident">(old_id + 1));
    CHECK(sipm->set<"session_id">(old_session + 1));
    // RFC 1624: the IPv4 checksum covers the id word; the UDP checksum covers the session id
    // (an even offset in the UDP payload). Three additions each, no pass over the bytes.
    CHECK(ipm->set<"checksum">(nm::inet::update16(ip_csum, old_id, u16(old_id + 1))));
    CHECK(udpm->set<"checksum">(nm::inet::update16(udp_csum, old_session, u16(old_session + 1))));
    CHECK(std::ranges::equal(next, golden2));

    // the incremental result equals a full recompute of every computed field
    std::vector<std::byte> full = next;
    const std::span<std::byte> fs(full);
    auto ipf = nm::overlay_mut<ipv4_hdr>(fs.subspan(kIp));
    auto udpf = nm::overlay_mut<udp_hdr>(fs.subspan(kUdp));
    CHECK(ipf && ipf->set<"checksum">(0) && ipf->recompute(nm::emit_ctx{bspan(fs.subspan(kUdp))}));
    CHECK(udpf && udpf->set<"checksum">(0) &&
          udpf->recompute(udp_v4_ctx{bspan(fs.subspan(kSomeip)), src_ip, dst_ip}));
    CHECK(full == next);
  }
  // out of range values are refused, nothing is written
  CHECK(!nm::overlay_mut<vlan_hdr>(nx.subspan(14))->set<"vid">(4096));
  CHECK(!nm::overlay_mut<ipv4_hdr>(nx.subspan(kIp, 19)));  // buffer smaller than the struct

  // 5. parse it back with the same structs ------------------------------------------------------
  nm::cursor cur{nm::from(bspan(next))};
  const auto p_eth = cur.next(nm::strct<eth_hdr>());
  const auto p_vlan = cur.next(nm::strct<vlan_hdr>());
  const bspan ip_bytes = cur.rest().span();
  const auto p_ip = cur.next(nm::strct<ipv4_hdr>());
  const bspan udp_bytes = cur.rest().span();
  const auto p_udp = cur.next(nm::strct<udp_hdr>());
  const bspan sip_bytes = cur.rest().span();
  const auto p_sip = cur.next(nm::strct<someip_hdr>());
  const auto p_payload = cur.take(payload.size());
  CHECK(cur && cur.empty());
  CHECK(p_eth.eth_type == 0x8100 && p_eth.src[5] == 1);
  CHECK(p_vlan.pcp == 3 && p_vlan.vid == 100 && p_vlan.eth_type == 0x0800);
  CHECK(p_ip.version == 4 && p_ip.ihl == 5 && p_ip.flags == 2 && p_ip.ident == 0x1c47);
  CHECK(p_ip.total_len == 20 + 8 + 16 + payload.size() && p_ip.ttl == 64 && p_ip.dst == dst_ip);
  CHECK(p_udp.src_port == 30501 && p_udp.dst_port == 30509 && p_udp.length == 8 + 16 + payload.size());
  CHECK(p_sip.service_id == 0x1234 && p_sip.method_id == 0x8001 && p_sip.length == 8 + payload.size());
  CHECK(p_sip.session_id == 2 && p_sip.message_type == 0x02);
  CHECK(std::ranges::equal(p_payload, payload));
  // the receiver's checks: stored computed fields match what writing would compute
  CHECK(nm::verify_computed<ipv4_hdr>(ip_bytes.first(20), nm::emit_ctx{ip_bytes.subspan(20)}));
  CHECK(nm::verify_computed<udp_hdr>(udp_bytes.first(8), udp_v4_ctx{udp_bytes.subspan(8), src_ip, dst_ip}));
  CHECK(nm::verify_computed<someip_hdr>(sip_bytes.first(16), nm::emit_ctx{sip_bytes.subspan(16)}));
  CHECK(nm::inet::verify(ip_bytes.first(20)));
  next[kPayload] ^= std::byte{1};  // a flipped payload bit breaks the UDP checksum
  CHECK(!nm::verify_computed<udp_hdr>(udp_bytes.first(8), udp_v4_ctx{udp_bytes.subspan(8), src_ip, dst_ip}));

  if (failures) return std::printf("%d failure(s)\n", failures), 1;
  std::printf("craft_frame: %zu-byte frame matches scapy; patch + parse checks passed\n", wire.size());
  return 0;
}
