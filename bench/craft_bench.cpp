// SPDX-License-Identifier: Apache-2.0
//
// Crafting Eth + VLAN + IPv4 + UDP + SOME/IP notification frames (94 bytes), six ways:
//
//   A  emit<> per layer   nanom::emit of each described header, inside-out into headroom, with
//                         computed fields (IPv4 total length + header checksum via
//                         nanom::inet::checksum, UDP length, SOME/IP length)
//   B  template + full    a prebuilt frame copied and patched (IPv4 id, SOME/IP session, payload),
//      checksum           IPv4 header checksum recomputed over the 20 header bytes
//   C  template + RFC1624 the same, but the checksum patched incrementally (inet::update16) from
//                         the template's -- no pass over the header at all
//   D  C into a capture   C plus a pcap record header, appended into one output buffer
//   E  nanom::craft       put_bytes(payload) | framed_by(someip) | framed_by(udp) | framed_by(ipv4)
//                         | framed_by(vlan) | framed_by(eth), written into a span_sink
//   F  mut_view patch     the template copied, then patched through overlay_mut<Ipv4> /
//                         overlay_mut<SomeipHeader> (set<"identification">, set<"session_id">) and
//                         the IPv4 computed fields re-derived with recompute()
//
// Every variant must produce byte-identical frames (an FNV-1a hash over all of them is compared).
//
// usage: nm_craft_bench [frames=2000000] [reps=5]
#include <nanom/checksum.hpp>
#include <nanom/craft.hpp>
#include <nanom/emit.hpp>
#include <nanom_shark/nanom_shark.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace nm = nanom;
using namespace nmproto;
using SH = nanom_shark::SomeipHeader;
using clk = std::chrono::steady_clock;
using bspan = std::span<const std::byte>;

template <>
struct nm::computed<Ipv4> {
  static constexpr auto fields = std::tuple{
      nm::calc<"total_length">([](const Ipv4&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      nm::checksum<"checksum">([](bspan h, const nm::emit_ctx&) { return nm::inet::checksum(h); })};
};
template <>
struct nm::computed<Udp> {
  static constexpr auto fields =
      std::tuple{nm::calc<"length">([](const Udp&, const nm::emit_ctx& c) { return 8 + c.payload.size(); })};
};
template <>
struct nm::computed<SH> {
  static constexpr auto fields =
      std::tuple{nm::calc<"length">([](const SH&, const nm::emit_ctx& c) { return 8 + c.payload.size(); })};
};

namespace {
constexpr std::size_t kPay = 32, kFrame = 14 + 4 + 20 + 8 + 16 + kPay;  // 94
constexpr std::size_t kIp = 18, kSomeip = 46;                            // header offsets
double secs(clk::time_point a) { return std::chrono::duration<double>(clk::now() - a).count(); }
std::uint64_t fnv(const std::byte* p, std::size_t n, std::uint64_t h) {
  for (std::size_t i = 0; i < n; ++i) h = (h ^ std::uint8_t(p[i])) * 1099511628211ull;
  return h;
}
constexpr std::uint64_t kFnv0 = 1469598103934665603ull;
inline void put16(std::byte* p, std::uint16_t v) {
  p[0] = std::byte(v >> 8);
  p[1] = std::byte(v);
}

// A: build one frame ending at `end` with nanom::emit, returns its first byte
std::byte* emit_frame(std::byte* end, int i, const std::byte* pay) {
  std::byte* p = end - kPay;
  std::memcpy(p, pay, kPay);
  SH sh{};
  sh.service_id = 0x1234;
  sh.method_id = 0x8001;
  sh.client_id = 1;
  sh.session_id = std::uint16_t(i);
  sh.protocol_version = 1;
  sh.interface_version = 1;
  sh.message_type = 2;
  p -= 16;
  (void)nm::emit(sh, {p, 16}, nm::emit_ctx{{p + 16, kPay}});
  Udp u{};
  u.src_port = 30501;
  u.dst_port = 30501;
  p -= 8;
  (void)nm::emit(u, {p, 8}, nm::emit_ctx{{p + 8, std::size_t(end - p - 8)}});
  Ipv4 ip{};
  ip.version = 4;  // ubits are assignable from integers
  ip.ihl = 5;
  ip.identification = std::uint16_t(i);
  ip.ttl = 64;
  ip.protocol = 17;
  ip.src = {10, 0, 0, 1};
  ip.dst = {10, 0, 0, 2};
  p -= 20;
  (void)nm::emit(ip, {p, 20}, nm::emit_ctx{{p + 20, std::size_t(end - p - 20)}});
  VlanTag v{};
  v.pcp = 3;
  v.vid = 100;
  v.inner_ethertype = 0x0800;
  p -= 4;
  (void)nm::emit(v, {p, 4});
  Ethernet e{};
  e.dst = {1, 0x80, 0xc2, 0, 0, 1};
  e.src = {2, 0, 0, 0, 0xaa, 1};
  e.ethertype = 0x8100;
  p -= 14;
  (void)nm::emit(e, {p, 14});
  return p;
}
}  // namespace

int main(int argc, char** argv) {
  const int N = argc > 1 ? std::max(1, std::atoi(argv[1])) : 2'000'000;
  const int reps = argc > 2 ? std::max(1, std::atoi(argv[2])) : 5;
  std::byte pay[kPay];

  // ---- A: emit<> per layer
  std::vector<std::byte> buf(256);
  std::uint64_t ha = kFnv0;
  double best = 1e30;
  for (int rep = 0; rep < reps; ++rep) {
    const auto t0 = clk::now();
    for (int i = 0; i < N; ++i) {
      std::memset(pay, i & 0xff, kPay);
      const std::byte* p = emit_frame(buf.data() + buf.size(), i, pay);
      if (rep == 0) ha = fnv(p, kFrame, ha);
    }
    best = std::min(best, secs(t0));
  }
  std::printf("A emit<> per layer            %6.1f ns/frame\n", best * 1e9 / N);

  // the template: the frame for i = 0, payload zero
  std::array<std::byte, kFrame> tmpl{};
  {
    std::byte zero[kPay] = {};
    std::memcpy(tmpl.data(), emit_frame(buf.data() + buf.size(), 0, zero), kFrame);
  }
  const std::uint16_t tmpl_csum = std::uint16_t(std::uint8_t(tmpl[kIp + 10]) << 8 | std::uint8_t(tmpl[kIp + 11]));

  // ---- B: template patch, full IPv4 header checksum
  std::array<std::byte, kFrame> fr{};
  std::uint64_t hb = kFnv0;
  best = 1e30;
  for (int rep = 0; rep < reps; ++rep) {
    const auto t0 = clk::now();
    for (int i = 0; i < N; ++i) {
      std::memcpy(fr.data(), tmpl.data(), kFrame);
      std::memset(fr.data() + kFrame - kPay, i & 0xff, kPay);
      const std::uint16_t s = std::uint16_t(i);
      put16(fr.data() + kIp + 4, s);  // identification
      put16(fr.data() + kIp + 10, 0);
      put16(fr.data() + kIp + 10, nm::inet::checksum(bspan(fr.data() + kIp, 20)));
      put16(fr.data() + kSomeip + 10, s);  // session id
      if (rep == 0) hb = fnv(fr.data(), kFrame, hb);
    }
    best = std::min(best, secs(t0));
  }
  std::printf("B template + full checksum    %6.1f ns/frame   identical to A: %s\n", best * 1e9 / N,
              ha == hb ? "yes" : "NO");

  // ---- C: template patch, RFC 1624 incremental checksum
  std::uint64_t hc = kFnv0;
  best = 1e30;
  for (int rep = 0; rep < reps; ++rep) {
    const auto t0 = clk::now();
    for (int i = 0; i < N; ++i) {
      std::memcpy(fr.data(), tmpl.data(), kFrame);
      std::memset(fr.data() + kFrame - kPay, i & 0xff, kPay);
      const std::uint16_t s = std::uint16_t(i);
      put16(fr.data() + kIp + 4, s);
      put16(fr.data() + kIp + 10, nm::inet::update16(tmpl_csum, 0, s));  // template id was 0
      put16(fr.data() + kSomeip + 10, s);
      if (rep == 0) hc = fnv(fr.data(), kFrame, hc);
    }
    best = std::min(best, secs(t0));
  }
  std::printf("C template + RFC 1624 update  %6.1f ns/frame   identical to A: %s\n", best * 1e9 / N,
              ha == hc ? "yes" : "NO");

  // ---- D: C plus a pcap record header, into one output buffer
  std::vector<std::byte> out(std::size_t(N) * (16 + kFrame));
  best = 1e30;
  for (int rep = 0; rep < reps; ++rep) {
    const auto t0 = clk::now();
    std::byte* w = out.data();
    for (int i = 0; i < N; ++i) {
      const std::uint32_t rec[4] = {std::uint32_t(i / 1000), std::uint32_t(i % 1000), std::uint32_t(kFrame),
                                    std::uint32_t(kFrame)};
      std::memcpy(w, rec, 16);
      std::byte* f = w + 16;
      std::memcpy(f, tmpl.data(), kFrame);
      std::memset(f + kFrame - kPay, i & 0xff, kPay);
      const std::uint16_t s = std::uint16_t(i);
      put16(f + kIp + 4, s);
      put16(f + kIp + 10, nm::inet::update16(tmpl_csum, 0, s));
      put16(f + kSomeip + 10, s);
      w += 16 + kFrame;
    }
    best = std::min(best, secs(t0));
  }
  std::uint64_t hd = kFnv0;
  for (int i = 0; i < N; ++i) hd = fnv(out.data() + std::size_t(i) * (16 + kFrame) + 16, kFrame, hd);
  std::printf("D C + pcap record, buffered   %6.1f ns/frame   %.2f GB/s written, identical to A: %s\n",
              best * 1e9 / N, double(out.size()) / best / 1e9, ha == hd ? "yes" : "NO");

  // ---- E: nanom::craft combinators, header by header, into a span_sink
  std::array<std::byte, 256> cbuf{};
  std::uint64_t he = kFnv0;
  best = 1e30;
  for (int rep = 0; rep < reps; ++rep) {
    const auto t0 = clk::now();
    for (int i = 0; i < N; ++i) {
      std::memset(pay, i & 0xff, kPay);
      SH sh{};
      sh.service_id = 0x1234;
      sh.method_id = 0x8001;
      sh.client_id = 1;
      sh.session_id = std::uint16_t(i);
      sh.protocol_version = 1;
      sh.interface_version = 1;
      sh.message_type = 2;
      Udp u{};
      u.src_port = 30501;
      u.dst_port = 30501;
      Ipv4 ip{};
      ip.version = 4;
      ip.ihl = 5;
      ip.identification = std::uint16_t(i);
      ip.ttl = 64;
      ip.protocol = 17;
      ip.src = {10, 0, 0, 1};
      ip.dst = {10, 0, 0, 2};
      VlanTag v{};
      v.pcp = 3;
      v.vid = 100;
      v.inner_ethertype = 0x0800;
      Ethernet e{};
      e.dst = {1, 0x80, 0xc2, 0, 0, 1};
      e.src = {2, 0, 0, 0, 0xaa, 1};
      e.ethertype = 0x8100;
      auto pkt = nm::craft::put_bytes(bspan(pay, kPay)) | nm::craft::framed_by(sh) | nm::craft::framed_by(u) |
                 nm::craft::framed_by(ip) | nm::craft::framed_by(v) | nm::craft::framed_by(e);
      nm::span_sink ss{cbuf};
      const auto r = nm::craft::write(pkt, ss);
      if (rep == 0) he = (r && *r == kFrame) ? fnv(cbuf.data(), kFrame, he) : 0;
    }
    best = std::min(best, secs(t0));
  }
  std::printf("E nanom::craft combinators    %6.1f ns/frame   identical to A: %s\n", best * 1e9 / N,
              ha == he ? "yes" : "NO");

  // ---- F: template copy + mut_view patching + recompute of the IPv4 computed fields
  std::uint64_t hf = kFnv0;
  best = 1e30;
  for (int rep = 0; rep < reps; ++rep) {
    const auto t0 = clk::now();
    for (int i = 0; i < N; ++i) {
      std::memcpy(fr.data(), tmpl.data(), kFrame);
      std::memset(fr.data() + kFrame - kPay, i & 0xff, kPay);
      const std::uint16_t s = std::uint16_t(i);
      auto ipm = nm::overlay_mut<Ipv4>(std::span<std::byte>(fr.data() + kIp, 20));
      auto shm = nm::overlay_mut<SH>(std::span<std::byte>(fr.data() + kSomeip, 16));
      if (ipm && shm) {
        (void)ipm->set<"identification">(s);
        (void)ipm->recompute(nm::emit_ctx{bspan(fr.data() + kIp + 20, kFrame - kIp - 20)});
        (void)shm->set<"session_id">(s);
      }
      if (rep == 0) hf = fnv(fr.data(), kFrame, hf);
    }
    best = std::min(best, secs(t0));
  }
  std::printf("F template + mut_view patch   %6.1f ns/frame   identical to A: %s\n", best * 1e9 / N,
              ha == hf ? "yes" : "NO");
  return (ha == hb && ha == hc && ha == hd && ha == he && ha == hf) ? 0 : 1;
}
