// Minimal downstream user of the installed nanom_shark library: prove that a nanom_shark header
// resolves from the install tree (<nanom_shark/...>, not a source-tree relative path) and that
// linking nanom::shark is enough to build a real decode.
#include <nanom_shark/pcap.hpp>
#include <nanom_shark/protocols.hpp>
#include <cstdio>
#include <cstdint>
#include <vector>

int main() {
  // A hand-rolled 1-packet classic pcap: global header + one record holding a minimal
  // Ethernet/IPv4/UDP frame. Parsed through the same entry points nanom_shark itself uses.
  std::vector<std::uint8_t> cap;
  auto put = [&](std::initializer_list<std::uint8_t> b) { cap.insert(cap.end(), b); };
  // pcap global header (little-endian magic, snaplen 65535, link type 1 = Ethernet)
  put({0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
       0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00});

  std::vector<std::uint8_t> frame;
  auto f = [&](std::initializer_list<std::uint8_t> b) { frame.insert(frame.end(), b); };
  f({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x08, 0x00});           // Ethernet, ethertype IPv4
  f({0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11});  // IPv4, proto 17 = UDP
  f({0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2});                        // checksum + src/dst
  f({0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00});              // UDP :53 -> :53

  const std::uint32_t n = static_cast<std::uint32_t>(frame.size());
  put({0, 0, 0, 0, 0, 0, 0, 0});  // ts sec/usec
  for (int i = 0; i < 4; ++i) cap.push_back(std::uint8_t((n >> (8 * i)) & 0xFF));  // caplen
  for (int i = 0; i < 4; ++i) cap.push_back(std::uint8_t((n >> (8 * i)) & 0xFF));  // origlen
  cap.insert(cap.end(), frame.begin(), frame.end());

  const nanom::bytes file(reinterpret_cast<const std::byte*>(cap.data()), cap.size());

  std::vector<nmpcap::BlockRef> refs;
  std::string err;
  if (!nmpcap::scan_blocks(file, refs, err)) {
    std::printf("shark consumer: scan_blocks failed: %s\n", err.c_str());
    return 1;
  }

  int packets = 0, udp_seen = 0;
  for (const auto& ref : refs) {
    if (ref.kind != nmpcap::Kind::PcapRecord && ref.kind != nmpcap::Kind::Epb) continue;
    nmpcap::EpbView e{};
    if (!nmpcap::parse_epb(file, ref, e)) continue;
    ++packets;
    const nanom::bytes pkt = file.subspan(std::size_t(e.payload_file_offset), e.caplen);
    nmproto::walk_packet(
        /*link_type=*/1, pkt,
        [&](const nmproto::Ethernet&) {}, [&](const nmproto::VlanTag&) {},
        [&](const nmproto::Ipv4&) {}, [&](const nmproto::Ipv6&) {},
        [&](const nmproto::Tcp&) {},
        [&](const nmproto::Udp& u) {
          if (std::uint16_t(u.dst_port) == 53) ++udp_seen;
        });
  }

  if (packets != 1 || udp_seen != 1) {
    std::printf("shark consumer: expected 1 packet / 1 udp, got %d / %d\n", packets, udp_seen);
    return 1;
  }
  std::printf("shark consumer ok: packets=%d udp=%d\n", packets, udp_seen);
  return 0;
}
