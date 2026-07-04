// nanom — 60-second tour, self-contained for Compiler Explorer (godbolt.org).
//
// Paste this together with the generated single-file header nanom-single.hpp
// (https://yoavbendor.github.io/nanom/nanom-single.hpp) — no other files needed.
// Locally: `python3 tools/amalgamate.py --out nanom-single.hpp` then
//          `g++-13 -std=c++23 -I . try/godbolt.cpp -o tour && ./tour`.
//
// It parses an Ethernet + VLAN header out of a byte buffer, shows the zero-copy overlay view,
// accumulates into a columnar soa<>, and prints the auto-generated Avro schema — all from a plain
// struct (no NANOM_DESCRIBE needed at all under a C++26 P2996 compiler).
#include "nanom-single.hpp"

#include <array>
#include <cstdint>
#include <cstdio>

namespace nm = nanom;

struct eth_hdr {
  std::array<std::uint8_t, 6> dst, src;
  nm::be<std::uint16_t>       eth_type;      // big-endian on the wire
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type); // (optional under C++26 reflection)

struct vlan_hdr {
  nm::ubits<3>          pcp;                  // bit fields, msb0 (network) order
  nm::ubits<1>          dei;
  nm::ubits<12>         vid;
  nm::be<std::uint16_t> eth_type;
};
NANOM_DESCRIBE(vlan_hdr, pcp, dei, vid, eth_type);

int main() {
  // dst(6) | src(6) | eth_type=0x8100 (VLAN) | pcp/dei/vid=5/0/100 | inner eth_type=0x0800 (IPv4)
  const std::array<std::uint8_t, 18> frame = {
    0x01,0x02,0x03,0x04,0x05,0x06,  0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x81,0x00,                      // outer ethertype: VLAN
    0xA0,0x64,                      // pcp=5(101) dei=0 vid=100(0x064)
    0x08,0x00                       // inner ethertype: IPv4
  };

  nm::input in = nm::from(frame);

  // 1. parse the Ethernet header by value -> {value, rest} or a localized error
  auto eth = nm::strct<eth_hdr>()(in);
  if (!eth) { std::puts(eth.error().render(in).c_str()); return 1; }
  std::printf("eth_type = 0x%04x\n", (unsigned)eth->value.eth_type);

  // 2. zero-copy overlay of the VLAN tag — fields decode on access, names are checked at compile time
  auto vlan = nm::overlay<vlan_hdr>()(eth->rest);
  if (!vlan) { std::puts(vlan.error().render(in).c_str()); return 1; }
  std::printf("vlan vid = %u, inner = 0x%04x\n",
              vlan->value.get<"vid">(), (unsigned)vlan->value.get<"eth_type">());

  // 3. columnar Struct-of-Arrays accumulation (ready for Arrow/Lance buffers)
  nm::soa<eth_hdr> table;
  table.push(eth->value);
  std::printf("soa rows = %zu, columns = %zu\n", table.rows(), table.columns().size());

  // 4. schema for free
  std::printf("avro = %s\n", nm::avro_schema<eth_hdr>().c_str());
  return 0;
}
