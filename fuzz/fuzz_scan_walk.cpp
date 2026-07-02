// SPDX-License-Identifier: Apache-2.0

// Coverage-guided libFuzzer entry point for the pcap scan + L2/L3/L4 walk.
// libFuzzer mutates `data` toward new code paths; ASan+UBSan make any
// out-of-bounds read or UB a crash. This is the continuous counterpart to the
// bounded self_fuzz.cpp (which runs as a ctest). Build via -DNANOM_BUILD_FUZZERS
// with Clang; run: ./fuzz_scan_walk -max_total_time=60 corpus/
//
//   the harness exercises two entry surfaces on the same bytes:
//     1. walk_packet() directly (raw packet bytes)
//     2. scan_blocks() + parse_epb() + walk_packet() (whole-file surface)

#include "../examples/nanotins_parity/nm_pcap.hpp"
#include "../examples/nanotins_parity/nm_protocols.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {
std::uint64_t sink = 0;

void walk(nanom::bytes pkt) {
  nmproto::walk_packet(
      1, pkt,
      [&](const nmproto::Ethernet& x) { sink ^= x.ethertype; },
      [&](const nmproto::VlanTag& x) { sink ^= x.vid; },
      [&](const nmproto::Ipv4& x) { sink ^= x.protocol ^ std::uint16_t(x.total_length); },
      [&](const nmproto::Ipv6& x) { sink ^= x.next_header ^ x.flow_label; },
      [&](const nmproto::Tcp& x) { sink ^= std::uint16_t(x.src_port) ^ std::uint16_t(x.data_offset); },
      [&](const nmproto::Udp& x) { sink ^= std::uint16_t(x.dst_port); });
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const nanom::bytes bytes(reinterpret_cast<const std::byte*>(data), size);

  // 1) treat the input as a bare packet
  walk(bytes);

  // 2) treat the input as a whole pcap/pcapng file
  std::vector<nmpcap::BlockRef> refs;
  std::string err;
  if (nmpcap::scan_blocks(bytes, refs, err)) {
    std::vector<std::uint16_t> iface_link;
    for (const auto& ref : refs) {
      if (ref.kind == nmpcap::Kind::Idb) {
        nmpcap::IdbView idb{};
        if (nmpcap::parse_idb(bytes, ref, idb)) iface_link.push_back(idb.link_type);
        continue;
      }
      nmpcap::EpbView e{};
      if (nmpcap::parse_epb(bytes, ref, e))
        walk(bytes.subspan(std::size_t(e.payload_file_offset), e.caplen));
    }
  }
  return 0;
}
