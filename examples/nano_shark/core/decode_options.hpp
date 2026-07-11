// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/decode_options.hpp — DecodeOptions lives in its own header (rather than
// decode_pass.hpp) so that l4_dispatch.hpp's SOME/IP dispatch (shared by the normal per-packet
// path and defrag's reassembly re-entry path) can see the someip_ports/someip_tlv_ports
// configuration without decode_pass.hpp and l4_dispatch.hpp needing to include each other.

#include "defrag.hpp"

#include <cstdint>
#include <vector>

namespace nano_shark {

struct DecodeOptions {
  bool decode_l2l3 = true;    // Eth/VLAN*/IPv4/IPv6(+ext headers, SRv6)/TCP/UDP
  bool decode_defrag = true;  // IPv4/IPv6 reassembly + re-entry into L4

  defrag::ReassemblyTable<defrag::Ipv4Key>::Config ipv4_defrag{};
  defrag::ReassemblyTable<defrag::Ipv6Key>::Config ipv6_defrag{};

  // SOME/IP has no EtherType/magic-number tag -- it's plain bytes on a UDP port agreed
  // out-of-band. someip_ports gates which UDP src/dst ports get a SomeipHeader parse attempt
  // (default: just the well-known Service Discovery port); someip_tlv_ports additionally marks
  // which of those ports carry the optional TLV serialization format (opt-in: a plain/flat
  // SOME/IP payload isn't self-describing as TLV without IDL knowledge, so this can't be
  // inferred). SD entry/option extraction, by contrast, IS self-describing and always attempted
  // once a SomeipHeader is parsed on a configured port.
  std::vector<std::uint16_t> someip_ports = {30490};
  std::vector<std::uint16_t> someip_tlv_ports = {};
};

}  // namespace nano_shark
