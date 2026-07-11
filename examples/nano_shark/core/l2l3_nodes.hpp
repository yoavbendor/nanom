// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/l2l3_nodes.hpp — Node<> instantiations + registrations for the base L2-L4 walk
// (Ethernet/VLAN/IPv4/IPv6/UDP/TCP), reusing nanotins_parity's existing wire structs verbatim.

#include "defrag.hpp"
#include "gptp.hpp"
#include "lldp_rows.hpp"
#include "node_row.hpp"
#include "someip_rows.hpp"

#include "nm_protocols.hpp"  // nmproto::{Ethernet,VlanTag,Ipv4,Ipv6,Udp,Tcp}; include path set by CMake

namespace nano_shark {

using EthNode  = Node<nmproto::Ethernet>;
using VlanNode = Node<nmproto::VlanTag>;
using Ipv4Node = Node<nmproto::Ipv4>;
using Ipv6Node = Node<nmproto::Ipv6>;
using UdpNode  = Node<nmproto::Udp>;
using TcpNode  = Node<nmproto::Tcp>;

}  // namespace nano_shark

// Node<Body>'s describe<> registration is one shared partial specialization in node_row.hpp,
// covering EthNode/VlanNode/Ipv4Node/Ipv6Node/UdpNode/TcpNode (and SomeipNode, see someip_rows.hpp)
// at once — no per-protocol NANOM_DESCRIBE line needed here.

namespace nano_shark {

// One table per protocol layer decoded by the base L2-L4 walk, always populated by
// run_decode_pass regardless of which sinks are active — the JSON sink does not depend on this
// struct at all (it renders straight from the decoded values at each walk_packet_ext callback
// site / dispatch call, see core/decode_pass.hpp). Grows further with the IPv6 ext-header/SRv6
// detail tables a later sink (Parquet/Lance) needs.
struct AllTables {
  node_table<EthNode>  eth{"eth"};
  node_table<VlanNode> vlan{"vlan"};
  node_table<Ipv4Node> ipv4{"ipv4"};
  node_table<Ipv6Node> ipv6{"ipv6"};
  node_table<UdpNode>  udp{"udp"};
  node_table<TcpNode>  tcp{"tcp"};

  // Phase 2: IPv4/IPv6 fragmentation. One row per observed fragment (forensic visibility, "this
  // packet was fragment N of datagram D") plus one row per reassembly attempt, complete or not.
  node_table<defrag::Ipv4FragMeta> ipv4_frag{"ipv4_frag"};
  node_table<defrag::Ipv6FragMeta> ipv6_frag{"ipv6_frag"};
  node_table<defrag::DatagramRow>  datagram{"datagram"};

  // Phase 3: SOME/IP (header + Service Discovery entries/options + optional TLV members), gPTP
  // (its own 9-table bundle, joined by msg_index rather than node_table's packet_id-only shape),
  // and LLDP (one row per TLV).
  node_table<SomeipNode>          someip{"someip"};
  node_table<SomeipSdEntryRow>    someip_sd_entry{"someip_sd_entry"};
  node_table<SomeipSdOptionRow>   someip_sd_option{"someip_sd_option"};
  node_table<SomeipTlvMemberRow>  someip_tlv{"someip_tlv"};
  nmgptp::GptpTables              gptp{};
  node_table<LldpTlvRow>          lldp{"lldp"};
};

}  // namespace nano_shark
