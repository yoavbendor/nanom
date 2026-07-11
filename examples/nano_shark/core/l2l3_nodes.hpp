// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/l2l3_nodes.hpp — Node<> instantiations + registrations for the base L2-L4 walk
// (Ethernet/VLAN/IPv4/IPv6/UDP/TCP), reusing nanotins_parity's existing wire structs verbatim.

#include "node_row.hpp"

#include "nm_protocols.hpp"  // nmproto::{Ethernet,VlanTag,Ipv4,Ipv6,Udp,Tcp}; include path set by CMake

namespace nano_shark {

using EthNode  = Node<nmproto::Ethernet>;
using VlanNode = Node<nmproto::VlanTag>;
using Ipv4Node = Node<nmproto::Ipv4>;
using Ipv6Node = Node<nmproto::Ipv6>;
using UdpNode  = Node<nmproto::Udp>;
using TcpNode  = Node<nmproto::Tcp>;

}  // namespace nano_shark

NANOM_DESCRIBE(nano_shark::EthNode, packet_id, datagram_id, is_reassembled, body);
NANOM_DESCRIBE(nano_shark::VlanNode, packet_id, datagram_id, is_reassembled, body);
NANOM_DESCRIBE(nano_shark::Ipv4Node, packet_id, datagram_id, is_reassembled, body);
NANOM_DESCRIBE(nano_shark::Ipv6Node, packet_id, datagram_id, is_reassembled, body);
NANOM_DESCRIBE(nano_shark::UdpNode, packet_id, datagram_id, is_reassembled, body);
NANOM_DESCRIBE(nano_shark::TcpNode, packet_id, datagram_id, is_reassembled, body);

namespace nano_shark {

// One table per protocol layer decoded by the base L2-L4 walk, always populated by
// run_decode_pass regardless of which sinks are active. Grows in later phases (defrag,
// SOME/IP, gPTP, LLDP, IPv6 ext-header/SRv6 detail tables) as those sinks come online — the
// JSON sink does not depend on this struct at all (it renders straight from the decoded
// values at each walk_packet_ext callback site, see core/decode_pass.hpp).
struct AllTables {
  node_table<EthNode>  eth{"eth"};
  node_table<VlanNode> vlan{"vlan"};
  node_table<Ipv4Node> ipv4{"ipv4"};
  node_table<Ipv6Node> ipv6{"ipv6"};
  node_table<UdpNode>  udp{"udp"};
  node_table<TcpNode>  tcp{"tcp"};
};

}  // namespace nano_shark
