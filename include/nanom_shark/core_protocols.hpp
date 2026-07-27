// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/core_protocols.hpp — the base Ethernet/VLAN/IPv4/IPv6/UDP/TCP walk, expressed as one
// registered "protocol" so that its output tables are declared through the SAME table_spec
// mechanism every pluggable protocol uses (this is what replaces the hand-written `AllTables`
// struct).
//
// CoreL2L3 is deliberately NOT dispatched: its trigger is `never`, because the L2/L3/L4 walk is
// infrastructure that FEEDS decode_ctx and the dispatch points -- it is not something a trigger
// selects. What it contributes to the type list is its TABLES, so that `tables_of<decoder<...>>`
// really is "every registered protocol's tables, concatenated", with no special case for the
// builtin ones.

#include <nanom_shark/defrag.hpp>
#include <nanom_shark/node_row.hpp>
#include <nanom_shark/packet_row.hpp>
#include <nanom_shark/protocol.hpp>

#include <nanom_shark/protocols.hpp>  // nmproto::{Ethernet,VlanTag,Ipv4,Ipv6,Udp,Tcp}

namespace nanom_shark {

using EthNode  = Node<nmproto::Ethernet>;
using VlanNode = Node<nmproto::VlanTag>;
using Ipv4Node = Node<nmproto::Ipv4>;
using Ipv6Node = Node<nmproto::Ipv6>;
using UdpNode  = Node<nmproto::Udp>;
using TcpNode  = Node<nmproto::Tcp>;

// Node<Body>'s describe<> registration is one shared partial specialization in node_row.hpp,
// covering every Node<...> at once -- no per-protocol NANOM_DESCRIBE line is needed here.

struct CoreL2L3 {
  using trigger = never;  // fed by the walk itself, never selected by a dispatch point
  using state   = no_state;

  static constexpr auto tables = table_spec<
      // One row per captured packet, regardless of decode outcome -- see packet_row.hpp. Anchors
      // byte-level sinks (e.g. the sibling `nanoshark` repo's Lance bridge) back to the source file.
      table_decl<"packets", PacketRow>,

      table_decl<"eth", EthNode>,
      table_decl<"vlan", VlanNode>,
      table_decl<"ipv4", Ipv4Node>,
      table_decl<"ipv6", Ipv6Node>,
      table_decl<"udp", UdpNode>,
      table_decl<"tcp", TcpNode>,

      // IPv4/IPv6 fragmentation: one row per observed fragment (forensic visibility, "this packet
      // was fragment N of datagram D") plus one row per reassembly attempt, complete or not.
      table_decl<"ipv4_frag", defrag::Ipv4FragMeta>,
      table_decl<"ipv6_frag", defrag::Ipv6FragMeta>,
      table_decl<"datagram", defrag::DatagramRow>>{};

  // No parse(): `never` prunes this protocol out of every dispatch fold at compile time, so one is
  // never required (and never instantiated).
};

}  // namespace nanom_shark
