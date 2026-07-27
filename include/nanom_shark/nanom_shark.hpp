// nanom_shark/nanom_shark.hpp — umbrella header for the nanom_shark decoder library.
//
// nanom_shark is a dependency-free (nanom-only) pcap/pcapng protocol decoder: one decode pass over
// a capture producing L2/L3/L4 node tables, zero-copy IPv4+IPv6 fragment reassembly, SOME/IP, gPTP
// and LLDP dissection, a JSON tree sink and an Avro Object Container File sink.
//
// Including this header pulls in the whole library. Consumers that only need one piece (say the
// pcap block scanner, or just the wire structs) should include that header directly instead —
// every header below is self-contained.
//
// CMake: target_link_libraries(your_target PRIVATE nanom::shark)
#pragma once

// -- substrate: capture-file scanning + the wire structs ---------------------
#include <nanom_shark/pcap.hpp>       // nmpcap::scan_blocks / parse_idb / parse_epb / BlockRef
#include <nanom_shark/protocols.hpp>  // nmproto::{Ethernet,VlanTag,Ipv4,Ipv6,Udp,Tcp}, walk_packet_ext

// -- row/table shapes --------------------------------------------------------
#include <nanom_shark/node_row.hpp>
#include <nanom_shark/packet_row.hpp>
#include <nanom_shark/soa_columns.hpp>

// -- reassembly --------------------------------------------------------------
#include <nanom_shark/defrag.hpp>

// -- per-protocol dissectors + their row shapes ------------------------------
#include <nanom_shark/gptp.hpp>
#include <nanom_shark/gptp_rows.hpp>
#include <nanom_shark/lldp.hpp>
#include <nanom_shark/lldp_rows.hpp>
#include <nanom_shark/someip.hpp>
#include <nanom_shark/someip_rows.hpp>

// -- the decode pass ---------------------------------------------------------
#include <nanom_shark/decode_options.hpp>
#include <nanom_shark/decode_pass.hpp>
#include <nanom_shark/l2l3_nodes.hpp>
#include <nanom_shark/l4_dispatch.hpp>

// -- sinks -------------------------------------------------------------------
#include <nanom_shark/avro_dump.hpp>
#include <nanom_shark/avro_ocf.hpp>
#include <nanom_shark/json_tree.hpp>
