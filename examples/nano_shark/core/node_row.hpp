// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/node_row.hpp — the one per-protocol row envelope + table container.
//
// Every protocol layer's row reuses its EXISTING NANOM_DESCRIBE'd wire struct as a nested field
// (nanom::soa<T>'s dotted-flattening already knows how to turn a nested Described member into
// "body.<field>" columns) instead of hand-retyping every field into a parallel row struct — see
// nanom/include/nanom/soa.hpp's build_nested(). One
//   NANOM_DESCRIBE(Node<SomeWireStruct>, packet_id, datagram_id, is_reassembled, body);
// line per protocol (see l2l3_nodes.hpp) is the entire per-protocol registration; it never repeats
// a single field name that the wire struct's own NANOM_DESCRIBE already listed.

#include <nanom/nanom.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace nano_shark {

namespace nm = nanom;

using packet_id_t = std::uint64_t;
inline constexpr packet_id_t kNoPacket = packet_id_t(-1);

// Body is an existing NANOM_DESCRIBE'd wire struct (nmproto::Ethernet, nmproto::Ipv4, ...).
// datagram_id/is_reassembled are 0/false for every packet except a UDP/TCP row built from a
// completed IPv4/IPv6 fragment reassembly (see core/defrag.hpp, added in a later phase).
template <class Body>
struct Node {
  packet_id_t   packet_id      = kNoPacket;
  std::uint32_t datagram_id    = 0;
  bool          is_reassembled = false;
  Body          body;
};

// One table per node "kind": a name (the JSON sink's layer key / a future Parquet+Lance file stem)
// plus the existing nm::soa<Row> columnar accumulator.
template <nm::Described Row>
class node_table {
 public:
  explicit node_table(std::string_view proto_name, std::size_t chunk_rows = 65536)
      : proto_name_(proto_name), table_(chunk_rows) {}

  void push(const Row& r) { table_.push(r); }
  const nm::soa<Row>& soa() const { return table_; }
  std::size_t rows() const { return table_.rows(); }
  std::string_view proto_name() const { return proto_name_; }

 private:
  std::string  proto_name_;
  nm::soa<Row> table_;
};

}  // namespace nano_shark
