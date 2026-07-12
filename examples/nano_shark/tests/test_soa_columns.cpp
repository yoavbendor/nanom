// SPDX-License-Identifier: Apache-2.0
// nano_shark soa_columns.hpp tests: columns_of<T> (a compile-time leaf column TYPE LIST) must agree
// with nanom::soa<T>::columns() (the existing runtime leaf column list) exactly -- same count, same
// dotted names, same order, same per-row element size -- since the sibling `nanoshark` repo's
// Parquet/Lance bridges zip nanom::soa<T>::chunk::as<V>(i) spans against columns_of<T>'s leaf types
// index-for-index. Exercises: nested Described members (Node<Body>'s "body.*" flattening), a flat
// (no nesting) synthesized row, bit-field members (SomeipHeader's plain-looking-but-packed fields),
// and a fixed byte-array member (LldpTlvRow::value_head).

#include "l2l3_nodes.hpp"
#include "soa_columns.hpp"

#include <cstdio>
#include <cstdint>

using namespace nano_shark;

namespace {

int failures = 0;
#define CHECK(cond)                                                \
  do {                                                              \
    if (!(cond)) {                                                  \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      ++failures;                                                   \
    }                                                                \
  } while (0)

template <class T>
void check_matches_soa() {
  using Cols = columns_of<T>;
  nanom::soa<T> s;
  CHECK(std::tuple_size_v<Cols> == s.columns().size());
  [&]<std::size_t... I>(std::index_sequence<I...>) {
    auto check_one = [&]<std::size_t J>(std::integral_constant<std::size_t, J>) {
      using Elem = std::tuple_element_t<J, Cols>;
      CHECK(Elem::name.sv() == s.columns()[J].name);
      CHECK(sizeof(typename Elem::type) == s.columns()[J].elem_bytes);
    };
    (check_one(std::integral_constant<std::size_t, I>{}), ...);
  }(std::make_index_sequence<std::tuple_size_v<Cols>>{});
}

}  // namespace

// Compile-time spot checks on EthNode (Node<nmproto::Ethernet>: packet_id/datagram_id/
// is_reassembled top-level, then body.dst/body.src/body.ethertype nested).
using EthCols = columns_of<EthNode>;
static_assert(std::tuple_size_v<EthCols> == 6);
static_assert(std::tuple_element_t<0, EthCols>::name.sv() == "packet_id");
static_assert(std::tuple_element_t<3, EthCols>::name.sv() == "body.dst");
static_assert(std::tuple_element_t<4, EthCols>::name.sv() == "body.src");
static_assert(std::tuple_element_t<5, EthCols>::name.sv() == "body.ethertype");
static_assert(std::is_same_v<std::tuple_element_t<3, EthCols>::type, std::array<std::uint8_t, 6>>);
static_assert(std::is_same_v<std::tuple_element_t<5, EthCols>::type, std::uint16_t>);

// A flat (no nested Described member) synthesized row.
using FragCols = columns_of<defrag::Ipv4FragMeta>;
static_assert(std::tuple_element_t<0, FragCols>::name.sv() == "packet_id");
static_assert(std::tuple_element_t<2, FragCols>::name.sv() == "frag_offset_bytes");

int main() {
  check_matches_soa<PacketRow>();
  check_matches_soa<EthNode>();
  check_matches_soa<VlanNode>();
  check_matches_soa<Ipv4Node>();
  check_matches_soa<Ipv6Node>();
  check_matches_soa<UdpNode>();
  check_matches_soa<TcpNode>();
  check_matches_soa<SomeipNode>();          // exercises bit-field (ubits<>) member decoding
  check_matches_soa<defrag::Ipv4FragMeta>();
  check_matches_soa<defrag::Ipv6FragMeta>();
  check_matches_soa<defrag::DatagramRow>();
  check_matches_soa<LldpTlvRow>();          // exercises a fixed byte-array member (value_head)
  check_matches_soa<SomeipSdEntryRow>();
  check_matches_soa<SomeipSdOptionRow>();
  check_matches_soa<SomeipTlvMemberRow>();

  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nano_shark_soa_columns_tests: OK\n");
  return 0;
}
