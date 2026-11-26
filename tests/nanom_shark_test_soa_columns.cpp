// SPDX-License-Identifier: Apache-2.0
// nanom_shark soa_columns.hpp tests: columns_of<T> (a compile-time leaf column TYPE LIST) must agree
// with nanom::soa<T>::columns() (the existing runtime leaf column list) exactly -- same count, same
// dotted names, same order, same per-row element size -- since the sibling `nanoshark` repo's
// Parquet/Lance bridges zip nanom::soa<T>::chunk::as<V>(i) spans against columns_of<T>'s leaf types
// index-for-index. Exercises: nested Described members (Node<Body>'s "body.*" flattening), a flat
// (no nesting) synthesized row, bit-field members (SomeipHeader's plain-looking-but-packed fields),
// and a fixed byte-array member (LldpTlvRow::value_head).

#include <nanom/emit.hpp>
#include <nanom_shark/l2l3_nodes.hpp>
#include <nanom_shark/soa_columns.hpp>

#include <cstdio>
#include <cstdint>

using namespace nanom_shark;

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

struct WideArrayRow {
  std::array<nanom::be_u24_t, 2> vals;
  std::array<nanom::be<std::uint16_t>, 3> words;
};
NANOM_DESCRIBE(WideArrayRow, vals, words);

static_assert(std::is_same_v<std::tuple_element_t<0, columns_of<WideArrayRow>>::type,
                             std::array<std::uint32_t, 2>>);
static_assert(std::is_same_v<std::tuple_element_t<1, columns_of<WideArrayRow>>::type,
                             std::array<std::uint16_t, 3>>);

void test_soa_safety_regressions() {
  check_matches_soa<WideArrayRow>();
  nanom::soa<WideArrayRow> tbl(/*chunk_rows=*/4);
  static_assert(noexcept(nanom::soa<WideArrayRow>(std::move(tbl))));

  // Default-constructed column_bytes must not dereference null
  nanom::soa<WideArrayRow>::column_bytes empty_cb{};
  CHECK(empty_cb.size() == 0 && empty_cb.empty());

  // Push >256 rows? Use chunk_rows=4 and push 20 rows via both value and view<T>
  for (std::uint32_t i = 0; i < 20; ++i) {
    WideArrayRow r{{nanom::be_u24_t(0x100000u + i), nanom::be_u24_t(0x200000u + i)},
                   {nanom::be<std::uint16_t>(std::uint16_t(i)),
                    nanom::be<std::uint16_t>(std::uint16_t(i + 1)),
                    nanom::be<std::uint16_t>(std::uint16_t(i + 2))}};
    if (i % 2 == 0) {
      tbl.push(r);
    } else {
      auto raw = nanom::to_bytes(r);
      CHECK(raw.has_value());
      if (raw) {
        auto v = nanom::overlay<WideArrayRow>()(nanom::from(std::span<const std::byte>(*raw)));
        CHECK(v.has_value());
        if (v) tbl.push(v->value);
      }
    }
  }
  CHECK(tbl.rows() == 20 && tbl.chunk_count() == 5);

  // Copy a column_bytes from sealed chunk 0, then trigger many seals so sealed_ reallocates
  auto cb0 = tbl.chunk_at(0).cols[0];
  CHECK(cb0.size() == 4 * sizeof(std::array<std::uint32_t, 2>));
  for (std::uint32_t i = 0; i < 40; ++i) {
    WideArrayRow r{{nanom::be_u24_t(i), nanom::be_u24_t(i)}, {0, 0, 0}};
    tbl.push(r);
  }
  CHECK(cb0.size() == 4 * sizeof(std::array<std::uint32_t, 2>));

  // Verify decoded values in chunk 0
  auto sp_vals = tbl.chunk_at(0).as<std::array<std::uint32_t, 2>>(0);
  auto sp_words = tbl.chunk_at(0).as<std::array<std::uint16_t, 3>>(1);
  CHECK(sp_vals.size() == 4 && sp_vals[1][0] == 0x100001u && sp_vals[1][1] == 0x200001u);
  CHECK(sp_words.size() == 4 && sp_words[3][0] == 3 && sp_words[3][2] == 5);

  // reserve(SIZE_MAX) must clamp to chunk_rows instead of wrapping
  tbl.reserve(std::numeric_limits<std::size_t>::max());

  // Move preserves rows and leaves moved-from empty
  auto moved = std::move(tbl);
  CHECK(moved.rows() == 60 && tbl.rows() == 0);
}

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
  test_soa_safety_regressions();

  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nanom_shark_soa_columns_tests: OK\n");
  return 0;
}
