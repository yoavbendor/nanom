// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/soa_columns.hpp — compile-time LEAF COLUMN LIST for a Described type, mirroring
// nanom::soa<T>'s own runtime column flattening (dotted names, nested Described members recursed
// into, fixed-size arrays kept as one column) but as a TYPE LIST usable as a template parameter
// pack -- e.g. folded into nanoarrow2parquet's Field<Name, T>... or nanolance's column<T, Name>...
// in the sibling `nanoshark` repo's Parquet/Lance sink bridges, so the flattening logic is written
// exactly once and is guaranteed to produce the same column order and leaf types
// nanom::soa<T>::columns() itself produces at runtime (both derive from the same
// nanom::detail::for_each_field / describe<T>::fields() traversal, walked in the same tuple-index
// order).

#include <nanom/nanom.hpp>

#include <array>
#include <cstddef>
#include <tuple>
#include <utility>

namespace nano_shark {

// One leaf column: a dotted, compile-time NAME plus its per-row DECODED element type -- exactly
// the V that nanom::soa<T>::chunk::as<V>(i) requires for that column index.
template <nanom::fixed_string Name, class LeafType>
struct leaf_column {
  static constexpr auto name = Name;
  using type = LeafType;
};

namespace detail {

// Decoded per-row type for a field F, matching soa<T>'s own column typing exactly: a Described
// nested struct never reaches here (the recursion below descends into it instead of treating it as
// a leaf); a fixed-size array is stored -- and read back via chunk::as<V>(i) -- as that SAME array
// type, regardless of element type (soa<T>::push_one concatenates each element's raw decoded
// bytes; the column's V must therefore be the array type itself, not its element type); everything
// else decodes through nanom::detail::wire<F>::decoded (be<>/le<>/ubits<>/plain scalars all resolve
// here, matching soa<T>::build_columns's own `sizeof(typename detail::wire<F>::decoded)` sizing).
template <class F>
struct leaf_type_of {
  using type = typename nanom::detail::wire<F>::decoded;
};
template <class E, std::size_t N>
struct leaf_type_of<std::array<E, N>> {
  using type = std::array<E, N>;
};
template <class F>
using leaf_type_of_t = typename leaf_type_of<F>::type;

// Build a new fixed_string "a.b" from two existing fixed_strings at compile time (each
// nanom::fixed_string<M> stores an M-1 char literal plus a trailing NUL; the joined string needs
// exactly one '.' plus one trailing NUL, so the new size is NA + NB). Same left-to-right fill
// technique nanom26.hpp's name_holder::qualified_name uses for qualified type names, applied here
// to dotted SoA column names instead.
template <std::size_t NA, std::size_t NB>
consteval auto join_names(nanom::fixed_string<NA> a, nanom::fixed_string<NB> b) {
  nanom::fixed_string<NA + NB> out{};
  std::size_t pos = 0;
  for (std::size_t i = 0; i < NA - 1; ++i) out.data[pos++] = a.data[i];
  out.data[pos++] = '.';
  for (std::size_t i = 0; i < NB - 1; ++i) out.data[pos++] = b.data[i];
  out.data[pos] = '\0';
  return out;
}

// Mutually recursive column-list builders, as class templates so forward declaration is trivial.
// `Prefix` is the dotted path down to (but not including) the current field; `HasPrefix` is false
// only at the very top level (Prefix is then an unused placeholder value).
template <nanom::Described T, nanom::fixed_string Prefix, bool HasPrefix>
struct flatten;

template <class Fld, nanom::fixed_string Prefix, bool HasPrefix>
struct build_one {
  using M = nanom::detail::member_t<Fld::mem_ptr>;

  static consteval auto full_name() {
    if constexpr (HasPrefix) return join_names(Prefix, Fld::name);
    else return Fld::name;
  }

  static consteval auto make() {
    if constexpr (nanom::Described<M>) {
      return flatten<M, full_name(), true>::make();
    } else {
      return std::tuple<leaf_column<full_name(), leaf_type_of_t<M>>>{};
    }
  }
};

template <nanom::Described T, nanom::fixed_string Prefix, bool HasPrefix>
struct flatten {
  using Flds = decltype(nanom::describe<T>::fields());

  template <std::size_t... I>
  static consteval auto build(std::index_sequence<I...>) {
    return std::tuple_cat(build_one<std::tuple_element_t<I, Flds>, Prefix, HasPrefix>::make()...);
  }

  static consteval auto make() { return build(std::make_index_sequence<std::tuple_size_v<Flds>>{}); }
};

}  // namespace detail

// columns_of<T> == std::tuple<leaf_column<"dotted.name", DecodedType>...>, one entry per LEAF
// field of T, in nanom::soa<T>::columns() order.
template <nanom::Described T>
struct column_list_of {
  using type = decltype(detail::flatten<T, nanom::fixed_string<1>{}, false>::make());
};
template <nanom::Described T>
using columns_of = typename column_list_of<T>::type;

}  // namespace nano_shark
