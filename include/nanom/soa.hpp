// SPDX-License-Identifier: Apache-2.0
// nanom/soa.hpp — soa<T>, column-oriented (Struct-of-Arrays) chunked storage for a described struct,
// ready to hand to nanoarrow / Lance buffers without a transpose (an "extra", layered on schema.hpp
// for dkind/arrow_format). See also bulk.hpp for the data-parallel (GPU-ready) scatter path.
#ifndef NANOM_SOA_HPP_INCLUDED
#define NANOM_SOA_HPP_INCLUDED

#include "schema.hpp"

namespace nanom {

// ---------------------------------------------------------------------------
// 23. soa<T> — columnar chunked storage (SoA) for nanoarrow / nanolance
// ---------------------------------------------------------------------------

namespace detail {

template <fixed_string Name, class LeafType>
struct soa_leaf_col {
  static constexpr auto name = Name;
  using type = LeafType;
};

template <std::size_t NA, std::size_t NB>
consteval auto soa_join_names(fixed_string<NA> a, fixed_string<NB> b) {
  fixed_string<NA + NB> out{};
  std::size_t pos = 0;
  for (std::size_t i = 0; i < NA - 1; ++i) out.data[pos++] = a.data[i];
  out.data[pos++] = '.';
  for (std::size_t i = 0; i < NB - 1; ++i) out.data[pos++] = b.data[i];
  out.data[pos] = '\0';
  return out;
}

template <Described T, fixed_string Prefix, bool HasPrefix>
struct soa_flatten;

template <class Fld, fixed_string Prefix, bool HasPrefix>
struct soa_build_one {
  using M = member_t<Fld::mem_ptr>;

  static consteval auto full_name() {
    if constexpr (HasPrefix) return soa_join_names(Prefix, Fld::name);
    else return Fld::name;
  }

  static consteval auto make() {
    if constexpr (Described<M>) {
      return soa_flatten<M, full_name(), true>::make();
    } else {
      return std::tuple<soa_leaf_col<full_name(), typename wire<M>::decoded>>{};
    }
  }
};

template <Described T, fixed_string Prefix, bool HasPrefix>
struct soa_flatten {
  using Flds = decltype(describe<T>::fields());

  template <std::size_t... I>
  static consteval auto build(std::index_sequence<I...>) {
    return std::tuple_cat(soa_build_one<std::tuple_element_t<I, Flds>, Prefix, HasPrefix>::make()...);
  }

  static consteval auto make() { return build(std::make_index_sequence<std::tuple_size_v<Flds>>{}); }
};

template <Described T>
using soa_columns_of_t = decltype(soa_flatten<T, fixed_string{""}, false>::make());

template <class Cols, fixed_string Name, std::size_t... I>
consteval std::size_t soa_col_index_impl(std::index_sequence<I...>) {
  std::size_t idx = std::size_t(-1);
  ((std::tuple_element_t<I, Cols>::name == Name.sv() ? void(idx = I) : void()), ...);
  return idx;
}

template <class Cols, fixed_string Name>
consteval std::size_t soa_col_index() {
  return soa_col_index_impl<Cols, Name>(std::make_index_sequence<std::tuple_size_v<Cols>>{});
}

template <fixed_string Bad, fixed_string... Valid>
struct soa_column_not_found {
  static constexpr bool value = false;
};

template <fixed_string Bad, class... Cols>
consteval void diagnose_unknown_soa_column(std::tuple<Cols...>) {
  static_assert(soa_column_not_found<Bad, Cols::name...>::value,
                "nanom::soa: unknown column name (see soa_column_not_found template args for valid names)");
}

}  // namespace detail

/// Column-oriented accumulator: push() decomposes each struct into flat,
/// host-order leaf columns; full chunks are sealed at chunk_rows so buffers
/// can be handed to ArrowArray / Lance fragment writers without a transpose.
/// Nested described structs are flattened with dotted names; byte arrays
/// become fixed-size binary columns; bit fields widen to their decoded type.
template <Described T>
class soa {
 public:
  struct column_info {
    std::string  name;        ///< flattened, dotted
    dkind        kind;        ///< scalar kind, or fixed_bin
    std::size_t  elem_bytes;  ///< bytes per row in this column
    std::string  arrow;       ///< Arrow C data interface format string
  };
  struct chunk {
    std::size_t                         rows = 0;
    std::vector<std::vector<std::byte>> cols;   ///< one contiguous buffer per column
    bytes col(std::size_t i) const { return {cols[i].data(), cols[i].size()}; }
    /// Typed access; V must match the column's decoded type.
    template <class V>
    std::span<const V> as(std::size_t i) const {
      return std::span<const V>(reinterpret_cast<const V*>(cols[i].data()), rows);
    }
    /// Compile-time named raw column access (supports top-level and dotted nested names).
    template <fixed_string Name>
    bytes column() const {
      using Cols = detail::soa_columns_of_t<T>;
      constexpr std::size_t I = detail::soa_col_index<Cols, Name>();
      if constexpr (I == std::size_t(-1)) {
        detail::diagnose_unknown_soa_column<Name>(Cols{});
        return {};
      } else {
        return col(I);
      }
    }
    /// Compile-time named typed span access (deduces the column's decoded type V).
    template <fixed_string Name>
    auto span() const {
      using Cols = detail::soa_columns_of_t<T>;
      constexpr std::size_t I = detail::soa_col_index<Cols, Name>();
      if constexpr (I == std::size_t(-1)) {
        detail::diagnose_unknown_soa_column<Name>(Cols{});
        return std::span<const std::byte>{};
      } else {
        using V = typename std::tuple_element_t<I, Cols>::type;
        return as<V>(I);
      }
    }
  };

  explicit soa(std::size_t chunk_rows = 65536) : chunk_rows_(chunk_rows) {
    build_columns<T>("");
    init_open();
  }

  const std::vector<column_info>& columns() const { return columns_; }
  std::size_t rows() const { return sealed_rows_ + open_.rows; }

  void push(const T& v) {
    std::size_t c = 0;
    push_fields(v, c);
    if (++open_.rows == chunk_rows_) seal();
  }

  /// Decode directly from a zero-copy view<T> into columns without materializing an intermediate T.
  void push(view<T> v) {
    detail::guard_view_pointer(v.p);
#if NANOM_GENERATION
    detail::check_wire_access(v.arena, v.gen, v.p, wire_size_v<T>, "soa::push(view)");
#endif
    std::size_t c = 0;
    push_view_fields<T, 0>(v.p, v.dflt, c);
    if (++open_.rows == chunk_rows_) seal();
  }

  /// Visit every chunk (sealed ones, then the open remainder if non-empty).
  template <class F>
  void for_each_chunk(F&& f) const {
    for (const auto& ch : sealed_) f(ch);
    if (open_.rows) f(open_);
  }

  /// Random access to the same chunk sequence `for_each_chunk` visits, in the same order: indices
  /// `[0, chunk_count())` are the sealed chunks followed by the open remainder when it is non-empty.
  ///
  /// `for_each_chunk` is a push-only visitor, which is all a sink writer needs but which cannot be
  /// composed with anything. With an index and a subscript, a caller can build whatever range it
  /// wants over the chunks without this header taking a dependency on <ranges>:
  ///
  ///     auto chunks = std::views::iota(std::size_t{0}, t.chunk_count())
  ///                 | std::views::transform([&](std::size_t i) -> const auto& {
  ///                     return t.chunk_at(i);
  ///                   });
  ///
  /// Deliberately chunk-level, not row-level: `soa<T>` never materializes a `T`, so a row range
  /// would have to reconstruct one per row and undo the whole point of the layout. Filtering
  /// happens over row INDICES inside a chunk, against that chunk's own column spans -- see
  /// docs/NANO_SHARK.md, "Composing with std::views".
  std::size_t chunk_count() const { return sealed_.size() + (open_.rows ? 1 : 0); }
  const chunk& chunk_at(std::size_t i) const {
    return i < sealed_.size() ? sealed_[i] : open_;
  }

  /// Force-seal the open chunk (e.g. before a final flush).
  void seal() {
    if (!open_.rows) return;
    sealed_rows_ += open_.rows;
    sealed_.push_back(std::move(open_));
    init_open();
  }

 private:
  void init_open() {
    open_ = {};
    open_.cols.resize(columns_.size());
    const std::size_t cap_rows = std::min<std::size_t>(chunk_rows_, 65536);
    for (std::size_t i = 0; i < columns_.size(); ++i)
      open_.cols[i].reserve(cap_rows * columns_[i].elem_bytes);
  }

  template <class F>
  void build_columns(std::string prefix, std::string_view name = "") {
    if constexpr (Described<F>) {
      build_nested<F>(name.empty() ? prefix : prefix + std::string(name) + ".");
    } else {
      schema_field s = detail::field_schema<F>(name);
      column_info ci;
      ci.name = prefix + std::string(name);
      if (s.kind == dkind::fixed_bin || s.kind == dkind::list) {
        // store fixed lists as flat fixed-size binary (elem×len bytes per row)
        ci.kind = dkind::fixed_bin;
        ci.elem_bytes = detail::wire<F>::bits / 8;
        schema_field bin = s;
        bin.kind = dkind::fixed_bin;
        bin.size = std::uint32_t(ci.elem_bytes);
        ci.arrow = arrow_format(bin);
      } else {
        ci.kind = s.kind;
        ci.elem_bytes = sizeof(typename detail::wire<F>::decoded);
        ci.arrow = arrow_format(s);
      }
      columns_.push_back(std::move(ci));
    }
  }
  template <class F>
  void build_nested(std::string prefix) {
    detail::for_each_field<F>([&](auto f) {
      build_columns<detail::member_t<decltype(f)::mem_ptr>>(prefix, decltype(f)::name.sv());
    });
  }

  static NANOM_ALWAYS_INLINE void append_bytes(std::vector<std::byte>& col, const void* src,
                                               std::size_t n) {
    const std::size_t off = col.size();
    col.resize(off + n);
    std::memcpy(col.data() + off, src, n);
  }

  template <class F>
  NANOM_ALWAYS_INLINE void push_one(const F& v, std::size_t& c) {
    if constexpr (Described<F>) {
      push_fields(v, c);
    } else if constexpr (detail::is_byte_array_v<F>) {
      append_bytes(open_.cols[c++], v.data(), v.size());
    } else if constexpr (detail::is_std_array_v<F>) {
      using ED = typename detail::wire<typename F::value_type>::decoded;
      auto& col = open_.cols[c++];
      const std::size_t off = col.size();
      col.resize(off + v.size() * sizeof(ED));
      std::byte* dst = col.data() + off;
      for (std::size_t i = 0; i < v.size(); ++i) {
        ED d = ED(v[i]);
        std::memcpy(dst + i * sizeof(ED), &d, sizeof(ED));
      }
    } else {
      using D = typename detail::wire<F>::decoded;
      D d = D(v);
      append_bytes(open_.cols[c++], &d, sizeof(D));
    }
  }
  template <class F, std::size_t... I>
  NANOM_ALWAYS_INLINE void push_fields_impl(const F& v, std::size_t& c, std::index_sequence<I...>) {
    constexpr auto fs = describe<F>::fields();
    (push_one(v.*(std::tuple_element_t<I, decltype(fs)>::mem_ptr), c), ...);
  }
  template <class F>
  NANOM_ALWAYS_INLINE void push_fields(const F& v, std::size_t& c) {
    push_fields_impl(v, c, std::make_index_sequence<detail::field_count_v<F>>{});
  }

  template <class F, std::size_t BitOff>
  NANOM_ALWAYS_INLINE void push_view_one(const std::byte* p, std::endian dflt, std::size_t& c) {
    if constexpr (Described<F>) {
      push_view_fields<F, BitOff>(p, dflt, c);
    } else if constexpr (detail::is_byte_array_v<F>) {
      append_bytes(open_.cols[c++], p + BitOff / 8, std::tuple_size_v<F>);
    } else if constexpr (detail::is_std_array_v<F>) {
      using E = typename F::value_type;
      using ED = typename detail::wire<E>::decoded;
      constexpr std::size_t eb = detail::wire<E>::bits;
      constexpr std::size_t n = std::tuple_size_v<F>;
      auto& col = open_.cols[c++];
      const std::size_t off = col.size();
      col.resize(off + n * sizeof(ED));
      std::byte* dst = col.data() + off;
      for (std::size_t i = 0; i < n; ++i) {
        ED d = detail::decode_field<E>(p, BitOff + i * eb, dflt);
        std::memcpy(dst + i * sizeof(ED), &d, sizeof(ED));
      }
    } else {
      using D = typename detail::wire<F>::decoded;
      D d = detail::decode_field_at<F, BitOff>(p, dflt);
      append_bytes(open_.cols[c++], &d, sizeof(D));
    }
  }
  template <class F, std::size_t BaseBitOff, std::size_t... I>
  NANOM_ALWAYS_INLINE void push_view_fields_impl(const std::byte* p, std::endian dflt,
                                                 std::size_t& c, std::index_sequence<I...>) {
    constexpr auto fs = describe<F>::fields();
    constexpr auto offs = detail::field_bit_offsets<F>();
    (push_view_one<detail::member_t<std::tuple_element_t<I, decltype(fs)>::mem_ptr>,
                   BaseBitOff + offs[I]>(p, dflt, c),
     ...);
  }
  template <class F, std::size_t BaseBitOff>
  NANOM_ALWAYS_INLINE void push_view_fields(const std::byte* p, std::endian dflt, std::size_t& c) {
    push_view_fields_impl<F, BaseBitOff>(p, dflt, c,
                                         std::make_index_sequence<detail::field_count_v<F>>{});
  }

  std::size_t              chunk_rows_;
  std::vector<column_info> columns_;
  std::vector<chunk>       sealed_;
  chunk                    open_;
  std::size_t              sealed_rows_ = 0;
};
}  // namespace nanom

#endif  // NANOM_SOA_HPP_INCLUDED
