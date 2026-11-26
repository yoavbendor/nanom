// SPDX-License-Identifier: Apache-2.0
// nanom/soa.hpp — soa<T>, column-oriented (Struct-of-Arrays) chunked storage for a described struct,
// ready to hand to nanoarrow / Lance buffers without a transpose (an "extra", layered on schema.hpp
// for dkind/arrow_format). See also bulk.hpp for the data-parallel (GPU-ready) scatter path.
#ifndef NANOM_SOA_HPP_INCLUDED
#define NANOM_SOA_HPP_INCLUDED

#include "schema.hpp"

#include <new>

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


/// Number of leaf columns soa<T> flattens F into (a nested described struct recurses, everything
/// else -- scalars, be/le, bit fields, fixed arrays -- is one column).
template <class F>
consteval std::size_t soa_leaf_count() {
  if constexpr (Described<F>) {
    std::size_t n = 0;
    for_each_field<F>([&](auto f) { n += soa_leaf_count<member_t<decltype(f)::mem_ptr>>(); });
    return n;
  } else {
    return 1;
  }
}
/// Index of field I's first leaf column among F's leaf columns.
template <class F, std::size_t I>
consteval std::size_t soa_leaf_offset() {
  return []<std::size_t... J>(std::index_sequence<J...>) {
    return (std::size_t{0} + ... + soa_leaf_count<field_type_at<F, J>>());
  }(std::make_index_sequence<I>{});
}
/// Bytes per row of one leaf column of type F.
template <class F>
consteval std::size_t soa_elem_bytes() {
  if constexpr (is_std_array_v<F>) return wire<F>::bits / 8;
  else return sizeof(typename wire<F>::decoded);
}
}  // namespace detail

/// Column-oriented accumulator: push() decomposes each struct into flat,
/// host-order leaf columns; full chunks are sealed at chunk_rows so buffers
/// can be handed to ArrowArray / Lance fragment writers without a transpose.
/// Nested described structs are flattened with dotted names; byte arrays
/// become fixed-size binary columns; bit fields widen to their decoded type.
///
/// The append path is built for per-packet decoding (nanom_shark pushes several rows into dozens
/// of columns for every packet). The column layout is a compile-time fact, so push() is an
/// unrolled sequence of fixed-size stores at `column base + row * width` -- one per leaf, no
/// per-field size check, no per-column growth. A chunk owns ONE allocation holding every column
/// (each 64-byte aligned); the only per-row branch is "is the open chunk full", and the open chunk
/// grows geometrically (256 rows, doubling) up to chunk_rows, after which each new chunk is
/// allocated at the size the previous one reached. A table that never gets a row allocates
/// nothing.
template <Described T>
class soa {
 public:
  /// Number of leaf columns (compile time).
  static constexpr std::size_t column_count = detail::soa_leaf_count<T>();

  struct column_info {
    std::string  name;        ///< flattened, dotted
    dkind        kind;        ///< scalar kind, or fixed_bin
    std::size_t  elem_bytes;  ///< bytes per row in this column
    std::string  arrow;       ///< Arrow C data interface format string
  };

  class chunk;
  /// One column's bytes inside a chunk: a read-only, contiguous `rows * elem_bytes` byte buffer
  /// (the vector<std::byte> it replaces exposed the same data()/size()/begin()/end()/[] reads).
  /// Its storage belongs to the chunk; data() stays valid when the chunk object is moved (e.g. by
  /// the sealed-chunk vector growing), so a sealed chunk's column pointers are stable for the
  /// lifetime of the soa.
  class column_bytes {
   public:
    const std::byte* data() const noexcept { return data_; }
    std::size_t      size() const noexcept { return *rows_ * elem_; }
    bool             empty() const noexcept { return size() == 0; }
    const std::byte* begin() const noexcept { return data_; }
    const std::byte* end() const noexcept { return data_ + size(); }
    std::byte        operator[](std::size_t i) const noexcept { return data_[i]; }
    std::size_t      elem_bytes() const noexcept { return elem_; }

   private:
    friend class soa;
    friend class chunk;
    std::byte*         data_ = nullptr;
    std::size_t        elem_ = 0;
    const std::size_t* rows_ = nullptr;  // the owning chunk's row count
  };

  class chunk {
   public:
    std::size_t               rows = 0;
    std::vector<column_bytes> cols;  ///< one contiguous buffer per column
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

    chunk() = default;
    chunk(chunk&& o) noexcept
        : rows(o.rows), cols(std::move(o.cols)), block_(o.block_), block_bytes_(o.block_bytes_), cap_(o.cap_) {
      o.release_();
      rebind_();
    }
    chunk& operator=(chunk&& o) noexcept {
      if (this != &o) {
        free_();
        rows = o.rows;
        cols = std::move(o.cols);
        block_ = o.block_;
        block_bytes_ = o.block_bytes_;
        cap_ = o.cap_;
        o.release_();
        rebind_();
      }
      return *this;
    }
    chunk(const chunk& o) : rows(o.rows), cols(o.cols), cap_(o.cap_) {
      if (o.block_) {
        block_ = alloc_(o.block_bytes_);
        block_bytes_ = o.block_bytes_;
        std::memcpy(block_, o.block_, o.block_bytes_);
        for (std::size_t c = 0; c < cols.size(); ++c) cols[c].data_ = block_ + (o.cols[c].data_ - o.block_);
      }
      rebind_();
    }
    chunk& operator=(const chunk& o) {
      if (this != &o) *this = chunk(o);
      return *this;
    }
    ~chunk() { free_(); }

   private:
    friend class soa;
    static constexpr std::size_t kAlign = 64;
    static std::byte* alloc_(std::size_t n) {
      return static_cast<std::byte*>(::operator new(n, std::align_val_t{kAlign}));
    }
    void free_() noexcept {
      if (block_) ::operator delete(block_, std::align_val_t{kAlign});
      block_ = nullptr;
    }
    void release_() noexcept {  // a moved-from chunk: empty, owns nothing
      block_ = nullptr;
      block_bytes_ = 0;
      cap_ = 0;
      rows = 0;
      cols.clear();
    }
    void rebind_() noexcept {
      for (auto& c : cols) c.rows_ = &rows;
    }
    std::byte*  block_ = nullptr;  // every column of this chunk, each kAlign-aligned
    std::size_t block_bytes_ = 0;
    std::size_t cap_ = 0;          // rows the block has room for
  };

  explicit soa(std::size_t chunk_rows = 65536) : chunk_rows_(chunk_rows ? chunk_rows : 1) {
    build_columns<T>("");
    for (std::size_t c = 0; c < column_count; ++c) elem_[c] = columns_[c].elem_bytes;
    init_open_();
  }
  soa(const soa& o)
      : chunk_rows_(o.chunk_rows_), columns_(o.columns_), elem_(o.elem_), sealed_(o.sealed_), open_(o.open_),
        sealed_rows_(o.sealed_rows_), next_cap_(o.next_cap_) {
    bind_base_();
  }
  soa(soa&& o) noexcept
      : chunk_rows_(o.chunk_rows_), columns_(std::move(o.columns_)), elem_(o.elem_), sealed_(std::move(o.sealed_)),
        open_(std::move(o.open_)), sealed_rows_(o.sealed_rows_), next_cap_(o.next_cap_) {
    bind_base_();
    o.sealed_rows_ = 0;
    o.init_open_();
  }
  soa& operator=(const soa& o) {
    if (this != &o) *this = soa(o);
    return *this;
  }
  soa& operator=(soa&& o) noexcept {
    if (this != &o) {
      chunk_rows_ = o.chunk_rows_;
      columns_ = std::move(o.columns_);
      elem_ = o.elem_;
      sealed_ = std::move(o.sealed_);
      open_ = std::move(o.open_);
      sealed_rows_ = o.sealed_rows_;
      next_cap_ = o.next_cap_;
      bind_base_();
      o.sealed_rows_ = 0;
      o.init_open_();
    }
    return *this;
  }

  const std::vector<column_info>& columns() const { return columns_; }
  std::size_t rows() const { return sealed_rows_ + open_.rows; }
  std::size_t chunk_rows() const { return chunk_rows_; }

  void push(const T& v) {
    if (open_.rows == open_.cap_) [[unlikely]] grow_();
    put_<0>(v, open_.rows);
    if (++open_.rows == chunk_rows_) [[unlikely]] seal();
  }

  /// Decode directly from a zero-copy view<T> into columns without materializing an intermediate T.
  void push(view<T> v) {
    detail::guard_view_pointer(v.p);
#if NANOM_GENERATION
    detail::check_wire_access(v.arena, v.gen, v.p, wire_size_v<T>, "soa::push(view)");
#endif
    if (open_.rows == open_.cap_) [[unlikely]] grow_();
    put_view_<0, T, 0>(v.p, v.dflt, open_.rows);
    if (++open_.rows == chunk_rows_) [[unlikely]] seal();
  }

  /// Make room for `n` more rows in the open chunk now (capped at chunk_rows), so the next pushes
  /// do not grow it. Purely an optimization; pushes work without it.
  void reserve(std::size_t n) {
    const std::size_t want = std::min(chunk_rows_, open_.rows + n);
    if (want > open_.cap_) regrow_(want);
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
    // the next chunk starts at the size this one reached: a table that fills whole chunks gets
    // chunk_rows at once, one sealed early and often (streaming flushes) stays small
    next_cap_ = std::max(open_.rows, kFirstRows);
    sealed_.push_back(std::move(open_));
    init_open_();
  }

 private:
  static constexpr std::size_t kFirstRows = 256;

  void init_open_() {
    open_ = chunk{};
    open_.cols.resize(column_count);
    for (std::size_t c = 0; c < column_count; ++c) open_.cols[c].elem_ = elem_[c];
    open_.rebind_();
    base_.fill(nullptr);
  }
  void bind_base_() noexcept {
    for (std::size_t c = 0; c < column_count; ++c) base_[c] = c < open_.cols.size() ? open_.cols[c].data_ : nullptr;
  }

  // Cold path: the open chunk is full (or was never allocated).
  void grow_() {
    std::size_t want = open_.cap_ ? open_.cap_ * 2 : next_cap_;
    regrow_(std::min(std::max<std::size_t>(want, 1), chunk_rows_));
  }
  void regrow_(std::size_t cap) {
    std::array<std::size_t, column_count> off{};
    std::size_t total = 0;
    for (std::size_t c = 0; c < column_count; ++c) {
      off[c] = total;
      total += (cap * elem_[c] + chunk::kAlign - 1) / chunk::kAlign * chunk::kAlign;
    }
    std::byte* nb = chunk::alloc_(total ? total : chunk::kAlign);
    for (std::size_t c = 0; c < column_count; ++c) {
      if (open_.rows) std::memcpy(nb + off[c], open_.cols[c].data_, open_.rows * elem_[c]);
      open_.cols[c].data_ = nb + off[c];
      base_[c] = nb + off[c];
    }
    open_.free_();
    open_.block_ = nb;
    open_.block_bytes_ = total;
    open_.cap_ = cap;
  }

  // ---- the append path: one fixed-size store per leaf column, unrolled at compile time ----
  template <std::size_t C, class F>
  void put_(const F& v, std::size_t r) noexcept {
    if constexpr (Described<F>) {
      put_fields_<C>(v, r, std::make_index_sequence<detail::field_count_v<F>>{});
    } else if constexpr (detail::is_std_array_v<F>) {
      using ED = typename detail::wire<typename F::value_type>::decoded;
      std::array<ED, std::tuple_size_v<F>> d;
      for (std::size_t i = 0; i < d.size(); ++i) d[i] = ED(v[i]);
      static_assert(sizeof(d) == detail::soa_elem_bytes<F>());
      std::memcpy(base_[C] + r * sizeof(d), &d, sizeof(d));
    } else {
      using D = typename detail::wire<F>::decoded;
      const D d = D(v);
      std::memcpy(base_[C] + r * sizeof(D), &d, sizeof(D));
    }
  }
  template <std::size_t C, class F, std::size_t... I>
  void put_fields_(const F& v, std::size_t r, std::index_sequence<I...>) noexcept {
    (put_<C + detail::soa_leaf_offset<F, I>()>(
         v.*(std::remove_cvref_t<decltype(std::get<I>(describe<F>::fields()))>::mem_ptr), r),
     ...);
  }

  // the same stores, decoding each leaf straight from the wire bytes at its compile-time offset
  template <std::size_t C, class F, std::size_t BitOff>
  void put_view_(const std::byte* p, std::endian dflt, std::size_t r) noexcept {
    if constexpr (Described<F>) {
      put_view_fields_<C, F, BitOff>(p, dflt, r, std::make_index_sequence<detail::field_count_v<F>>{});
    } else if constexpr (detail::is_byte_array_v<F>) {
      std::memcpy(base_[C] + r * std::tuple_size_v<F>, p + BitOff / 8, std::tuple_size_v<F>);
    } else if constexpr (detail::is_std_array_v<F>) {
      using E = typename F::value_type;
      using ED = typename detail::wire<E>::decoded;
      constexpr std::size_t eb = detail::wire<E>::bits;
      std::array<ED, std::tuple_size_v<F>> d;
      for (std::size_t i = 0; i < d.size(); ++i) d[i] = detail::decode_field<E>(p, BitOff + i * eb, dflt);
      std::memcpy(base_[C] + r * sizeof(d), &d, sizeof(d));
    } else {
      using D = typename detail::wire<F>::decoded;
      const D d = detail::decode_field_at<F, BitOff>(p, dflt);
      std::memcpy(base_[C] + r * sizeof(D), &d, sizeof(D));
    }
  }
  template <std::size_t C, class F, std::size_t BaseBitOff, std::size_t... I>
  void put_view_fields_(const std::byte* p, std::endian dflt, std::size_t r, std::index_sequence<I...>) noexcept {
    constexpr auto offs = detail::field_bit_offsets<F>();
    (put_view_<C + detail::soa_leaf_offset<F, I>(), detail::field_type_at<F, I>, BaseBitOff + offs[I]>(p, dflt, r),
     ...);
  }

  // ---- column metadata (runtime names/Arrow formats, built once) ----
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

  std::size_t                            chunk_rows_;
  std::vector<column_info>               columns_;
  std::array<std::size_t, column_count>  elem_{};
  std::array<std::byte*, column_count>   base_{};  // the open chunk's column starts (hot path)
  std::vector<chunk>                     sealed_;
  chunk                                  open_;
  std::size_t                            sealed_rows_ = 0;
  std::size_t                            next_cap_ = kFirstRows;
};
}  // namespace nanom

#endif  // NANOM_SOA_HPP_INCLUDED
