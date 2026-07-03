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
      return {reinterpret_cast<const V*>(cols[i].data()), rows};
    }
  };

  explicit soa(std::size_t chunk_rows = 65536) : chunk_rows_(chunk_rows) {
    build_columns<T>("");
    open_.cols.resize(columns_.size());
  }

  const std::vector<column_info>& columns() const { return columns_; }
  std::size_t rows() const { return sealed_rows_ + open_.rows; }

  void push(const T& v) {
    std::size_t c = 0;
    push_fields(v, c);
    if (++open_.rows == chunk_rows_) seal();
  }

  /// Visit every chunk (sealed ones, then the open remainder if non-empty).
  template <class F>
  void for_each_chunk(F&& f) const {
    for (const auto& ch : sealed_) f(ch);
    if (open_.rows) f(open_);
  }
  /// Force-seal the open chunk (e.g. before a final flush).
  void seal() {
    if (!open_.rows) return;
    sealed_rows_ += open_.rows;
    sealed_.push_back(std::move(open_));
    open_ = {};
    open_.cols.resize(columns_.size());
  }

 private:
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

  template <class F>
  void push_one(const F& v, std::size_t& c) {
    if constexpr (Described<F>) {
      push_fields(v, c);
    } else if constexpr (detail::is_std_array_v<F>) {
      auto& col = open_.cols[c++];
      for (const auto& e : v) {
        using ED = typename detail::wire<typename F::value_type>::decoded;
        ED d = ED(e);
        const auto* b = reinterpret_cast<const std::byte*>(&d);
        col.insert(col.end(), b, b + sizeof(ED));
      }
    } else {
      using D = typename detail::wire<F>::decoded;
      D d = D(v);
      auto& col = open_.cols[c++];
      const auto* b = reinterpret_cast<const std::byte*>(&d);
      col.insert(col.end(), b, b + sizeof(D));
    }
  }
  template <class F>
  void push_fields(const F& v, std::size_t& c) {
    detail::for_each_field<F>([&](auto f) { push_one(v.*(decltype(f)::mem_ptr), c); });
  }

  std::size_t              chunk_rows_;
  std::vector<column_info> columns_;
  std::vector<chunk>       sealed_;
  chunk                    open_;
  std::size_t              sealed_rows_ = 0;
};
}  // namespace nanom

#endif  // NANOM_SOA_HPP_INCLUDED
