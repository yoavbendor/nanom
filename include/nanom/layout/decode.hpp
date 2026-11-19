// SPDX-License-Identifier: Apache-2.0
// nanom/layout/decode.hpp — columnar decode: N records -> one contiguous typed column per field.
//
// The plan is turned into a `decoder` once (per selection). A decoder is a list of ops, each a
// function pointer to a loop specialized on (load mode, byte order, sign, column type) — so the
// innermost loop of every field is straight-line load/shift/store code with no per-value branch.
// Two schedules run the same ops:
//
//   field_major   records are processed in ~1 MiB blocks (at least 32 records); inside a block
//                 every field runs its own tight strided loop over the block's records (one
//                 indirect call per field per block), writing its column sequentially.
//   record_major  per record, one pass over each op bucket (ops grouped by kernel, sorted by
//                 offset), writing one element into every column.
//
// Measured (docs/LAYOUT.md): field_major wins for both small and huge records — record_major
// writes one element to each of thousands of columns per record, i.e. thousands of distinct pages
// (TLB misses) per record. automatic therefore means field_major.
#ifndef NANOM_LAYOUT_DECODE_HPP_INCLUDED
#define NANOM_LAYOUT_DECODE_HPP_INCLUDED

#include "plan.hpp"

namespace nanom::layout {

enum class strategy : std::uint8_t { automatic, field_major, record_major };

/// Caller-provided output for one selected field: `data` must hold n * storage_size bytes.
struct column_out {
  std::byte* data = nullptr;
  std::size_t bytes = 0;
};

namespace detail {

template <storage S> struct elem_of;
template <> struct elem_of<storage::u8> { using type = std::uint8_t; };
template <> struct elem_of<storage::u16> { using type = std::uint16_t; };
template <> struct elem_of<storage::u32> { using type = std::uint32_t; };
template <> struct elem_of<storage::u64> { using type = std::uint64_t; };
template <> struct elem_of<storage::i8> { using type = std::uint8_t; };
template <> struct elem_of<storage::i16> { using type = std::uint16_t; };
template <> struct elem_of<storage::i32> { using type = std::uint32_t; };
template <> struct elem_of<storage::i64> { using type = std::uint64_t; };
template <> struct elem_of<storage::f32> { using type = std::uint32_t; };
template <> struct elem_of<storage::f64> { using type = std::uint64_t; };
template <> struct elem_of<storage::boolean> { using type = std::uint8_t; };

/// Store kinds: the low 1/2/4/8 bytes of the extracted bits, or a 0/1 byte (booleans).
enum class sk : std::uint8_t { b1, b2, b4, b8, flag };
constexpr sk store_kind(storage s) {
  if (s == storage::boolean) return sk::flag;
  switch (storage_size(s)) { case 1: return sk::b1; case 2: return sk::b2; case 4: return sk::b4; default: return sk::b8; }
}

template <sk K>
inline void put(std::byte* dst, std::uint64_t v) {
  if constexpr (K == sk::flag) { const std::uint8_t b = v != 0; std::memcpy(dst, &b, 1); }
  else if constexpr (K == sk::b1) { const auto x = std::uint8_t(v); std::memcpy(dst, &x, 1); }
  else if constexpr (K == sk::b2) { const auto x = std::uint16_t(v); std::memcpy(dst, &x, 2); }
  else if constexpr (K == sk::b4) { const auto x = std::uint32_t(v); std::memcpy(dst, &x, 4); }
  else std::memcpy(dst, &v, 8);
}
template <sk K> constexpr std::size_t put_size = K == sk::b2 ? 2 : K == sk::b4 ? 4 : K == sk::b8 ? 8 : 1;

/// field-major kernel: one field, n records.
using fm_fn = void (*)(const std::byte* src, std::size_t stride, std::byte* dst, std::size_t n,
                       const access& a);
template <mode M, bool BE, bool Sign, sk K>
void fm_loop(const std::byte* src, std::size_t stride, std::byte* dst, std::size_t n, const access& a0) {
  const access a = a0;  // local copy: the compiler keeps shift/width in registers
  for (std::size_t r = 0; r < n; ++r)
    put<K>(dst + r * put_size<K>, extract_t<M, BE, Sign>(src + r * stride, a));
}

/// record-major op (bound): read at rec + acc.off, write at dst + row * size.
struct rm_op {
  access acc;
  std::byte* dst;
};
/// record-major kernel: all ops of one bucket, one record.
using rm_fn = void (*)(const std::byte* rec, std::size_t row, const rm_op* ops, std::size_t nops);
template <mode M, bool BE, bool Sign, sk K>
void rm_loop(const std::byte* rec, std::size_t row, const rm_op* ops, std::size_t nops) {
  for (std::size_t i = 0; i < nops; ++i)
    put<K>(ops[i].dst + row * put_size<K>, extract_t<M, BE, Sign>(rec, ops[i].acc));
}

struct kernel_pair {
  fm_fn fm;
  rm_fn rm;
  std::uint32_t key;  ///< bucket id: (mode, be, sign, store kind)
};

inline kernel_pair pick_kernel(const access& a, storage st) {
  const sk k = store_kind(st);
  // Sign only matters when bits above `width` are stored: bit-fields, or narrower-than-column
  // loads. Normalising it keeps natural copies on one kernel.
  access n = a;
  if (k == sk::flag || (a.m <= mode::n64 && storage_size(st) * 8 <= a.width)) n.sign = false;
  return dispatch_access(n, [&](auto M, auto B, auto S) {
    constexpr mode m = decltype(M)::value;
    constexpr bool be = decltype(B)::value, sg = decltype(S)::value;
    const std::uint32_t key = std::uint32_t(m) * 20 + (be ? 10 : 0) + (sg ? 5 : 0) + std::uint32_t(k);
    switch (k) {
      case sk::b1: return kernel_pair{&fm_loop<m, be, sg, sk::b1>, &rm_loop<m, be, sg, sk::b1>, key};
      case sk::b2: return kernel_pair{&fm_loop<m, be, sg, sk::b2>, &rm_loop<m, be, sg, sk::b2>, key};
      case sk::b4: return kernel_pair{&fm_loop<m, be, sg, sk::b4>, &rm_loop<m, be, sg, sk::b4>, key};
      case sk::b8: return kernel_pair{&fm_loop<m, be, sg, sk::b8>, &rm_loop<m, be, sg, sk::b8>, key};
      default: return kernel_pair{&fm_loop<m, be, sg, sk::flag>, &rm_loop<m, be, sg, sk::flag>, key};
    }
  });
}

}  // namespace detail

/// A compiled decode program for one selection of one plan. Reusable and thread-safe (run() keeps
/// its scratch on the stack/heap per call).
class decoder {
 public:
  decoder() = default;
  decoder(const plan& p, const selection& s) : stride_(p.stride()) {
    ops_.reserve(s.fields.size());
    for (std::uint32_t slot = 0; slot < s.fields.size(); ++slot) {
      const field& f = p.fields()[s.fields[slot]];
      const auto k = detail::pick_kernel(f.acc, f.st);
      ops_.push_back(op{f.acc, k.fm, k.rm, k.key, slot, f.st});
    }
    // record-major order: by bucket, then offset (sequential reads within a bucket)
    order_.resize(ops_.size());
    for (std::uint32_t i = 0; i < order_.size(); ++i) order_[i] = i;
    std::sort(order_.begin(), order_.end(), [&](auto a, auto b) {
      return ops_[a].key != ops_[b].key ? ops_[a].key < ops_[b].key : ops_[a].acc.off < ops_[b].acc.off;
    });
    fields_ = s.fields;
  }

  std::size_t columns() const { return ops_.size(); }
  storage column_storage(std::size_t slot) const { return ops_[slot].st; }
  std::uint32_t field_index(std::size_t slot) const { return fields_[slot]; }
  std::size_t stride() const { return stride_; }

  /// Records per field-major block: ~block_bytes() of input (L2-resident), but never fewer than
  /// 32 records (per-field loop overhead must amortize, even for 60 KB records) nor more than 16384.
  std::size_t block_records() const {
    return std::clamp<std::size_t>(block_bytes_ / std::max<std::size_t>(stride_, 1), 32, 16384);
  }
  std::size_t block_bytes() const { return block_bytes_; }
  /// Tuning knob: input bytes per field-major block (default 1 MiB; see docs/LAYOUT.md).
  void block_bytes(std::size_t b) { block_bytes_ = std::max<std::size_t>(b, 1); }
  /// automatic = field_major: it won on every layout measured (docs/LAYOUT.md); record_major
  /// stays available for experiments and as a second, independently scheduled implementation.
  strategy resolve(strategy s) const {
    return s == strategy::automatic ? strategy::field_major : s;
  }

  /// Decode records [0, n) of `src` (n * stride bytes must be readable — the caller proves it)
  /// into outs[slot] + row_offset elements. No checks: see plan-level decode_into().
  void run_unchecked(const std::byte* src, std::size_t n, std::span<const column_out> outs,
                     strategy s = strategy::automatic) const {
    if (resolve(s) == strategy::field_major) {
      const std::size_t B = block_records();
      for (std::size_t r0 = 0; r0 < n; r0 += B) {
        const std::size_t nb = std::min(B, n - r0);
        const std::byte* blk = src + r0 * stride_;
        for (const op& o : ops_)
          o.fm(blk, stride_, outs[o.slot].data + r0 * storage_size(o.st), nb, o.acc);
      }
      return;
    }
    // record-major: bind destinations, cut into buckets
    std::vector<detail::rm_op> bound(ops_.size());
    struct bucket { detail::rm_fn fn; std::size_t first, count; };
    std::vector<bucket> buckets;
    for (std::size_t i = 0; i < order_.size(); ++i) {
      const op& o = ops_[order_[i]];
      bound[i] = detail::rm_op{o.acc, outs[o.slot].data};
      if (buckets.empty() || ops_[order_[buckets.back().first]].key != o.key)
        buckets.push_back(bucket{o.rm, i, 0});
      ++buckets.back().count;
    }
    for (std::size_t r = 0; r < n; ++r) {
      const std::byte* rec = src + r * stride_;
      for (const bucket& b : buckets) b.fn(rec, r, bound.data() + b.first, b.count);
    }
  }

 private:
  struct op {
    detail::access acc;
    detail::fm_fn fm;
    detail::rm_fn rm;
    std::uint32_t key;
    std::uint32_t slot;
    storage st;
  };
  std::vector<op> ops_;
  std::vector<std::uint32_t> order_;
  std::vector<std::uint32_t> fields_;
  std::size_t stride_ = 0;
  std::size_t block_bytes_ = std::size_t(1) << 20;
};

/// Records to decode: [first, first + count) clamped to the whole records present.
struct decode_options {
  std::size_t first = 0;
  std::size_t count = std::size_t(-1);
  bool allow_partial = false;  ///< a trailing partial record is an error unless set
  strategy strat = strategy::automatic;
};

/// Library-owned columns: one 64-byte-aligned contiguous buffer per selected field.
class table {
 public:
  std::size_t rows() const { return rows_; }
  std::size_t columns() const { return slots_.size(); }
  std::size_t tail_bytes() const { return tail_; }  ///< bytes of a trailing partial record (ignored)
  std::size_t first_record() const { return first_; }
  const plan& source() const { return *plan_; }

  const field& column_field(std::size_t c) const { return plan_->fields()[slots_[c]]; }
  std::uint32_t field_index(std::size_t c) const { return slots_[c]; }
  storage column_storage(std::size_t c) const { return column_field(c).st; }
  /// Column index of a column/scalar name, or nullopt.
  std::optional<std::size_t> find(std::string_view name) const {
    auto h = plan_->find(name);
    if (!h) return std::nullopt;
    for (std::size_t c = 0; c < slots_.size(); ++c)
      if (slots_[c] == h->index) return c;
    return std::nullopt;
  }
  /// Raw bytes of column c (rows() * storage_size).
  std::span<const std::byte> bytes(std::size_t c) const {
    return {buf_.get() + offs_[c], rows_ * storage_size(column_storage(c))};
  }
  /// Typed column: T must be exactly the column's element type (bool for booleans, int32_t for
  /// Int, uint64_t for pointers, float for Real*4 ...). Mismatch -> empty span.
  template <class T> std::span<const T> column(std::size_t c) const {
    if (c >= slots_.size() || storage_of<T>() != column_storage(c)) return {};
    return {reinterpret_cast<const T*>(buf_.get() + offs_[c]), rows_};
  }
  template <class T> std::span<const T> column(std::string_view name) const {
    auto c = find(name);
    return c ? column<T>(*c) : std::span<const T>{};
  }
  /// One cell as a scalar (enum name, float, ... interpretation included).
  scalar cell(std::size_t row, std::size_t c) const {
    const field& f = column_field(c);
    const std::byte* p = buf_.get() + offs_[c] + row * storage_size(f.st);
    auto ld = [p]<class T>(T) { T x; std::memcpy(&x, p, sizeof x); return x; };
    std::uint64_t v = 0;
    switch (f.st) {
      case storage::i8: v = std::uint64_t(std::int64_t(ld(std::int8_t{}))); break;
      case storage::i16: v = std::uint64_t(std::int64_t(ld(std::int16_t{}))); break;
      case storage::i32: v = std::uint64_t(std::int64_t(ld(std::int32_t{}))); break;
      case storage::u16: v = ld(std::uint16_t{}); break;
      case storage::u32: case storage::f32: v = ld(std::uint32_t{}); break;
      case storage::u64: case storage::i64: case storage::f64: v = ld(std::uint64_t{}); break;
      default: v = ld(std::uint8_t{}); break;
    }
    return scalar{v, f.st, f.fam, std::uint8_t(f.bit_width), f.enums};
  }

  // internal (used by plan-level decode)
  static table make(const plan& p, const selection& s, std::size_t rows, std::size_t first, std::size_t tail) {
    table t;
    t.plan_ = &p;
    t.slots_ = s.fields;
    t.rows_ = rows;
    t.first_ = first;
    t.tail_ = tail;
    std::size_t total = 0;
    for (auto i : s.fields) {
      t.offs_.push_back(total);
      total += (rows * storage_size(p.fields()[i].st) + 63) / 64 * 64;
    }
    t.buf_.reset(static_cast<std::byte*>(::operator new(std::max<std::size_t>(total, 64), std::align_val_t(64))));
    return t;
  }
  std::vector<column_out> outs() {
    std::vector<column_out> o;
    for (std::size_t c = 0; c < slots_.size(); ++c)
      o.push_back(column_out{buf_.get() + offs_[c], rows_ * storage_size(column_storage(c))});
    return o;
  }

 private:
  struct aligned_delete {
    void operator()(std::byte* p) const { ::operator delete(p, std::align_val_t(64)); }
  };
  const plan* plan_ = nullptr;
  std::vector<std::uint32_t> slots_;
  std::vector<std::size_t> offs_;
  std::unique_ptr<std::byte, aligned_delete> buf_;
  std::size_t rows_ = 0, first_ = 0, tail_ = 0;
};

/// The record range decode_options selects, validated against `data`.
struct record_range {
  std::size_t first = 0, count = 0, tail = 0;
};
inline lresult<record_range> resolve_range(const plan& p, std::span<const std::byte> data,
                                           const decode_options& o) {
  const auto rs = p.records(data);
  if (rs.tail_bytes() && !o.allow_partial)
    return lfail(p.raw_file(), 0, 0,
                 "input holds " + std::to_string(rs.size()) + " whole record(s) of " +
                     std::to_string(p.stride()) + " bytes plus a partial record of " +
                     std::to_string(rs.tail_bytes()) + " bytes (wrong stride? set allow_partial to ignore it)");
  record_range r;
  r.tail = rs.tail_bytes();
  r.first = std::min(o.first, rs.size());
  r.count = std::min(o.count, rs.size() - r.first);
  return r;
}

/// Decode into caller-provided columns (outs[i] receives selection field i). Checks every
/// buffer size, then runs unchecked. Returns the number of records decoded.
inline lresult<std::size_t> decode_into(const decoder& dec, const plan& p, std::span<const std::byte> data,
                                        std::span<const column_out> outs, const decode_options& o = {}) {
  auto rr = resolve_range(p, data, o);
  if (!rr) return unexpected<layout_error>(rr.error());
  if (outs.size() != dec.columns())
    return lfail(p.raw_file(), 0, 0, "decode_into: " + std::to_string(outs.size()) + " outputs for " +
                                         std::to_string(dec.columns()) + " columns");
  for (std::size_t c = 0; c < outs.size(); ++c)
    if (outs[c].bytes < rr->count * storage_size(dec.column_storage(c)) || (!outs[c].data && rr->count))
      return lfail(p.raw_file(), 0, 0, "decode_into: output " + std::to_string(c) + " (" +
                                           p.fields()[dec.field_index(c)].column + ") is too small");
  dec.run_unchecked(data.data() + rr->first * p.stride(), rr->count, outs, o.strat);
  return rr->count;
}

/// Decode a selection into a library-owned table.
inline lresult<table> decode(const plan& p, std::span<const std::byte> data, const selection& s,
                             const decode_options& o = {}) {
  auto rr = resolve_range(p, data, o);
  if (!rr) return unexpected<layout_error>(rr.error());
  table t = table::make(p, s, rr->count, rr->first, rr->tail);
  const decoder dec(p, s);
  const auto outs = t.outs();
  dec.run_unchecked(data.data() + rr->first * p.stride(), rr->count, outs, o.strat);
  return t;
}
/// Decode every field.
inline lresult<table> decode(const plan& p, std::span<const std::byte> data, const decode_options& o = {}) {
  return decode(p, data, p.all(), o);
}

}  // namespace nanom::layout

#endif
