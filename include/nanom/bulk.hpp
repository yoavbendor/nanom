// ============================================================================
// nanom/bulk.hpp — data-parallel bulk decode into columnar (SoA) storage.
//
// The model is the one a GPU wants and nanotins uses: a grid of independent
// tasks, one per packet, each decoding its packet and scattering the result
// into pre-sized SoA columns at its own row index — *disjoint* writes, so no
// locks, no atomics, no push_back, no per-task allocation. On CPU the grid is a
// thread pool (`par_exec`); on a device it is a kernel launch. The per-packet
// work (`decode`) and the field scatter (`scatter_row`) are POD, allocation-free
// and NANOM_HD-annotated, so the *same* code compiles for host and device.
//
//   nm::bulk_table<PacketRow> tbl;
//   nm::bulk_decode(packets, tbl, kernel, nm::par_exec{});   // fills columns
//   auto ts = tbl.column<std::uint64_t>("ts_raw");           // contiguous span
//
// where `kernel` is  bool(const nm::pkt_ref&, PacketRow&)  — a device-safe
// function the caller writes with nanom's overlay<>/get<> (see examples).
//
// GPU status: this header is written to be device-compilable (see docs/GPU.md);
// the CPU `par_exec` path is what runs and is benchmarked here. Swapping in a
// CUDA/HIP launcher for the executor is the only remaining step.
// SPDX-License-Identifier: Apache-2.0
// ============================================================================
#ifndef NANOM_BULK_HPP_INCLUDED
#define NANOM_BULK_HPP_INCLUDED

#include "soa.hpp"  // its real dependency: soa<T> column layout + the describe/wire/for_each_field seam
                    // (transitively pulls nom.hpp/reflect.hpp/schema.hpp). bulk stays a separate opt-in.

#include <span>
#include <thread>
#include <vector>

namespace nanom {

/// POD packet descriptor — trivially copyable, safe to memcpy to a device.
/// `data` points into the (device-resident, on GPU) packet buffer.
struct pkt_ref {
  const std::byte* data = nullptr;
  std::uint32_t    len  = 0;
  std::uint32_t    link = 1;  ///< link type (1 = Ethernet), like pcap
};
static_assert(std::is_trivially_copyable_v<pkt_ref>);

/// True when data is non-null or len is zero (empty packet descriptor).
constexpr bool pkt_ref_valid(const pkt_ref& p) noexcept {
  return p.data != nullptr || p.len == 0;
}

namespace detail {

/// Device-safe byte copy (no libc memcpy dependency in device code).
NANOM_HD inline void byte_copy(std::byte* dst, const void* src, std::size_t n) {
  const std::byte* s = reinterpret_cast<const std::byte*>(src);
  for (std::size_t k = 0; k < n; ++k) dst[k] = s[k];
}

/// Scatter one (already-decoded) field of a row into flattened column `c` at
/// row index `i`: writes to col_base[c] + i*elem[c]. Mirrors soa::push_one but
/// index-addressed (disjoint across i) and allocation-free — the device kernel.
template <class F>
NANOM_HD void scatter_one(std::byte* const* col_base, const std::size_t* elem,
                          std::size_t i, std::size_t& c, const F& v) {
  if constexpr (Described<F>) {
    for_each_field<F>([&](auto f) { scatter_one(col_base, elem, i, c, v.*(decltype(f)::mem_ptr)); });
  } else if constexpr (is_std_array_v<F>) {
    using ED = typename wire<typename F::value_type>::decoded;
    std::byte* dst = col_base[c] + i * elem[c];
    std::size_t off = 0;
    for (const auto& x : v) { ED d = ED(x); byte_copy(dst + off, &d, sizeof(ED)); off += sizeof(ED); }
    ++c;
  } else {
    using D = typename wire<F>::decoded;
    D d = D(v);
    byte_copy(col_base[c] + i * elem[c], &d, sizeof(D));
    ++c;
  }
}

}  // namespace detail

/// Scatter a whole decoded row into the columns at index `i`. Device-safe.
template <Described Row>
NANOM_HD void scatter_row(std::byte* const* col_base, const std::size_t* elem,
                          std::size_t i, const Row& r) {
  std::size_t c = 0;
  detail::for_each_field<Row>([&](auto f) {
    detail::scatter_one(col_base, elem, i, c, r.*(decltype(f)::mem_ptr));
  });
}

/// Column-major, index-addressed table: one contiguous buffer per flattened
/// leaf column, pre-sized to N rows. Reuses soa<Row>'s column layout (names,
/// Arrow format strings, element widths). A validity byte per row records
/// whether the kernel produced output (a packet that didn't match decodes to a
/// default row with valid=0). The column buffers are exactly what nanoarrow /
/// Lance import.
template <Described Row>
class bulk_table {
  static_assert(std::is_trivially_copyable_v<Row>,
                "bulk_table Row must be trivially copyable (needed for device transfer)");
 public:
  using column_info = typename soa<Row>::column_info;

  bulk_table() { columns_ = soa<Row>{}.columns(); }

  const std::vector<column_info>& columns() const { return columns_; }
  std::size_t capacity() const { return n_; }

  /// Allocate column storage for exactly n rows (all zero, valid=0).
  void prepare(std::size_t n) {
    n_ = n;
    storage_.assign(columns_.size(), {});
    base_.assign(columns_.size(), nullptr);
    elem_.assign(columns_.size(), 0);
    for (std::size_t c = 0; c < columns_.size(); ++c) {
      storage_[c].assign(n * columns_[c].elem_bytes, std::byte{0});
      base_[c] = storage_[c].data();
      elem_[c] = columns_[c].elem_bytes;
    }
    valid_.assign(n, 0);
  }

  // --- the device-transferable sink (raw pointers a kernel writes through) ---
  std::byte* const*  col_base() const { return base_.data(); }
  const std::size_t* col_elem() const { return elem_.data(); }
  std::uint8_t*      valid()          { return valid_.data(); }
  const std::uint8_t* valid() const   { return valid_.data(); }

  /// Rows the kernel actually produced (valid==1).
  std::size_t rows() const {
    std::size_t k = 0;
    for (auto v : valid_) k += v;
    return k;
  }
  /// Typed view of a column by name (V must match the column's decoded type).
  template <class V>
  std::span<const V> column(std::string_view name) const {
    for (std::size_t c = 0; c < columns_.size(); ++c)
      if (columns_[c].name == name)
        return {reinterpret_cast<const V*>(storage_[c].data()), n_};
    return {};
  }
  bytes column_bytes(std::size_t c) const { return {storage_[c].data(), storage_[c].size()}; }

 private:
  std::vector<column_info>            columns_;
  std::vector<std::vector<std::byte>> storage_;
  std::vector<std::byte*>             base_;
  std::vector<std::size_t>            elem_;
  std::vector<std::uint8_t>           valid_;
  std::size_t                         n_ = 0;
};

// ---------------------------------------------------------------------------
// executors — the "grid". Each runs a functor over [0, n) once per index.
// ---------------------------------------------------------------------------

/// Serial reference executor (also the shape a device kernel body takes).
struct seq_exec {
  template <class F>
  void run(std::size_t n, F&& f) const {
    for (std::size_t i = 0; i < n; ++i) f(i);
  }
};

/// CPU thread-pool executor: partitions [0, n) into `threads` disjoint ranges.
/// This is the CPU stand-in for a GPU grid — same disjoint-write contract.
struct par_exec {
  unsigned threads = 0;  ///< 0 = hardware_concurrency
  template <class F>
  void run(std::size_t n, F&& f) const {
    unsigned t = threads ? threads : std::max(1u, std::thread::hardware_concurrency());
    if (t <= 1 || n < 4096) { for (std::size_t i = 0; i < n; ++i) f(i); return; }
    const std::size_t chunk = (n + t - 1) / t;
    std::vector<std::thread> pool;
    pool.reserve(t);
    for (unsigned k = 0; k < t; ++k) {
      const std::size_t lo = std::size_t(k) * chunk, hi = std::min(n, lo + chunk);
      if (lo >= hi) break;
      pool.emplace_back([&f, lo, hi] { for (std::size_t i = lo; i < hi; ++i) f(i); });
    }
    for (auto& th : pool) th.join();
  }
};

// ---------------------------------------------------------------------------
// the driver: one row per packet, filled in parallel with disjoint writes.
// `kernel(pkt, row) -> bool` decodes packet -> row; false = leave row default
// and mark invalid. Returns the number of valid rows produced.
// ---------------------------------------------------------------------------
template <Described Row, class Kernel, class Exec = par_exec>
std::size_t bulk_decode(std::span<const pkt_ref> pkts, bulk_table<Row>& tbl,
                        Kernel kernel, Exec exec = {}) {
  for (const pkt_ref& pk : pkts)
    if (!pkt_ref_valid(pk)) return 0;
  tbl.prepare(pkts.size());
  std::byte* const* base  = tbl.col_base();
  const std::size_t* elem = tbl.col_elem();
  std::uint8_t*     valid = tbl.valid();
  const pkt_ref*    p      = pkts.data();
  exec.run(pkts.size(), [=](std::size_t i) {
    Row r{};
    if (kernel(p[i], r)) {                // pure, device-safe, no allocation
      scatter_row<Row>(base, elem, i, r);
      valid[i] = 1;
    }
  });
  return tbl.rows();
}

}  // namespace nanom

#endif  // NANOM_BULK_HPP_INCLUDED
