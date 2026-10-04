// SPDX-License-Identifier: Apache-2.0
// nanom/columnar.hpp — decode kernels for columnar page encodings (Parquet; Lance shares several).
//
// These are the inner loops of a column reader: they turn encoded page bytes into flat, host-order
// value buffers. Every kernel follows one safety rule — CHECK AT THE BOUNDARY, RUN UNCHECKED INSIDE:
// sizes and counts taken from the wire are validated once, against the input span and the caller's
// output span, before the loop; the loop itself never reads past what was proven present and never
// writes past the output. A kernel that cannot finish reports how far it got instead of guessing.
//
//   unpack_bits<U>       LSB-first bit-packed integers (Parquet BIT_PACKED groups, RLE-hybrid runs,
//                        delta miniblocks). The bit width is a TEMPLATE parameter inside the loop:
//                        one runtime switch selects a loop specialized for that width.
//   rle_bp_decoder       Parquet's RLE / bit-packed hybrid (definition/repetition levels, dictionary
//                        indices, RLE booleans), streaming in caller-sized batches.
//   delta_binary_packed  DELTA_BINARY_PACKED (int32 / int64), also the length stream of
//                        DELTA_LENGTH_BYTE_ARRAY and DELTA_BYTE_ARRAY.
//   byte_stream_split    BYTE_STREAM_SPLIT (floats, doubles, any fixed width).
//   unpack_bool_bitmap   PLAIN booleans: LSB-first bits, already Arrow's bitmap layout (copy/shift).
#ifndef NANOM_COLUMNAR_HPP_INCLUDED
#define NANOM_COLUMNAR_HPP_INCLUDED

#include "nom.hpp"

namespace nanom::columnar {

// ---------------------------------------------------------------------------
// 26. bit unpacking (LSB-first, Parquet order)
// ---------------------------------------------------------------------------

namespace detail {

inline std::uint64_t load_le64(const std::uint8_t* p) {
  std::uint64_t v;
  std::memcpy(&v, p, 8);
  if constexpr (std::endian::native == std::endian::big) v = std::byteswap(v);
  return v;
}

/// Unpack 8 values of W bits from `in` (which must have W + 8 readable bytes: the group's W bytes
/// plus slack for the 64-bit loads — callers guarantee it or copy the tail into a padded buffer).
template <class U, unsigned W>
inline void unpack8(const std::uint8_t* in, U* out) {
  if constexpr (W == 0) {
    for (int i = 0; i < 8; ++i) out[i] = 0;
  } else if constexpr (W <= 56) {
    constexpr std::uint64_t mask = W == 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << W) - 1;
    for (unsigned i = 0; i < 8; ++i) {
      const unsigned bit = i * W;
      out[i] = U((load_le64(in + bit / 8) >> (bit % 8)) & mask);
    }
  } else {
    // widths 57..64 can straddle 9 bytes: assemble from two loads
    constexpr std::uint64_t mask = W == 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << W) - 1;
    for (unsigned i = 0; i < 8; ++i) {
      const unsigned bit = i * W, sh = bit % 8;
      const std::uint64_t lo = load_le64(in + bit / 8);
      const std::uint64_t hi = sh ? std::uint64_t(in[bit / 8 + 8]) << (64 - sh) : 0;
      out[i] = U(((lo >> sh) | hi) & mask);
    }
  }
}

/// Unpack `groups` groups of 8 W-bit values. `in_len` is what is readable at `in`.
template <class U, unsigned W>
inline void unpack_groups(const std::uint8_t* in, std::size_t in_len, U* out, std::size_t groups) {
  std::size_t g = 0;
  // fast path: enough slack for the unchecked 64-bit loads
  const std::size_t safe = in_len >= W + 8 ? (in_len - (W + 8)) / (W ? W : 1) + 1 : 0;
  const std::size_t fast = W == 0 ? groups : std::min(groups, safe);
  for (; g < fast; ++g) unpack8<U, W>(in + g * W, out + g * 8);
  // tail: copy the group into a zero-padded buffer
  for (; g < groups; ++g) {
    std::uint8_t buf[64 + 16]{};
    const std::size_t at = g * W;
    const std::size_t have = at < in_len ? std::min<std::size_t>(W, in_len - at) : 0;
    if (have) std::memcpy(buf, in + at, have);
    unpack8<U, W>(buf, out + g * 8);
  }
}

template <class U>
using unpack_fn = void (*)(const std::uint8_t*, std::size_t, U*, std::size_t);

template <class U, std::size_t... W>
constexpr auto make_unpack_table(std::index_sequence<W...>) {
  return std::array<unpack_fn<U>, sizeof...(W)>{&unpack_groups<U, unsigned(W)>...};
}
template <class U>
inline constexpr auto unpack_table = make_unpack_table<U>(std::make_index_sequence<8 * sizeof(U) + 1>{});

}  // namespace detail

/// Unpack `n` W-bit LSB-first values from `in` into `out` (n rounded up to whole groups of 8 is
/// what gets READ; exactly n values are WRITTEN). Returns false — writing nothing — when `width`
/// exceeds U's bits, `out` is too small, or `in` holds fewer than ceil(n * width / 8) bytes.
template <class U>
  requires(std::same_as<U, std::uint32_t> || std::same_as<U, std::uint64_t>)
inline bool unpack_bits(std::span<const std::byte> in, unsigned width, std::span<U> out, std::size_t n) {
  if (width > 8 * sizeof(U) || out.size() < n) return false;
  const std::uint64_t need_bits = std::uint64_t(n) * width;
  if (in.size() < (need_bits + 7) / 8) return false;
  const auto* src = reinterpret_cast<const std::uint8_t*>(in.data());
  const std::size_t full = n / 8;
  detail::unpack_table<U>[width](src, in.size(), out.data(), full);
  if (const std::size_t rem = n % 8) {
    U tmp[8];
    const std::size_t at = full * width;
    detail::unpack_table<U>[width](src + at, in.size() - at, tmp, 1);
    for (std::size_t i = 0; i < rem; ++i) out[full * 8 + i] = tmp[i];
  }
  return true;
}

// ---------------------------------------------------------------------------
// 27. RLE / bit-packed hybrid (Parquet levels, dictionary indices, RLE booleans)
// ---------------------------------------------------------------------------

/// Streaming decoder for the RLE / bit-packed hybrid:
///   run header (ULEB128): LSB 1 -> bit-packed run of (header >> 1) groups of 8 values
///                         LSB 0 -> RLE run of (header >> 1) copies of one value stored in
///                                  ceil(width / 8) little-endian bytes
/// get() fills up to n values and returns how many it produced; fewer than asked means the data
/// ended (or was malformed: check ok()). Run lengths come from the wire and are never trusted to
/// size anything: a run is consumed only as far as the caller asks. A final bit-packed run that is
/// shorter than its header claims (some writers truncate the padding) yields what is present.
class rle_bp_decoder {
 public:
  rle_bp_decoder() = default;
  rle_bp_decoder(std::span<const std::byte> data, unsigned width)
      : p_(data.data()), e_(data.data() + data.size()), width_(width), ok_(width <= 32) {}

  bool     ok()    const { return ok_; }
  unsigned width() const { return width_; }

  std::size_t get(std::uint32_t* out, std::size_t n) {
    std::size_t done = 0;
    while (done < n && ok_) {
      if (rle_left_) {
        const std::size_t k = std::min<std::size_t>(rle_left_, n - done);
        std::fill_n(out + done, k, rle_value_);
        rle_left_ -= k;
        done += k;
      } else if (bp_left_) {
        done += take_bitpacked(out + done, n - done);
      } else if (!next_run()) {
        break;
      }
    }
    return done;
  }

  /// One run of the stream, exposed without expanding it (for consumers that can act on whole
  /// runs: an RLE run of definition levels is a range fill, a bit-packed run of width-1 levels IS a
  /// validity bitmap).
  struct run {
    bool             packed = false;  ///< bit-packed (true) or RLE (false)
    std::uint32_t    value  = 0;      ///< RLE: the repeated value
    std::size_t      count  = 0;      ///< values in this run (at most what the caller asked for)
    std::span<const std::byte> bits;  ///< packed: the run's bytes, first value at bit `bit_offset`
    std::size_t      bit_offset = 0;
  };
  /// Next run, truncated to at most `max_values`. Returns false at the end of the data (or on
  /// malformed input: check ok()). Interleaves correctly with get().
  bool next_run(run& r, std::size_t max_values) {
    while (ok_ && max_values) {
      if (rle_left_) {
        r.packed = false;
        r.value = rle_value_;
        r.count = std::min(rle_left_, max_values);
        rle_left_ -= r.count;
        return true;
      }
      if (bp_left_) {
        r.packed = true;
        r.count = std::min(bp_left_, max_values);
        const std::size_t bit = bp_pos_ * width_;
        r.bits = std::span<const std::byte>(bp_ + bit / 8, bp_bytes_ - bit / 8);
        r.bit_offset = bit % 8;
        bp_pos_ += r.count;
        bp_left_ -= r.count;
        return true;
      }
      if (!next_run()) return false;
    }
    return false;
  }

  /// Skip n values (returns how many were skipped).
  std::size_t skip(std::size_t n) {
    std::uint32_t buf[256];
    std::size_t done = 0;
    while (done < n) {
      const std::size_t k = get(buf, std::min<std::size_t>(256, n - done));
      if (!k) break;
      done += k;
    }
    return done;
  }

 private:
  bool next_run() {
    if (p_ >= e_) return false;
    std::uint64_t h = 0;
    {
      const input in = from(std::span<const std::byte>(p_, std::size_t(e_ - p_)));
      auto r = varint_u64(in);
      if (!r) { ok_ = false; return false; }
      h = r->value;
      p_ = r->rest.first;
    }
    if (h & 1) {
      const std::uint64_t groups = h >> 1;
      // values actually present: whole bytes available limit the run
      const std::size_t bytes_avail = std::size_t(e_ - p_);
      // groups comes from the wire: clamp before multiplying (each group is >= 1 byte at width > 0)
      const std::uint64_t want_bytes = groups > bytes_avail ? std::uint64_t(bytes_avail) * width_ : groups * width_;
      const std::size_t run_bytes = std::size_t(std::min<std::uint64_t>(want_bytes, bytes_avail));
      bp_left_ = width_ ? std::size_t(std::min<std::uint64_t>(groups * 8, std::uint64_t(run_bytes) * 8 / width_))
                        : std::size_t(std::min<std::uint64_t>(groups * 8, std::uint64_t(1) << 40));
      bp_ = p_;
      bp_bytes_ = run_bytes;
      bp_pos_ = 0;
      p_ += run_bytes;
      if (groups == 0) return true;  // empty run: legal, move on
    } else {
      const std::size_t vbytes = (width_ + 7) / 8;
      if (std::size_t(e_ - p_) < vbytes) { ok_ = false; return false; }
      std::uint32_t v = 0;
      for (std::size_t i = 0; i < vbytes; ++i) v |= std::uint32_t(std::uint8_t(p_[i])) << (8 * i);
      if (width_ < 32 && (v >> width_) != 0) { ok_ = false; return false; }  // value wider than width
      p_ += vbytes;
      rle_value_ = v;
      rle_left_ = std::size_t(std::min<std::uint64_t>(h >> 1, std::uint64_t(1) << 40));
    }
    return true;
  }

  std::size_t take_bitpacked(std::uint32_t* out, std::size_t n) {
    // bp_pos_ counts values consumed from this run; decode whole groups through a small buffer
    // when not group-aligned, directly into out otherwise
    std::size_t done = 0;
    while (done < n && bp_left_) {
      const std::size_t in_group = bp_pos_ % 8;
      const std::size_t group_byte = (bp_pos_ / 8) * width_;
      const auto in = std::span<const std::byte>(bp_ + group_byte, bp_bytes_ - group_byte);
      if (in_group == 0 && n - done >= 8 && bp_left_ >= 8) {
        const std::size_t groups = std::min(n - done, bp_left_) / 8;
        unpack_bits<std::uint32_t>(in, width_, std::span<std::uint32_t>(out + done, groups * 8), groups * 8);
        done += groups * 8;
        bp_pos_ += groups * 8;
        bp_left_ -= groups * 8;
      } else {
        std::uint32_t g[8];
        const std::size_t avail_in_group = std::min<std::size_t>(8, bp_left_ + in_group);
        detail::unpack_table<std::uint32_t>[width_](reinterpret_cast<const std::uint8_t*>(in.data()),
                                                    in.size(), g, 1);
        const std::size_t k = std::min(avail_in_group - in_group, n - done);
        for (std::size_t i = 0; i < k; ++i) out[done + i] = g[in_group + i];
        done += k;
        bp_pos_ += k;
        bp_left_ -= k;
      }
    }
    return done;
  }

  const std::byte* p_ = nullptr;
  const std::byte* e_ = nullptr;
  unsigned width_ = 0;
  bool ok_ = false;
  std::uint32_t rle_value_ = 0;
  std::size_t rle_left_ = 0;
  const std::byte* bp_ = nullptr;
  std::size_t bp_bytes_ = 0, bp_pos_ = 0, bp_left_ = 0;
};

// ---------------------------------------------------------------------------
// 28. DELTA_BINARY_PACKED (int32 / int64)
// ---------------------------------------------------------------------------

/// Decode the first `n` values of a DELTA_BINARY_PACKED stream into out. Returns the number of
/// input bytes consumed through the miniblock holding value n (with n == the stream's total count,
/// that is the stream's end — what DELTA_LENGTH_BYTE_ARRAY needs to find the bytes that follow), or
/// nullopt when the stream is malformed or declares fewer than n values. Arithmetic wraps (the
/// encoding is defined modulo 2^bits), so no signed overflow is ever executed.
template <class T>
  requires(std::same_as<T, std::int32_t> || std::same_as<T, std::int64_t>)
inline std::optional<std::size_t> delta_binary_packed(std::span<const std::byte> in, std::span<T> out,
                                                      std::size_t n) {
  using U = std::make_unsigned_t<T>;
  if (out.size() < n) return std::nullopt;
  input cur = from(in);
  auto rd = [&](std::uint64_t& v) {
    auto r = varint_u64(cur);
    if (!r) return false;
    v = r->value;
    cur = r->rest;
    return true;
  };
  std::uint64_t block_size = 0, minis = 0, total = 0, first_zz = 0;
  if (!rd(block_size) || !rd(minis) || !rd(total) || !rd(first_zz)) return std::nullopt;
  if (block_size == 0 || block_size % 128 != 0 || minis == 0 || block_size % minis != 0 ||
      (block_size / minis) % 32 != 0 || block_size > (1u << 20))
    return std::nullopt;
  if (total < n) return std::nullopt;
  const std::size_t per_mini = std::size_t(block_size / minis);
  if (n == 0) return std::size_t(cur.first - in.data());
  U last = U(zigzag_decode(first_zz));
  out[0] = std::bit_cast<T>(last);
  std::size_t produced = 1;
  std::uint64_t unpacked[1024];  // miniblocks are decoded in chunks of at most 1024 values
  while (produced < n) {
    std::uint64_t min_zz = 0;
    if (!rd(min_zz)) return std::nullopt;
    const U min_delta = U(zigzag_decode(min_zz));
    if (cur.size() < minis) return std::nullopt;
    const std::byte* widths = cur.first;
    cur = cur.advance(std::size_t(minis));
    for (std::size_t m = 0; m < minis && produced < n; ++m) {
      const unsigned w = std::uint8_t(widths[m]);
      if (w > 8 * sizeof(T)) return std::nullopt;
      const std::size_t mini_bytes = per_mini * w / 8;
      const std::size_t need_vals = std::min(per_mini, n - produced);
      const std::size_t need_bytes = (need_vals * w + 7) / 8;
      if (cur.size() < need_bytes) return std::nullopt;
      // decode in chunks of up to 1024 values (per_mini may exceed that for huge blocks)
      std::size_t done = 0;
      while (done < need_vals) {
        const std::size_t k = std::min<std::size_t>(1024, need_vals - done);
        const std::size_t off_bytes = done * w / 8;  // done is a multiple of 1024 -> byte aligned
        if (!unpack_bits<std::uint64_t>(std::span<const std::byte>(cur.first + off_bytes, cur.size() - off_bytes), w,
                                        std::span<std::uint64_t>(unpacked, k), k))
          return std::nullopt;
        for (std::size_t i = 0; i < k; ++i) {
          last = U(last + min_delta + U(unpacked[i]));
          out[produced++] = std::bit_cast<T>(last);
        }
        done += k;
      }
      // a miniblock that held values is padded to full size on the wire (the last may be cut short)
      cur = cur.advance(std::min(mini_bytes, cur.size()));
    }
  }
  return std::size_t(cur.first - in.data());
}

// ---------------------------------------------------------------------------
// 29. BYTE_STREAM_SPLIT and PLAIN booleans
// ---------------------------------------------------------------------------

/// BYTE_STREAM_SPLIT: `width` streams of n bytes each -> n interleaved values of `width` bytes.
inline bool byte_stream_split(std::span<const std::byte> in, std::size_t width, std::size_t n,
                              std::span<std::byte> out) {
  if (width == 0 || n > std::numeric_limits<std::size_t>::max() / width) return false;
  const std::size_t total = n * width;
  if (in.size() < total || out.size() < total) return false;
  const std::byte* src = in.data();
  std::byte* dst = out.data();
  if (width == 4) {  // the float case, unrolled
    for (std::size_t i = 0; i < n; ++i) {
      dst[4 * i + 0] = src[i];
      dst[4 * i + 1] = src[n + i];
      dst[4 * i + 2] = src[2 * n + i];
      dst[4 * i + 3] = src[3 * n + i];
    }
  } else if (width == 8) {
    for (std::size_t i = 0; i < n; ++i)
      for (std::size_t b = 0; b < 8; ++b) dst[8 * i + b] = src[b * n + i];
  } else {
    for (std::size_t b = 0; b < width; ++b)
      for (std::size_t i = 0; i < n; ++i) dst[width * i + b] = src[b * n + i];
  }
  return true;
}

/// Copy n LSB-first bits starting at bit 0 of `in` into a bitmap at bit offset `dst_bit` of `out`.
/// PLAIN booleans are already Arrow's validity/boolean layout: a byte-aligned destination is one
/// memcpy, otherwise a shift-merge per byte.
inline bool copy_bits(std::span<const std::byte> in, std::size_t n, std::span<std::byte> out,
                      std::size_t dst_bit) {
  if (in.size() < (n + 7) / 8) return false;
  if (dst_bit > std::numeric_limits<std::size_t>::max() - n || out.size() < (dst_bit + n + 7) / 8)
    return false;
  if (n == 0) return true;
  const auto* s = reinterpret_cast<const std::uint8_t*>(in.data());
  auto* d = reinterpret_cast<std::uint8_t*>(out.data());
  if (dst_bit % 8 == 0) {
    const std::size_t full = n / 8;
    std::memcpy(d + dst_bit / 8, s, full);
    if (const std::size_t rem = n % 8) {
      const std::uint8_t mask = std::uint8_t((1u << rem) - 1);
      std::uint8_t& t = d[dst_bit / 8 + full];
      t = std::uint8_t((t & ~mask) | (s[full] & mask));
    }
    return true;
  }
  // unaligned destination: every output byte takes the high bits of one source byte and the low
  // bits of the next. Fill the partial first byte, then whole output words, then the tail.
  const unsigned sh = unsigned(dst_bit % 8);   // destination bit offset in its byte
  std::uint8_t* o = d + dst_bit / 8;
  {
    const std::size_t head = std::min<std::size_t>(n, 8 - sh);
    const std::uint8_t mask = std::uint8_t(((1u << head) - 1) << sh);
    *o = std::uint8_t((*o & ~mask) | ((s[0] << sh) & mask));
    if (n == head) return true;
    ++o;
  }
  // the rest is byte-aligned in the output: output byte q holds source bits [8q + k, 8q + k + 8)
  const unsigned k = 8 - sh;                   // 1..7 source bits went into the first byte
  std::size_t left = n - k, p = 0;
  const std::size_t in_bytes = (n + 7) / 8;
  while (left >= 64 && p + 9 <= in_bytes) {
    std::uint64_t w;
    std::memcpy(&w, s + p, 8);
    w = (w >> k) | (std::uint64_t(s[p + 8]) << (64 - k));
    std::memcpy(o, &w, 8);
    o += 8;
    p += 8;
    left -= 64;
  }
  while (left >= 8) {  // whole bytes: s[p + 1] exists because k + 8 more bits remain in the source
    *o++ = std::uint8_t((s[p] >> k) | (s[p + 1] << (8 - k)));
    ++p;
    left -= 8;
  }
  if (left) {
    const std::size_t first = p * 8 + k;        // source bit of the tail's first bit
    unsigned v = s[first / 8] >> (first % 8);
    if ((first % 8) + left > 8) v |= unsigned(s[first / 8 + 1]) << (8 - first % 8);
    const std::uint8_t mask = std::uint8_t((1u << left) - 1);
    *o = std::uint8_t((*o & ~mask) | (v & mask));
  }
  return true;
}

}  // namespace nanom::columnar

#endif  // NANOM_COLUMNAR_HPP_INCLUDED
