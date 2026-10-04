// SPDX-License-Identifier: Apache-2.0
// nanom/columnar_encode.hpp — WRITE columnar pages: the encoders of nanom/columnar.hpp's decoders.
//
// Every encoder here writes exactly what the matching decoder reads (tests/test_columnar_encode.cpp
// round-trips each one through it, and fuzz/fuzz_columnar_encode.cpp fuzzes the pairs):
//
//   pack_bits<U>          LSB-first bit packing                         <-> unpack_bits<U>
//   rle_hybrid_encode     RLE / bit-packed hybrid (levels, dictionary   <-> rle_bp_decoder
//                         indices, RLE booleans): runs of >= 8 equal values become RLE runs,
//                         everything else bit-packed groups of 8
//   rle_bitmap_encode     the same, straight from a bitmap (width 1: a  <-> rle_bitmap
//                         literal group IS one bitmap byte)
//   delta_binary_packed_encode<T>  DELTA_BINARY_PACKED (int32 / int64) <-> delta_binary_packed<T>
//   byte_stream_split_encode       BYTE_STREAM_SPLIT                   <-> byte_stream_split
//   delta_length_encode            DELTA_LENGTH_BYTE_ARRAY             <-> delta_length_views
//   delta_prefix_encode            DELTA_BYTE_ARRAY (front coding)     <-> delta_prefix_views
//   fixed_dictionary<T>, string_dictionary   dictionary builders (open addressing, exact: values
//                         are compared by their bytes, so -0.0 / +0.0 and NaN payloads stay apart)
//   value_stats / binary_stats               min / max / null count in Parquet's orders
//   fastlanes::pack_1024<T>        FastLanes 1024-value block (Lance)  <-> fastlanes::unpack_1024<T>
//
// Encoders append to a std::vector<std::byte> (the page body before compression). Inputs are the
// caller's values; nothing is read past the spans given. Reading code never includes this header.
#ifndef NANOM_COLUMNAR_ENCODE_HPP_INCLUDED
#define NANOM_COLUMNAR_ENCODE_HPP_INCLUDED

#include "fastlanes.hpp"
#include "values.hpp"

#include <string_view>
#include <vector>

namespace nanom::columnar {

namespace enc_detail {
inline void put_uleb(std::vector<std::byte>& out, std::uint64_t v) {
  std::byte b[leb128_max_bytes<std::uint64_t>];
  const std::size_t n = uleb128_encode(v, b);
  out.insert(out.end(), b, b + n);
}
inline void put_le(std::vector<std::byte>& out, std::uint64_t v, std::size_t nbytes) {
  for (std::size_t i = 0; i < nbytes; ++i) out.push_back(std::byte(std::uint8_t(v >> (8 * i))));
}
}  // namespace enc_detail

// ---------------------------------------------------------------------------
// 45. bit packing
// ---------------------------------------------------------------------------

/// Append the n values of `in` packed LSB-first at `width` bits each: exactly ceil(n * width / 8)
/// bytes. Values must fit in `width` bits (higher bits are masked off).
template <class U>
  requires(std::unsigned_integral<U>)
inline void pack_bits(std::span<const U> in, unsigned width, std::vector<std::byte>& out) {
  if (width == 0 || in.empty()) return;
  const std::uint64_t mask = width >= 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << width) - 1;
  const std::size_t total = (in.size() * width + 7) / 8;
  const std::size_t base = out.size();
  out.resize(base + total + 8);  // + slack for the whole-word stores
  std::byte* o = out.data() + base;
  std::uint64_t acc = 0;
  unsigned bits = 0;
  for (const U x : in) {
    const std::uint64_t v = std::uint64_t(x) & mask;
    acc |= v << bits;
    if (bits + width >= 64) {
      std::memcpy(o, &acc, 8);  // little-endian hosts (static_assert'ed by callers' formats)
      o += 8;
      acc = bits ? v >> (64 - bits) : 0;
      bits = bits + width - 64;
    } else {
      bits += width;
    }
  }
  std::memcpy(o, &acc, 8);
  out.resize(base + total);
}

// ---------------------------------------------------------------------------
// 46. RLE / bit-packed hybrid
// ---------------------------------------------------------------------------

/// Append the RLE / bit-packed hybrid encoding of `values` (each < 2^width) to `out`.
/// A run of >= 8 equal values is an RLE run; values between runs form bit-packed runs of whole
/// groups of 8 (the stream's last group is zero-padded: decoders read only the count they were
/// given). A pending literal run borrows from the next RLE run to finish its group.
template <class V>
  requires(std::unsigned_integral<V>)
inline void rle_hybrid_encode(std::span<const V> values, unsigned width, std::vector<std::byte>& out) {
  const std::size_t n = values.size();
  const std::size_t vbytes = (width + 7) / 8;
  std::size_t lit_begin = 0, lit_end = 0;  // pending literal values [lit_begin, lit_end)
  std::vector<V> pad;
  const auto flush_literal = [&](bool last) {
    const std::size_t count = lit_end - lit_begin;
    if (count == 0) return;
    const std::size_t groups = (count + 7) / 8;
    enc_detail::put_uleb(out, (std::uint64_t(groups) << 1) | 1);
    if (count % 8 == 0 || !last) {
      pack_bits<V>(values.subspan(lit_begin, count), width, out);
    } else {  // the stream's final, partial group: pad with zeros
      pad.assign(values.begin() + std::ptrdiff_t(lit_begin), values.begin() + std::ptrdiff_t(lit_end));
      pad.resize(groups * 8, V(0));
      pack_bits<V>(std::span<const V>(pad), width, out);
    }
    lit_begin = lit_end;
  };
  std::size_t i = 0;
  while (i < n) {
    std::size_t j = i + 1;
    while (j < n && values[j] == values[i]) ++j;
    std::size_t run = j - i;
    if (run >= 8) {
      // finish the pending literal's last group with values from this run
      const std::size_t pending = lit_end - lit_begin;
      if (pending % 8) {
        const std::size_t steal = 8 - pending % 8;
        lit_end += steal;
        i += steal;
        run -= steal;
      }
      if (run >= 8) {
        flush_literal(false);
        enc_detail::put_uleb(out, std::uint64_t(run) << 1);
        enc_detail::put_le(out, std::uint64_t(values[i]), vbytes);
        lit_begin = lit_end = j;
      } else {
        lit_end = j;
      }
    } else {
      if (lit_begin == lit_end) lit_begin = i;
      lit_end = j;
    }
    i = j;
  }
  flush_literal(true);
}

/// The hybrid encoding of n bits of a bitmap (width 1: definition levels of an optional field, RLE
/// booleans). Uniform stretches of >= 2 bytes (16 values) become RLE runs; mixed bytes are literal
/// groups, copied as they are (a width-1 group of 8 values IS one bitmap byte).
inline void rle_bitmap_encode(const std::uint8_t* bm, std::size_t n, std::vector<std::byte>& out) {
  const std::size_t full = n / 8;  // whole bytes; the partial tail goes into the final literal
  std::size_t lit_from = 0;        // first byte of the pending literal
  const auto flush_literal = [&](std::size_t to, bool with_tail) {
    std::size_t groups = to - lit_from + (with_tail ? 1 : 0);
    if (groups == 0) return;
    enc_detail::put_uleb(out, (std::uint64_t(groups) << 1) | 1);
    for (std::size_t b = lit_from; b < to; ++b) out.push_back(std::byte(bm[b]));
    if (with_tail) out.push_back(std::byte(bm[full] & std::uint8_t((1u << (n % 8)) - 1)));
  };
  std::size_t b = 0;
  while (b < full) {
    const std::uint8_t v = bm[b];
    if (v == 0x00 || v == 0xff) {
      std::size_t e = b + 1;
      while (e + 8 <= full) {  // 8 bytes at a time
        std::uint64_t w;
        std::memcpy(&w, bm + e, 8);
        if (w != (v ? ~std::uint64_t(0) : 0)) break;
        e += 8;
      }
      while (e < full && bm[e] == v) ++e;
      if (e - b >= 2) {
        flush_literal(b, false);
        enc_detail::put_uleb(out, std::uint64_t(e - b) * 8 << 1);
        out.push_back(std::byte(v ? 1 : 0));
        lit_from = e;
        b = e;
        continue;
      }
    }
    ++b;
  }
  flush_literal(full, n % 8 != 0);
}

/// Repetition / definition levels (each <= max_level) in the hybrid encoding at
/// bit_width(max_level) bits.
inline void encode_levels(std::span<const std::uint16_t> levels, std::uint16_t max_level, std::vector<std::byte>& out) {
  rle_hybrid_encode<std::uint16_t>(levels, unsigned(std::bit_width(unsigned(max_level))), out);
}

// ---------------------------------------------------------------------------
// 47. DELTA_BINARY_PACKED
// ---------------------------------------------------------------------------

/// Append the DELTA_BINARY_PACKED encoding of `values`: blocks of 128 values in 4 miniblocks of 32
/// (the format's usual shape). Arithmetic wraps modulo 2^bits, exactly as the decoder undoes it.
template <class T>
  requires(std::same_as<T, std::int32_t> || std::same_as<T, std::int64_t>)
inline void delta_binary_packed_encode(std::span<const T> values, std::vector<std::byte>& out) {
  using U = std::make_unsigned_t<T>;
  constexpr std::size_t block = 128, minis = 4, per_mini = block / minis;
  enc_detail::put_uleb(out, block);
  enc_detail::put_uleb(out, minis);
  enc_detail::put_uleb(out, values.size());
  enc_detail::put_uleb(out, zigzag_encode(std::int64_t(values.empty() ? 0 : values[0])));
  if (values.size() <= 1) return;
  U deltas[block];
  U adjusted[block];
  for (std::size_t start = 1; start < values.size(); start += block) {
    const std::size_t count = std::min(block, values.size() - start);
    T min_delta = std::numeric_limits<T>::max();
    for (std::size_t k = 0; k < count; ++k) {
      deltas[k] = U(U(values[start + k]) - U(values[start + k - 1]));
      min_delta = std::min(min_delta, std::bit_cast<T>(deltas[k]));
    }
    for (std::size_t k = 0; k < count; ++k) adjusted[k] = U(deltas[k] - U(min_delta));
    for (std::size_t k = count; k < block; ++k) adjusted[k] = 0;  // padding of the last miniblock
    enc_detail::put_uleb(out, zigzag_encode(std::int64_t(min_delta)));
    std::uint8_t widths[minis];
    const std::size_t used = (count + per_mini - 1) / per_mini;  // miniblocks holding values
    for (std::size_t m = 0; m < minis; ++m) {
      U hi = 0;
      if (m < used)
        for (std::size_t k = m * per_mini; k < (m + 1) * per_mini; ++k) hi |= adjusted[k];
      widths[m] = std::uint8_t(std::bit_width(hi));
      out.push_back(std::byte(widths[m]));
    }
    for (std::size_t m = 0; m < used; ++m)  // unused miniblocks: width 0, no bytes
      pack_bits<U>(std::span<const U>(adjusted + m * per_mini, per_mini), widths[m], out);
  }
}

// ---------------------------------------------------------------------------
// 48. BYTE_STREAM_SPLIT and byte-array encodings
// ---------------------------------------------------------------------------

/// n values of `width` bytes -> `width` streams of n bytes (byte k of every value, then k + 1 …),
/// written into `out`. False, writing nothing, when `in` or `out` is shorter than n * width.
inline bool byte_stream_split_encode(std::span<const std::byte> in, std::size_t width, std::size_t n,
                                     std::span<std::byte> out) {
  if (width == 0 || n > std::numeric_limits<std::size_t>::max() / width) return false;
  if (in.size() < n * width || out.size() < n * width) return false;
  std::byte* dst = out.data();
  const std::byte* src = in.data();
  if (width == 4) {
    for (std::size_t i = 0; i < n; ++i) {
      dst[i] = src[4 * i];
      dst[n + i] = src[4 * i + 1];
      dst[2 * n + i] = src[4 * i + 2];
      dst[3 * n + i] = src[4 * i + 3];
    }
  } else {
    for (std::size_t b = 0; b < width; ++b)
      for (std::size_t i = 0; i < n; ++i) dst[b * n + i] = src[width * i + b];
  }
  return true;
}

/// The same, appended to `out`.
inline void byte_stream_split_encode(std::span<const std::byte> in, std::size_t width, std::size_t n,
                                     std::vector<std::byte>& out) {
  if (width == 0 || n == 0 || in.size() / width < n) return;
  const std::size_t base = out.size();
  out.resize(base + n * width);
  (void)byte_stream_split_encode(in, width, n, std::span<std::byte>(out.data() + base, n * width));
}

/// DELTA_LENGTH_BYTE_ARRAY: the lengths (DELTA_BINARY_PACKED int32), then the bytes back to back.
/// Returns false (writing nothing) when a value is longer than the format's int32.
inline bool delta_length_encode(std::span<const std::string_view> values, std::vector<std::byte>& out) {
  std::vector<std::int32_t> lengths(values.size());
  std::size_t total = 0;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (values[i].size() > std::size_t(INT32_MAX)) return false;
    lengths[i] = std::int32_t(values[i].size());
    total += values[i].size();
  }
  delta_binary_packed_encode<std::int32_t>(lengths, out);
  out.reserve(out.size() + total);
  for (const auto v : values) {
    const auto* p = reinterpret_cast<const std::byte*>(v.data());
    out.insert(out.end(), p, p + v.size());
  }
  return true;
}

/// DELTA_BYTE_ARRAY (front coding): prefix lengths shared with the previous value (DBP int32), then
/// the suffixes as DELTA_LENGTH_BYTE_ARRAY.
inline bool delta_prefix_encode(std::span<const std::string_view> values, std::vector<std::byte>& out) {
  std::vector<std::int32_t> prefix(values.size());
  std::vector<std::string_view> suffix(values.size());
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (values[i].size() > std::size_t(INT32_MAX)) return false;
    std::size_t p = 0;
    if (i) {
      const std::size_t lim = std::min(values[i].size(), values[i - 1].size());
      while (p < lim && values[i][p] == values[i - 1][p]) ++p;
    }
    prefix[i] = std::int32_t(p);
    suffix[i] = values[i].substr(p);
  }
  delta_binary_packed_encode<std::int32_t>(prefix, out);
  return delta_length_encode(suffix, out);
}

// ---------------------------------------------------------------------------
// 49. dictionary builders
// ---------------------------------------------------------------------------

namespace enc_detail {
inline std::uint64_t load64(const unsigned char* p) {
  std::uint64_t w;
  std::memcpy(&w, p, 8);
  return w;
}
#if defined(__SIZEOF_INT128__)
__extension__ using uint128_t = unsigned __int128;
inline std::uint64_t mix64(std::uint64_t a, std::uint64_t b) {
  // 64x64 -> 128 multiply, folded (the wyhash / mum mix): one multiply per step
  const uint128_t r = uint128_t(a) * b;
  return std::uint64_t(r) ^ std::uint64_t(r >> 64);
}
#else
inline std::uint64_t mix64(std::uint64_t a, std::uint64_t b) {  // portable: the same folded product
  const std::uint64_t al = a & 0xffffffffu, ah = a >> 32, bl = b & 0xffffffffu, bh = b >> 32;
  const std::uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
  const std::uint64_t mid = (ll >> 32) + (lh & 0xffffffffu) + (hl & 0xffffffffu);
  const std::uint64_t lo = (ll & 0xffffffffu) | (mid << 32);
  const std::uint64_t hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
  return lo ^ hi;
}
#endif
/// Hash of n bytes: two overlapping word loads for short keys, 16-byte steps for long ones.
inline std::uint64_t hash_bytes(const void* p, std::size_t n) {
  constexpr std::uint64_t k0 = 0xa0761d6478bd642full, k1 = 0xe7037ed1a0b428dbull, k2 = 0x8ebc6af09c88c6e3ull;
  const auto* b = static_cast<const unsigned char*>(p);
  std::uint64_t lo, hi, seed = k0 ^ n;
  if (n > 16) {
    for (std::size_t i = 0; i + 16 < n; i += 16) seed = mix64(load64(b + i) ^ k1, load64(b + i + 8) ^ seed);
    lo = load64(b + n - 16);  // the last 16 bytes (overlapping what the loop saw)
    hi = load64(b + n - 8);
  } else if (n >= 8) {
    lo = load64(b);
    hi = load64(b + n - 8);
  } else if (n >= 4) {
    std::uint32_t x, y;
    std::memcpy(&x, b, 4);
    std::memcpy(&y, b + n - 4, 4);
    lo = x;
    hi = y;
  } else {
    lo = n ? (std::uint64_t(b[0]) << 16) | (std::uint64_t(b[n / 2]) << 8) | b[n - 1] : 0;
    hi = 0;
  }
  return mix64(lo ^ k1, hi ^ seed ^ k2);
}

/// Open-addressing slots holding entry index + 1 (0 = empty), power-of-two sized, at most half full.
/// The dictionaries probe it inline (no indirect calls on the hot path).
struct probe_slots {
  std::vector<std::uint32_t> slots;
  bool needs_grow(std::size_t entries) const { return (entries + 1) * 2 > slots.size(); }
  template <class HashOf>
  void grow(std::size_t, HashOf&& hash_of) {
    std::vector<std::uint32_t> old;
    old.swap(slots);
    slots.assign(old.empty() ? 64 : old.size() * 2, 0u);
    const std::size_t mask = slots.size() - 1;
    for (const std::uint32_t at : old) {
      if (!at) continue;
      std::size_t s = std::size_t(hash_of(at - 1)) & mask;
      while (slots[s]) s = (s + 1) & mask;
      slots[s] = at;
    }
  }
};
}  // namespace enc_detail

/// Dictionary of fixed-width values, compared by their bytes (floats by bit pattern: -0.0 and +0.0
/// are distinct entries, as are NaN payloads, so decoding reproduces every value exactly).
template <class T>
  requires(std::is_trivially_copyable_v<T>)
class fixed_dictionary {
 public:
  /// The index of v (added when new).
  std::uint32_t index_of(const T& v) {
    if (t_.needs_grow(values_.size()))
      t_.grow(values_.size(), [&](std::uint32_t i) { return hashes_[i]; });
    const std::uint64_t h = enc_detail::hash_bytes(&v, sizeof(T));
    const std::size_t mask = t_.slots.size() - 1;
    for (std::size_t s = std::size_t(h) & mask;; s = (s + 1) & mask) {
      const std::uint32_t at = t_.slots[s];
      if (at == 0) {
        t_.slots[s] = std::uint32_t(values_.size() + 1);
        values_.push_back(v);
        hashes_.push_back(h);
        return std::uint32_t(values_.size() - 1);
      }
      if (hashes_[at - 1] == h && std::memcmp(&values_[at - 1], &v, sizeof(T)) == 0) return at - 1;
    }
  }
  /// The distinct values, in first-seen order (index i = values()[i]). The span is invalidated by
  /// index_of() (adding an entry may reallocate).
  std::span<const T> values() const { return values_; }
  std::size_t size() const { return values_.size(); }
  void clear() {
    values_.clear();
    hashes_.clear();
    std::fill(t_.slots.begin(), t_.slots.end(), 0u);
  }

 private:
  std::vector<T> values_;
  std::vector<std::uint64_t> hashes_;
  enc_detail::probe_slots t_;
};

/// Dictionary of byte strings. Entries are views: the caller keeps the bytes alive while the
/// dictionary is used. bytes() is the total size of the distinct values (for a PLAIN dictionary
/// page, add 4 bytes of length per entry).
class string_dictionary {
 public:
  std::uint32_t index_of(std::string_view v) {
    if (t_.needs_grow(values_.size()))
      t_.grow(values_.size(), [&](std::uint32_t i) { return hashes_[i]; });
    const std::uint64_t h = enc_detail::hash_bytes(v.data(), v.size());
    const std::size_t mask = t_.slots.size() - 1;
    for (std::size_t s = std::size_t(h) & mask;; s = (s + 1) & mask) {
      const std::uint32_t at = t_.slots[s];
      if (at == 0) {
        t_.slots[s] = std::uint32_t(values_.size() + 1);
        values_.push_back(v);
        hashes_.push_back(h);
        bytes_ += v.size();
        return std::uint32_t(values_.size() - 1);
      }
      if (hashes_[at - 1] == h && values_[at - 1] == v) return at - 1;
    }
  }
  /// The distinct values, in first-seen order; invalidated by index_of().
  std::span<const std::string_view> values() const { return values_; }
  std::size_t size() const { return values_.size(); }
  std::size_t bytes() const { return bytes_; }
  void clear() {
    values_.clear();
    hashes_.clear();
    bytes_ = 0;
    std::fill(t_.slots.begin(), t_.slots.end(), 0u);
  }

 private:
  std::vector<std::string_view> values_;
  std::vector<std::uint64_t> hashes_;
  std::size_t bytes_ = 0;
  enc_detail::probe_slots t_;
};

// ---------------------------------------------------------------------------
// 50. statistics (Parquet's column orders)
// ---------------------------------------------------------------------------

/// min / max / null count of the non-null values (validity bit set; null validity = all valid).
/// Integers compare as T (pass an unsigned T for unsigned logical types). Floating point follows
/// the Parquet spec: NaN is ignored (no min / max when every value is NaN), a minimum of +0 is
/// reported as -0 and a maximum of -0 as +0.
template <class T>
struct value_stats {
  bool has_minmax = false;
  T min{}, max{};
  std::int64_t null_count = 0;
};
template <class T>
  requires(std::is_arithmetic_v<T>)
inline value_stats<T> compute_stats(std::span<const T> values, const std::uint8_t* validity, std::size_t n) {
  value_stats<T> s;
  for (std::size_t i = 0; i < n; ++i) {
    if (validity && !get_bit(validity, i)) {
      ++s.null_count;
      continue;
    }
    const T v = values[i];
    if constexpr (std::is_floating_point_v<T>)
      if (v != v) continue;  // NaN
    if (!s.has_minmax) {
      s.min = s.max = v;
      s.has_minmax = true;
    } else {
      if (v < s.min) s.min = v;
      if (v > s.max) s.max = v;
    }
  }
  if constexpr (std::is_floating_point_v<T>) {
    if (s.has_minmax && s.min == T(0)) s.min = -T(0);
    if (s.has_minmax && s.max == T(0)) s.max = T(0);
  }
  return s;
}

/// min / max of byte strings (unsigned lexicographic order, Parquet's order for BYTE_ARRAY / FLBA),
/// as views into the inputs. `views` holds the non-null values only.
struct binary_stats {
  bool has_minmax = false;
  std::string_view min, max;
};
inline binary_stats compute_binary_stats(std::span<const std::string_view> views) {
  binary_stats s;
  const auto less = [](std::string_view a, std::string_view b) {
    const std::size_t n = std::min(a.size(), b.size());
    const int c = n ? std::memcmp(a.data(), b.data(), n) : 0;  // memcmp compares as unsigned char
    return c < 0 || (c == 0 && a.size() < b.size());
  };
  for (const auto v : views) {
    if (!s.has_minmax) {
      s.min = s.max = v;
      s.has_minmax = true;
    } else {
      if (less(v, s.min)) s.min = v;
      if (less(s.max, v)) s.max = v;
    }
  }
  return s;
}

}  // namespace nanom::columnar

// ---------------------------------------------------------------------------
// 51. FastLanes blocks (Lance's InlineBitpacking, format 2.0 Bitpacked)
// ---------------------------------------------------------------------------

namespace nanom::columnar::fastlanes {

namespace detail {

template <word T, unsigned Width>
void pack_w(const T* in, T* out) {
  constexpr unsigned bits = kBits<T>;
  constexpr std::size_t lanes = kBlock / bits;
  constexpr T mask = fl_mask<T>(Width);
  T tmp[128];  // lanes <= 128 (the u8 case)
  for (unsigned row = 0; row < bits; ++row) {
    const T* in_row = in + fl_index(row, 0);
    const unsigned shift = (row * Width) % bits;
    const unsigned curr_word = (row * Width) / bits;
    const unsigned next_word = ((row + 1U) * Width) / bits;
    if (row == 0U) {
      for (std::size_t lane = 0; lane < lanes; ++lane) tmp[lane] = static_cast<T>(in_row[lane] & mask);
    } else {
      for (std::size_t lane = 0; lane < lanes; ++lane)
        tmp[lane] = static_cast<T>(tmp[lane] | static_cast<T>(static_cast<T>(in_row[lane] & mask) << shift));
    }
    if (next_word > curr_word) {
      T* out_word = out + lanes * curr_word;
      for (std::size_t lane = 0; lane < lanes; ++lane) out_word[lane] = tmp[lane];
      const unsigned rshift = Width - ((row + 1U) * Width) % bits;
      for (std::size_t lane = 0; lane < lanes; ++lane)
        tmp[lane] = static_cast<T>(static_cast<T>(in_row[lane] & mask) >> rshift);
    }
  }
}

}  // namespace detail

/// Pack one block without checks: `in` holds 1024 values, `out` packed_words_1024<T>(width) words,
/// and width <= kBits<T>. Bits of a value above `width` are dropped, as Lance does.
template <word T>
void pack_1024_unchecked(unsigned width, const T* in, T* out) {
  constexpr unsigned bits = kBits<T>;
  constexpr std::size_t lanes = kBlock / bits;
  if (width == 0U) return;
  if (width == bits) {
    for (unsigned row = 0; row < bits; ++row)
      std::memcpy(out + lanes * row, in + detail::fl_index(row, 0), lanes * sizeof(T));
    return;
  }
  using fn = void (*)(const T*, T*);
  static constexpr auto table = []<unsigned... Ws>(std::integer_sequence<unsigned, Ws...>) {
    return std::array<fn, sizeof...(Ws)>{&detail::pack_w<T, Ws + 1U>...};
  }(std::make_integer_sequence<unsigned, bits - 1U>{});
  table[width - 1U](in, out);
}

/// Pack one block of 1024 values at `width` bits into the first packed_words_1024<T>(width) words of
/// `out`, the exact inverse of unpack_1024 for values that fit in `width` bits. False, writing
/// nothing, when the width is over kBits<T> or `out` is too short.
template <word T>
bool pack_1024(unsigned width, std::span<const T, kBlock> in, std::span<T> out) {
  if (width > kBits<T> || out.size() < packed_words_1024<T>(width)) return false;
  pack_1024_unchecked<T>(width, in.data(), out.data());
  return true;
}

}  // namespace nanom::columnar::fastlanes

#endif  // NANOM_COLUMNAR_ENCODE_HPP_INCLUDED
