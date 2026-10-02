// SPDX-License-Identifier: Apache-2.0
// nanom/values.hpp — value kernels shared by columnar readers (Parquet, Lance, Arrow IPC …).
//
// columnar.hpp turns encoded bits into integers (bit unpacking, RLE / bit-packed runs, deltas).
// This header is the step after: turning those integers and byte ranges into the values a reader
// hands out — validity bitmaps, fixed-width values spread over null slots, variable-length values
// in offsets + data layout (Arrow's, and Lance's), dictionary gathers, UTF-8 validation and
// integer / decimal widening. Nothing here knows a file format.
//
// Same safety rule as columnar.hpp — CHECK AT THE BOUNDARY, RUN UNCHECKED INSIDE: every length,
// index and count that came from the wire is validated before it is used, and a kernel that
// cannot finish says why (a static message) instead of producing a partial guess.
//
//   bitmaps      set_bits, count_bits, get_bit (LSB-first, Arrow's validity layout),
//                rle_bitmap (a width-1 RLE / bit-packed stream -> bitmap, run by run),
//                scatter_bits (dense bits -> the non-null slots of a bitmap)
//   levels       decode_levels (RLE / bit-packed levels -> u16, run by run, range-checked),
//                level_slots (Dremel definition levels -> value slots + their validity),
//                struct_slots / list_slots (Dremel record assembly: validity, list offsets)
//   utf8         valid_utf8 (ASCII-word fast path), utf8_starts_ok (values start on a boundary)
//   nulls        spread_nulls: nn dense fixed-width values -> n slots, in place, nulls zeroed
//   widening     sign_extend_be (big-endian two's complement -> little-endian, any width),
//                sign_extend_le (signed integer -> wider little-endian two's complement)
//   byte arrays  length_prefixed_views (u32 LE length + bytes, i.e. Parquet PLAIN BYTE_ARRAY),
//                delta_length_views, delta_prefix_views (DELTA_LENGTH_BYTE_ARRAY / DELTA_BYTE_ARRAY)
//   dictionaries check_indices, gather_fixed, gathered_size
//   offsets      append_length_prefixed, append_gathered, append_views: write values + int32
//                offsets for n slots (null slots repeat the offset) into an offsets + data pair
#ifndef NANOM_VALUES_HPP_INCLUDED
#define NANOM_VALUES_HPP_INCLUDED

#include "columnar.hpp"

#include <string_view>
#include <vector>

namespace nanom::columnar {

/// What a value kernel reports: success, or a static message naming what was malformed.
struct kernel_status {
  const char* error = nullptr;
  constexpr explicit operator bool() const { return error == nullptr; }
};
inline constexpr kernel_status kernel_ok{};
constexpr kernel_status kernel_fail(const char* why) { return kernel_status{why}; }

// ---------------------------------------------------------------------------
// 34. bitmaps (LSB-first)
// ---------------------------------------------------------------------------

inline bool get_bit(const std::uint8_t* bm, std::size_t i) { return (bm[i / 8] >> (i % 8)) & 1; }

/// Set bits [start, start + count) (bits outside are untouched).
inline void set_bits(std::uint8_t* bm, std::size_t start, std::size_t count) {
  std::size_t i = start;
  const std::size_t end = start + count;
  for (; i < end && i % 8; ++i) bm[i / 8] = std::uint8_t(bm[i / 8] | (1u << (i % 8)));
  if (end - i >= 8) {
    std::memset(bm + i / 8, 0xff, (end - i) / 8);
    i += ((end - i) / 8) * 8;
  }
  for (; i < end; ++i) bm[i / 8] = std::uint8_t(bm[i / 8] | (1u << (i % 8)));
}

/// Number of set bits in [start, start + count), a 64-bit word at a time.
inline std::size_t count_bits(const std::uint8_t* bm, std::size_t start, std::size_t count) {
  std::size_t c = 0, i = start;
  const std::size_t end = start + count;
  for (; i < end && i % 64; ++i) c += get_bit(bm, i);
  for (; end - i >= 64; i += 64) {
    std::uint64_t w;
    std::memcpy(&w, bm + i / 8, 8);
    c += std::size_t(std::popcount(w));
  }
  for (; i < end; ++i) c += get_bit(bm, i);
  return c;
}

/// Expand n values of a width-1 RLE / bit-packed stream (definition levels of an optional field,
/// RLE booleans) into the bitmap `out` at bit `at`, run by run: an RLE run of 1s is a range fill, a
/// bit-packed run a bit copy. out's bits [at, at + n) must be zero; bits outside stay untouched.
/// Fails on a value above 1 or a stream shorter than n.
inline kernel_status rle_bitmap(rle_bp_decoder& d, std::size_t n, std::span<std::byte> out, std::size_t at) {
  if (d.width() != 1) return kernel_fail("rle_bitmap needs a width-1 stream");
  if (at > out.size() * 8 || n > out.size() * 8 - at) return kernel_fail("bitmap smaller than the value count");
  auto* bm = reinterpret_cast<std::uint8_t*>(out.data());
  rle_bp_decoder::run lr;
  for (std::size_t i = 0; i < n; i += lr.count) {
    if (!d.next_run(lr, n - i)) return kernel_fail("bit stream shorter than its values");
    if (!lr.packed) {
      if (lr.value > 1) return kernel_fail("value above 1 in a bit stream");
      if (lr.value) set_bits(bm, at + i, lr.count);
    } else if (lr.bit_offset == 0) {
      if (!copy_bits(lr.bits, lr.count, out, at + i)) return kernel_fail("bit stream shorter than its values");
    } else {  // a run resumed mid-byte
      for (std::size_t k = 0; k < lr.count; ++k) {
        const std::size_t b = lr.bit_offset + k;
        if ((std::uint8_t(lr.bits[b / 8]) >> (b % 8)) & 1) set_bits(bm, at + i + k, 1);
      }
    }
  }
  return kernel_ok;
}

/// Place the nn bits of `dense` (bit j = the j-th non-null value) at the n slots of `out` starting
/// at bit `at`, in slot order: slot r takes the next dense bit when its validity bit is set (null
/// validity = all valid). out's bits [at, at + n) must be zero (null slots stay zero).
inline void scatter_bits(const std::uint8_t* dense, const std::uint8_t* validity, std::size_t n, std::uint8_t* out,
                         std::size_t at) {
  std::size_t j = 0;
  for (std::size_t r = 0; r < n; ++r) {
    if (validity && !get_bit(validity, r)) continue;
    const std::size_t b = at + r;
    out[b / 8] = std::uint8_t(out[b / 8] | (unsigned(get_bit(dense, j)) << (b % 8)));
    ++j;
  }
}

// ---------------------------------------------------------------------------
// 34b. levels (Dremel repetition / definition levels)
// ---------------------------------------------------------------------------

/// Decode n RLE / bit-packed levels, each <= maxv, into out: an RLE run is a fill, a bit-packed
/// run is unpacked in blocks with a vectorizable range check.
inline kernel_status decode_levels(std::span<const std::byte> data, std::uint16_t maxv, std::size_t n, std::uint16_t* out) {
  const unsigned w = unsigned(std::bit_width(unsigned(maxv)));
  rle_bp_decoder d(data, w);
  rle_bp_decoder::run lr;
  std::uint32_t tmp[512];
  for (std::size_t i = 0; i < n; i += lr.count) {
    if (!d.next_run(lr, n - i)) return kernel_fail("levels shorter than the page");
    if (!lr.packed) {
      if (lr.value > maxv) return kernel_fail("level above the column's maximum");
      std::fill_n(out + i, lr.count, std::uint16_t(lr.value));
      continue;
    }
    std::uint32_t hi = 0;
    if (lr.bit_offset == 0) {
      for (std::size_t k = 0; k < lr.count; k += 512) {
        const std::size_t m = std::min<std::size_t>(512, lr.count - k);
        const std::size_t byte = k * w / 8;  // k is a multiple of 8: a whole-byte position
        if (!unpack_bits<std::uint32_t>(lr.bits.subspan(byte), w, std::span<std::uint32_t>(tmp), m))
          return kernel_fail("levels shorter than the page");
        for (std::size_t j = 0; j < m; ++j) {
          hi |= tmp[j] > maxv ? 1u : 0u;
          out[i + k + j] = std::uint16_t(tmp[j]);
        }
      }
    } else {  // a run resumed mid-byte (not produced by one pass, kept for generality)
      const auto* b = reinterpret_cast<const std::uint8_t*>(lr.bits.data());
      for (std::size_t k = 0; k < lr.count; ++k) {
        const std::size_t bit = lr.bit_offset + k * w;
        std::uint32_t v = 0;
        for (unsigned t = 0; t < w; ++t) {
          const std::size_t q = bit + t;
          if (q / 8 >= lr.bits.size()) return kernel_fail("levels shorter than the page");
          v |= std::uint32_t((b[q / 8] >> (q % 8)) & 1) << t;
        }
        hi |= v > maxv ? 1u : 0u;
        out[i + k] = std::uint16_t(v);
      }
    }
    if (hi) return kernel_fail("level above the column's maximum");
  }
  return kernel_ok;
}

/// Which of n level entries hold a value slot, and which slots are non-null: an entry is a slot
/// when def >= slot_level (its innermost enclosing list has an element there; 0 = every entry),
/// and the slot is non-null when def == max_def. Sets the validity bits of the slots in `bm`
/// (zeroed, >= n bits) and returns {slots, non-null}.
struct slot_counts {
  std::size_t slots = 0, non_null = 0;
};
inline slot_counts level_slots(const std::uint16_t* def, std::size_t n, std::uint16_t slot_level, std::uint16_t max_def,
                               std::uint8_t* bm) {
  slot_counts c;
  for (std::size_t i = 0; i < n; ++i) {
    if (def[i] < slot_level) continue;  // an empty or null ancestor: no slot here
    if (def[i] == max_def) {
      bm[c.slots / 8] = std::uint8_t(bm[c.slots / 8] | (1u << (c.slots % 8)));
      ++c.non_null;
    }
    ++c.slots;
  }
  return c;
}

// ---------------------------------------------------------------------------
// 34c. Dremel record assembly (structure from one leaf's levels)
// ---------------------------------------------------------------------------
//
// For a node whose enclosing list has repetition level r_enc and element level d_enc (both 0 at
// the top level), the node's slots are the level entries with rep <= r_enc and def >= d_enc:
//   struct slot  non-null when def >= def_present
//   list slot    non-null when def >= def_present; holds an element when def >= def_elem, and
//                every later entry with rep == rep_elem (before the next slot) is another element
// The caller knows how many slots the parent promised (`expected`): more or fewer is an error,
// so leaves that disagree about the structure are rejected rather than assembled inconsistently.

struct dremel_node {
  std::uint16_t r_enc = 0, d_enc = 0;  ///< the enclosing list's repetition / element level
  std::uint16_t def_present = 0;       ///< def level at which this node's slot is non-null
  std::uint16_t def_elem = 0, rep_elem = 0;  ///< lists: def level of a first element, rep level of the rest
};

/// Struct (or any non-repeated group) slots: validity bits into `validity` (zeroed, >= expected
/// bits); `nulls` counts null slots.
inline kernel_status struct_slots(const std::uint16_t* rep, const std::uint16_t* def, std::size_t entries,
                                  const dremel_node& nd, std::int64_t expected, std::uint8_t* validity,
                                  std::int64_t& nulls) {
  std::int64_t slots = 0;
  nulls = 0;
  for (std::size_t i = 0; i < entries; ++i) {
    if (rep[i] > nd.r_enc || def[i] < nd.d_enc) continue;
    if (slots >= expected) return kernel_fail("more slots than the parent has");
    if (def[i] >= nd.def_present) validity[slots / 8] = std::uint8_t(validity[slots / 8] | (1u << (slots % 8)));
    else ++nulls;
    ++slots;
  }
  if (slots != expected) return kernel_fail("fewer slots than the parent has");
  return kernel_ok;
}

/// List slots: offsets[0 .. expected] (int32, Arrow's list layout), validity bits into `validity`
/// (zeroed, >= expected bits), `nulls` null slots and `elements` elements in all (the child's
/// expected slot count).
inline kernel_status list_slots(const std::uint16_t* rep, const std::uint16_t* def, std::size_t entries,
                                const dremel_node& nd, std::int64_t expected, std::int32_t* offsets,
                                std::uint8_t* validity, std::int64_t& nulls, std::int64_t& elements) {
  std::int64_t slots = 0, elems = 0;
  nulls = 0;
  bool open = false;  // the current slot holds a non-empty list
  for (std::size_t i = 0; i < entries; ++i) {
    if (rep[i] <= nd.r_enc) {
      open = false;
      if (def[i] < nd.d_enc) continue;  // an empty / null ancestor: not a slot of this list
      if (slots >= expected) return kernel_fail("more slots than the parent has");
      offsets[slots] = std::int32_t(elems);
      if (def[i] >= nd.def_present) validity[slots / 8] = std::uint8_t(validity[slots / 8] | (1u << (slots % 8)));
      else ++nulls;
      ++slots;
      if (def[i] >= nd.def_elem) {
        open = true;
        ++elems;
      }
    } else if (rep[i] == nd.rep_elem) {
      if (!open) return kernel_fail("an element continues a list that has none");
      ++elems;
    }
    if (elems > INT32_MAX) return kernel_fail("more than 2^31 list elements");
  }
  if (slots != expected) return kernel_fail("fewer slots than the parent has");
  offsets[slots] = std::int32_t(elems);
  elements = elems;
  return kernel_ok;
}

// ---------------------------------------------------------------------------
// 35. UTF-8
// ---------------------------------------------------------------------------

/// Is `s` well-formed UTF-8 (no overlongs, no surrogates, <= U+10FFFF)? ASCII runs are checked
/// 16 / 8 bytes at a time.
inline bool valid_utf8(std::string_view s) {
  const auto* p = reinterpret_cast<const unsigned char*>(s.data());
  const auto* e = p + s.size();
  while (p < e) {
    if (e - p >= 16) {
      std::uint64_t w0, w1;
      std::memcpy(&w0, p, 8);
      std::memcpy(&w1, p + 8, 8);
      if (!((w0 | w1) & 0x8080808080808080ull)) { p += 16; continue; }
    } else if (e - p >= 8) {
      std::uint64_t w;
      std::memcpy(&w, p, 8);
      if (!(w & 0x8080808080808080ull)) { p += 8; continue; }
    }
    const unsigned c = *p;
    if (c < 0x80) { ++p; continue; }
    int n;
    std::uint32_t cp;
    if ((c & 0xe0) == 0xc0) { n = 1; cp = c & 0x1f; }
    else if ((c & 0xf0) == 0xe0) { n = 2; cp = c & 0x0f; }
    else if ((c & 0xf8) == 0xf0) { n = 3; cp = c & 0x07; }
    else return false;
    if (e - p <= n) return false;
    for (int i = 1; i <= n; ++i) {
      if ((p[i] & 0xc0) != 0x80) return false;
      cp = (cp << 6) | (p[i] & 0x3f);
    }
    if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) || cp > 0x10ffff ||
        (cp >= 0xd800 && cp <= 0xdfff))
      return false;
    p += n + 1;
  }
  return true;
}

/// With the concatenation data[0 .. end) already valid_utf8: is every value valid on its own?
/// It is exactly when no value starts on a continuation byte. `starts` holds n value start
/// offsets (a start equal to `end` is an empty last value).
template <class Off>
inline bool utf8_starts_ok(const std::byte* data, std::int64_t end, const Off* starts, std::size_t n) {
  for (std::size_t i = 0; i < n; ++i) {
    const auto o = std::int64_t(starts[i]);
    if (o < end && (std::uint8_t(data[o]) & 0xc0) == 0x80) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// 36. nulls: dense values -> slots
// ---------------------------------------------------------------------------

namespace detail {
/// Move nn dense W-byte values (dst[0 .. nn)) to their slots in dst[0 .. n), back to front,
/// zero-filling null slots. Whole 64-slot words that are all valid / all null move as one block;
/// mixed words take a branchless per-slot step (no mispredictions at any null density).
template <std::size_t W>
inline void spread_nulls_w(std::byte* dst, std::size_t n, std::size_t nn, const std::uint8_t* bm) {
  std::size_t j = nn, r = n;
  while (r > 0) {
    if (j == 0) {  // only nulls remain
      std::memset(dst, 0, r * W);
      return;
    }
    if (r % 64 == 0) {
      std::uint64_t word;
      std::memcpy(&word, bm + (r - 64) / 8, 8);
      if (word == ~std::uint64_t(0)) {
        j -= 64;
        r -= 64;
        if (j != r) std::memmove(dst + r * W, dst + j * W, 64 * W);
        continue;
      }
      if (word == 0) {
        r -= 64;
        std::memset(dst + r * W, 0, 64 * W);
        continue;
      }
      if (j >= 64) {  // mixed word: j >= popcount(word) >= 1 keeps dst[j - 1] in range
        for (int k = 0; k < 64; ++k) {
          --r;
          const std::size_t bit = (word >> 63) & 1;
          word <<= 1;
          std::byte v[W];
          std::memcpy(v, dst + (j - 1) * W, W);
          if constexpr (W <= 8) {
            using U = std::conditional_t<W == 1, std::uint8_t, std::conditional_t<W == 2, std::uint16_t,
                      std::conditional_t<W <= 4, std::uint32_t, std::uint64_t>>>;
            U u = 0;
            std::memcpy(&u, v, W);
            u = U(u & (U(0) - U(bit)));
            std::memcpy(dst + r * W, &u, W);
          } else {
            const std::byte m = bit ? std::byte{0xff} : std::byte{0};
            for (std::size_t b = 0; b < W; ++b) v[b] &= m;
            std::memcpy(dst + r * W, v, W);
          }
          j -= bit;
        }
        continue;
      }
    }
    --r;
    if (get_bit(bm, r)) {
      --j;
      if (j != r) std::memcpy(dst + r * W, dst + j * W, W);
    } else {
      std::memset(dst + r * W, 0, W);
    }
  }
}
}  // namespace detail

/// Spread nn dense values of `width` bytes at dst[0 .. nn) over the n slots dst[0 .. n) whose
/// validity bits (`validity`, LSB-first, nn of the first n set, readable in whole 64-bit words:
/// ceil(n / 64) * 8 bytes) mark the non-null ones. In place; null slots become zero bytes.
inline void spread_nulls(std::byte* dst, std::size_t n, std::size_t nn, std::size_t width,
                         const std::uint8_t* validity) {
  switch (width) {
    case 1: return detail::spread_nulls_w<1>(dst, n, nn, validity);
    case 2: return detail::spread_nulls_w<2>(dst, n, nn, validity);
    case 4: return detail::spread_nulls_w<4>(dst, n, nn, validity);
    case 8: return detail::spread_nulls_w<8>(dst, n, nn, validity);
    case 16: return detail::spread_nulls_w<16>(dst, n, nn, validity);
    default: break;
  }
  std::size_t j = nn;
  for (std::size_t r = n; r-- > 0;) {
    if (get_bit(validity, r)) {
      --j;
      if (j != r) std::memcpy(dst + r * width, dst + j * width, width);
    } else {
      std::memset(dst + r * width, 0, width);
    }
  }
}

// ---------------------------------------------------------------------------
// 37. integer widening
// ---------------------------------------------------------------------------

/// Big-endian two's complement of k bytes -> little-endian two's complement of `width` bytes
/// (k <= width; e.g. Parquet DECIMAL bytes -> Arrow decimal128).
inline void sign_extend_be(const std::byte* src, std::size_t k, std::byte* out, std::size_t width) {
  const std::byte sign = k && (std::uint8_t(src[0]) & 0x80) ? std::byte{0xff} : std::byte{0};
  for (std::size_t i = 0; i < width; ++i) out[i] = i < k ? src[k - 1 - i] : sign;
}

/// A signed integer -> little-endian two's complement of `width` (>= sizeof(T)) bytes.
template <std::signed_integral T>
inline void sign_extend_le(T v, std::byte* out, std::size_t width) {
  std::memcpy(out, &v, sizeof(T));
  std::memset(out + sizeof(T), v < 0 ? 0xff : 0, width - sizeof(T));
}

// ---------------------------------------------------------------------------
// 38. variable-length values as views
// ---------------------------------------------------------------------------

/// nn values stored as [u32 LE length][bytes] (Parquet PLAIN BYTE_ARRAY, dictionary pages) ->
/// views into `in`. Returns the bytes consumed, or nullopt (with nothing promised in `out`).
inline std::optional<std::size_t> length_prefixed_views(std::span<const std::byte> in, std::size_t nn,
                                                        std::span<std::string_view> out) {
  if (out.size() < nn) return std::nullopt;
  std::size_t p = 0;
  for (std::size_t i = 0; i < nn; ++i) {
    if (in.size() - p < 4) return std::nullopt;
    std::uint32_t len;
    std::memcpy(&len, in.data() + p, 4);
    if constexpr (std::endian::native == std::endian::big) len = std::byteswap(len);
    p += 4;
    if (len > in.size() - p) return std::nullopt;
    out[i] = std::string_view(reinterpret_cast<const char*>(in.data()) + p, len);
    p += len;
  }
  return p;
}

/// DELTA_LENGTH_BYTE_ARRAY: a DELTA_BINARY_PACKED length stream, then the bytes back to back.
/// `lengths` is caller scratch (resized to nn). Views point into `in`.
inline kernel_status delta_length_views(std::span<const std::byte> in, std::size_t nn,
                                        std::vector<std::int32_t>& lengths, std::span<std::string_view> out) {
  if (out.size() < nn) return kernel_fail("output smaller than the value count");
  lengths.resize(nn);
  auto used = delta_binary_packed<std::int32_t>(in, std::span<std::int32_t>(lengths), nn);
  if (!used) return kernel_fail("malformed DELTA_LENGTH_BYTE_ARRAY lengths");
  std::size_t p = *used;
  for (std::size_t i = 0; i < nn; ++i) {
    if (lengths[i] < 0 || std::size_t(lengths[i]) > in.size() - p)
      return kernel_fail("DELTA_LENGTH_BYTE_ARRAY data past the page");
    out[i] = std::string_view(reinterpret_cast<const char*>(in.data()) + p, std::size_t(lengths[i]));
    p += std::size_t(lengths[i]);
  }
  return kernel_ok;
}

/// DELTA_BYTE_ARRAY (incremental / front coding): a prefix-length stream, then a
/// DELTA_LENGTH_BYTE_ARRAY of suffixes; value i = the first prefix[i] bytes of value i - 1 +
/// suffix i. Values are rebuilt into `arena` (sized once, at most `max_bytes`); views point into
/// it. `prefix` / `lengths` are caller scratch.
inline kernel_status delta_prefix_views(std::span<const std::byte> in, std::size_t nn, std::vector<std::int32_t>& prefix,
                                        std::vector<std::int32_t>& lengths, std::vector<char>& arena,
                                        std::span<std::string_view> out, std::size_t max_bytes) {
  if (out.size() < nn) return kernel_fail("output smaller than the value count");
  prefix.resize(nn);
  lengths.resize(nn);
  auto u1 = delta_binary_packed<std::int32_t>(in, std::span<std::int32_t>(prefix), nn);
  if (!u1) return kernel_fail("malformed DELTA_BYTE_ARRAY prefix lengths");
  const auto rest = in.subspan(*u1);
  auto u2 = delta_binary_packed<std::int32_t>(rest, std::span<std::int32_t>(lengths), nn);
  if (!u2) return kernel_fail("malformed DELTA_BYTE_ARRAY suffix lengths");
  // size the arena once, validating every prefix / suffix on the way
  std::size_t total = 0, prev = 0, p = *u2;
  for (std::size_t i = 0; i < nn; ++i) {
    if (prefix[i] < 0 || lengths[i] < 0 || std::size_t(prefix[i]) > prev || std::size_t(lengths[i]) > rest.size() - p)
      return kernel_fail("DELTA_BYTE_ARRAY prefix/suffix out of range");
    p += std::size_t(lengths[i]);
    prev = std::size_t(prefix[i]) + std::size_t(lengths[i]);
    if (prev > max_bytes || total > max_bytes - prev) return kernel_fail("DELTA_BYTE_ARRAY expands past the size limit");
    total += prev;
  }
  arena.resize(total);
  std::size_t at = 0, prev_at = 0;
  p = *u2;
  for (std::size_t i = 0; i < nn; ++i) {
    const std::size_t pre = std::size_t(prefix[i]), suf = std::size_t(lengths[i]);
    if (pre) std::memmove(arena.data() + at, arena.data() + prev_at, pre);
    if (suf) std::memcpy(arena.data() + at + pre, rest.data() + p, suf);
    p += suf;
    out[i] = std::string_view(arena.data() + at, pre + suf);
    prev_at = at;
    at += pre + suf;
  }
  return kernel_ok;
}

// ---------------------------------------------------------------------------
// 39. dictionaries
// ---------------------------------------------------------------------------

/// Are all indices < dict_size?
inline bool check_indices(std::span<const std::uint32_t> idx, std::size_t dict_size) {
  std::uint32_t bad = 0;
  for (const auto i : idx) bad |= i >= dict_size ? 1u : 0u;
  return bad == 0;
}

/// out[i] = dict[idx[i]] for fixed-width values (indices must already pass check_indices).
inline void gather_fixed(const std::byte* dict, std::size_t width, std::span<const std::uint32_t> idx, std::byte* out) {
  const std::size_t k = idx.size();
  if (width == 4) for (std::size_t i = 0; i < k; ++i) std::memcpy(out + 4 * i, dict + 4 * std::size_t(idx[i]), 4);
  else if (width == 8) for (std::size_t i = 0; i < k; ++i) std::memcpy(out + 8 * i, dict + 8 * std::size_t(idx[i]), 8);
  else for (std::size_t i = 0; i < k; ++i) std::memcpy(out + width * i, dict + width * std::size_t(idx[i]), width);
}

/// Total bytes of the variable-length dictionary values idx selects (`dict_offsets` has
/// dict_size + 1 entries; indices must already pass check_indices).
template <class Off>
inline std::uint64_t gathered_size(const Off* dict_offsets, std::span<const std::uint32_t> idx) {
  std::uint64_t total = 0;
  for (const auto i : idx) total += std::uint64_t(dict_offsets[i + 1] - dict_offsets[i]);
  return total;
}

// ---------------------------------------------------------------------------
// 40. offsets + data output (Arrow's / Lance's variable-length layout)
// ---------------------------------------------------------------------------
//
// The append_* kernels fill n slots of an offsets + data pair: slot r's END offset goes to
// ends[r] (so pass offsets + first_slot + 1), valid slots take the next value, null slots
// (validity bit clear; null validity = all valid) repeat the offset. `cur` is the data size
// before and after. Each takes kValueSlack writable bytes past the data it writes: short values
// move as one fixed 16-byte copy.

inline constexpr std::size_t kValueSlack = 16;

namespace detail {
/// One value: a short value with 16 readable bytes behind it moves as one fixed 16-byte copy
/// (the destination has kValueSlack writable bytes), anything else as an ordinary memcpy.
inline void copy_value(std::byte* dst, const std::byte* src, std::size_t len, const std::byte* src_end) {
  if (len <= 16 && src_end - src >= 16) std::memcpy(dst, src, 16);
  else if (len) std::memcpy(dst, src, len);
}
inline bool slot_valid(const std::uint8_t* validity, std::size_t r) { return !validity || get_bit(validity, r); }
}  // namespace detail

/// Length-prefixed values of `in` (see length_prefixed_views) straight into data at `cur`, in one
/// pass. `data` must hold cur + in.size() + kValueSlack bytes. Fails past `max_size` total.
template <class Off>
inline kernel_status append_length_prefixed(std::span<const std::byte> in, std::size_t n, const std::uint8_t* validity,
                                            std::byte* data, std::int64_t& cur, Off* ends, std::int64_t max_size) {
  const std::byte* p = in.data();
  const std::byte* const e = p + in.size();
  for (std::size_t r = 0; r < n; ++r) {
    if (detail::slot_valid(validity, r)) {
      if (e - p < 4) return kernel_fail("truncated length-prefixed value");
      std::uint32_t len;
      std::memcpy(&len, p, 4);
      if constexpr (std::endian::native == std::endian::big) len = std::byteswap(len);
      p += 4;
      if (len > std::size_t(e - p)) return kernel_fail("length-prefixed value runs past the page");
      detail::copy_value(data + cur, p, len, e);
      p += len;
      cur += len;
      if (cur > max_size) return kernel_fail("values exceed the offset type");
    }
    ends[r] = Off(cur);
  }
  return kernel_ok;
}

/// Dictionary gather of variable-length values into data at `cur`. `dict_end` bounds the readable
/// dictionary bytes (keep kValueSlack readable bytes past the last value for the fast copies);
/// `data` must hold cur + gathered_size(...) + kValueSlack bytes; indices must pass check_indices.
template <class Off, class DOff>
inline void append_gathered(const std::byte* dict_data, const std::byte* dict_end, const DOff* dict_offsets,
                            std::span<const std::uint32_t> idx, std::size_t n, const std::uint8_t* validity,
                            std::byte* data, std::int64_t& cur, Off* ends) {
  std::size_t j = 0;
  for (std::size_t r = 0; r < n; ++r) {
    if (detail::slot_valid(validity, r)) {
      const auto a = std::size_t(dict_offsets[idx[j]]);
      const auto len = std::size_t(dict_offsets[idx[j] + 1]) - a;
      ++j;
      detail::copy_value(data + cur, dict_data + a, len, dict_end);
      cur += std::int64_t(len);
    }
    ends[r] = Off(cur);
  }
}

/// Views (one per valid slot) into data at `cur`; `data` must hold cur + their total size bytes.
template <class Off>
inline void append_views(std::span<const std::string_view> views, std::size_t n, const std::uint8_t* validity,
                         std::byte* data, std::int64_t& cur, Off* ends) {
  std::size_t j = 0;
  for (std::size_t r = 0; r < n; ++r) {
    if (detail::slot_valid(validity, r)) {
      const auto v = views[j++];
      if (!v.empty()) std::memcpy(data + cur, v.data(), v.size());
      cur += std::int64_t(v.size());
    }
    ends[r] = Off(cur);
  }
}

}  // namespace nanom::columnar

#endif  // NANOM_VALUES_HPP_INCLUDED
