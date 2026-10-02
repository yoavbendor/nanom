// SPDX-License-Identifier: Apache-2.0
// nanom/codec.hpp — page decompression with no external dependencies: Snappy (raw) and LZ4 block.
//
// Columnar formats compress each page independently and record the uncompressed size in the page
// header. These decoders take that size as the output span and never write past it, never read
// past the input, and reject every back-reference that points before the start of the output — a
// corrupt or hostile page fails with a codec_error, it never becomes an out-of-bounds access. The
// "decompression bomb" defence is the caller's: size `out` from the header's uncompressed size
// after capping it (the decoders cannot produce more than out.size() bytes).
//
// Heavier codecs (zstd, gzip/deflate, brotli) plug in at the reader through the same shape:
//   expected<std::size_t, codec_error> decompress(std::span<const std::byte> in, std::span<std::byte> out)
#ifndef NANOM_CODEC_HPP_INCLUDED
#define NANOM_CODEC_HPP_INCLUDED

#include "nom.hpp"

namespace nanom::codec {

struct codec_error {
  const char* what = "";
  std::size_t at = 0;  ///< input offset where decoding stopped
};
using status = expected<std::size_t, codec_error>;

namespace detail {
inline status fail(const char* what, std::size_t at) { return unexpected<codec_error>(codec_error{what, at}); }

/// Overlapping back-reference copy (LZ77 semantics: the source may overlap the destination).
inline void copy_match(std::byte* dst, std::size_t offset, std::size_t len) {
  const std::byte* src = dst - offset;
  if (offset >= len) {
    std::memcpy(dst, src, len);
  } else if (offset >= 8) {
    while (len >= 8) {
      std::memcpy(dst, src, 8);
      dst += 8; src += 8; len -= 8;
    }
    while (len--) *dst++ = *src++;
  } else {
    while (len--) *dst++ = *src++;
  }
}
inline void copy8(std::byte* d, const std::byte* s) { std::memcpy(d, s, 8); }
inline void copy16(std::byte* d, const std::byte* s) { std::memcpy(d, s, 16); }

/// LZ77 back-reference copy of `len` bytes from `offset` back, allowed to write up to 15 bytes past
/// dst + len (callers guarantee `room` = writable bytes from dst, and fall back to copy_match when
/// room < len + 16). Every byte read is either before dst or already written by this copy, so the
/// overshoot never feeds garbage into the result, and the bytes past len are overwritten later.
inline void copy_match_wild(std::byte* dst, std::size_t offset, std::size_t len) {
  const std::byte* src = dst - offset;
  if (offset >= 16) {
    for (std::size_t i = 0; i < len; i += 16) copy16(dst + i, src + i);
  } else if (offset >= 8) {
    for (std::size_t i = 0; i < len; i += 8) copy8(dst + i, src + i);
  } else {
    // offset 1..7 (run-like repeats): the first 8 bytes byte-wise, then 8-byte chunks from a lag
    // that is a multiple of the period and >= 8 (same bytes, by periodicity, and non-overlapping)
    const std::size_t head = len < 8 ? len : 8;
    for (std::size_t i = 0; i < head; ++i) dst[i] = src[i];
    const std::size_t lag = offset * ((8 + offset - 1) / offset);  // 8..14
    for (std::size_t i = head; i < len; i += 8) copy8(dst + i, dst + i - lag);
  }
}
}  // namespace detail

// ---------------------------------------------------------------------------
// 30. Snappy (raw block format — what Parquet's SNAPPY codec stores)
// ---------------------------------------------------------------------------
//
// Fast paths (all guarded by explicit room checks; the exact paths below handle the last bytes of
// a block and every other case): short literals move as one fixed 16-byte copy, back-references
// as 16- / 8-byte chunks or periodic 8-byte chunks for offsets under 8. Every read stays inside
// the input or the already-produced output; every write stays inside `out`.

/// Uncompressed length from the Snappy preamble (to size/validate the output before decoding).
inline std::optional<std::uint32_t> snappy_uncompressed_length(std::span<const std::byte> in) {
  auto r = varint_u32(from(in));
  if (!r) return std::nullopt;
  return r->value;
}

namespace detail {
/// Snappy tag table, built at compile time: for every tag byte, the element length (bits 0-7),
/// the copy offset's high bits (bits 8-10, copy-1 only) and the count of extra bytes (bits 11-13).
/// Literals with a length suffix (len > 60) are marked with length 0 and handled out of line.
consteval std::array<std::uint16_t, 256> snappy_table() {
  std::array<std::uint16_t, 256> t{};
  for (unsigned tag = 0; tag < 256; ++tag) {
    unsigned len = 0, high = 0, extra = 0;
    switch (tag & 3) {
      case 0: len = (tag >> 2) + 1; if (len > 60) len = 0; extra = 0; break;
      case 1: len = ((tag >> 2) & 7) + 4; high = (tag >> 5) << 8; extra = 1; break;
      case 2: len = (tag >> 2) + 1; extra = 2; break;
      default: len = (tag >> 2) + 1; extra = 4; break;
    }
    t[tag] = std::uint16_t(len | high | (extra << 11));
  }
  return t;
}
inline constexpr std::array<std::uint16_t, 256> snappy_tags = snappy_table();
inline constexpr std::uint32_t snappy_extra_mask[5] = {0, 0xff, 0xffff, 0xffffff, 0xffffffff};
inline std::uint32_t load_le32(const std::byte* p) {
  std::uint32_t v;
  std::memcpy(&v, p, 4);
  if constexpr (std::endian::native == std::endian::big) v = std::byteswap(v);
  return v;
}
}  // namespace detail

/// Decompress a raw Snappy block into exactly out.size() bytes (the preamble length must match).
inline status snappy_decompress(std::span<const std::byte> in, std::span<std::byte> out) {
  auto pre = varint_u32(from(in));
  if (!pre) return detail::fail("snappy: bad length preamble", 0);
  if (pre->value != out.size()) return detail::fail("snappy: length preamble does not match the page header", 0);
  const std::byte* ip = pre->rest.first;
  const std::byte* const ie = in.data() + in.size();
  std::byte* op = out.data();
  std::byte* const ob = out.data();
  std::byte* const oe = out.data() + out.size();
  const auto at = [&] { return std::size_t(ip - in.data()); };
  const auto u8 = [](const std::byte* p) { return std::size_t(std::uint8_t(*p)); };
  // fast-path limits, computed once (an element may use the fast path while ip < ip_fast and
  // op < op_fast: 16 input bytes and 80 output bytes of headroom)
  const std::byte* const ip_fast = in.size() >= 16 ? ie - 16 : in.data();
  std::byte* const op_fast = out.size() >= 80 ? oe - 80 : ob;
  while (ip < ie) {
    const std::size_t tag = u8(ip);
    const std::uint16_t entry = detail::snappy_tags[tag];
    // Fast path, per element: while >= 16 input bytes (tag + 4 extra bytes, or a 16-byte literal)
    // and >= 80 output bytes (the longest copy, 64, plus 16 of overshoot) remain, an element is a
    // table lookup, one masked 4-byte load and fixed-size copies. Offsets are still validated.
    if (ip < ip_fast && op < op_fast) {
      // Literals and copies take ONE branch-free step: the source is selected (cmov), not
      // branched on, so the literal/copy alternation of typical data costs no mispredictions.
      // It covers literals of 1..16 bytes and copies of <= 16 bytes from >= 8 back, as two
      // 8-byte moves (with offset >= 8 the second move reads only bytes already final).
      const bool lit = (tag & 3) == 0;
      const std::size_t len = entry & 0xff;  // 0: a literal with a length suffix
      const std::size_t extra = entry >> 11;
      const std::size_t offset = (entry & 0x700) + (detail::load_le32(ip + 1) & detail::snappy_extra_mask[extra]);
      const std::size_t produced = std::size_t(op - ob);
      // the next tag's position comes from the tag by ALU alone (no table load on the loop's
      // ip -> tag -> ip dependency chain): a literal advances (tag >> 2) + 2, a copy-1 / copy-2
      // (tag & 3) + 1; copy-4 (tag & 3 == 3) takes the path below
      const bool slow = (len - 1 >= 16) | ((tag & 3) == 3) | (bool(!lit) & ((offset < 8) | (offset > produced)));
      if (!slow) {
        const std::byte* src = lit ? ip + 1 : op - offset;
        detail::copy8(op, src);
        detail::copy8(op + 8, src + 8);
        op += len;
        ip += lit ? (tag >> 2) + 2 : (tag & 3) + 1;
        continue;
      }
      if (!lit && len <= 64 && offset - 1 < produced) {
        // a copy the step above does not cover: longer than 16 or from under 8 back
        ip += 1 + extra;
        detail::copy_match_wild(op, offset, len);
        op += len;
        continue;
      }
      // a literal over 16 bytes, or an invalid offset: the exact path below
    }
    ++ip;  // exact path: every length and offset checked against both ends
    if ((tag & 3) == 0) {  // literal
      std::size_t len = (tag >> 2) + 1;
      if (len > 60) {
        const std::size_t nb = len - 60;  // 1..4 length bytes
        if (std::size_t(ie - ip) < nb) return detail::fail("snappy: truncated literal length", at());
        len = 0;
        for (std::size_t i = 0; i < nb; ++i) len |= u8(ip + i) << (8 * i);
        ip += nb;
        len += 1;
      }
      if (std::size_t(ie - ip) < len) return detail::fail("snappy: literal runs past the input", at());
      if (std::size_t(oe - op) < len) return detail::fail("snappy: literal overflows the output", at());
      std::memcpy(op, ip, len);
      ip += len;
      op += len;
      continue;
    }
    std::size_t len, offset;
    switch (tag & 3) {
      case 1:
        if (ie - ip < 1) return detail::fail("snappy: truncated copy", at());
        len = ((tag >> 2) & 7) + 4;
        offset = ((tag >> 5) << 8) | u8(ip);
        ip += 1;
        break;
      case 2:
        if (ie - ip < 2) return detail::fail("snappy: truncated copy", at());
        len = (tag >> 2) + 1;
        offset = u8(ip) | (u8(ip + 1) << 8);
        ip += 2;
        break;
      default:
        if (ie - ip < 4) return detail::fail("snappy: truncated copy", at());
        len = (tag >> 2) + 1;
        offset = u8(ip) | (u8(ip + 1) << 8) | (u8(ip + 2) << 16) | (u8(ip + 3) << 24);
        ip += 4;
        break;
    }
    if (offset == 0 || offset > std::size_t(op - ob)) return detail::fail("snappy: copy offset outside the output", at());
    if (std::size_t(oe - op) >= len + 16) {
      detail::copy_match_wild(op, offset, len);
    } else {
      if (std::size_t(oe - op) < len) return detail::fail("snappy: copy overflows the output", at());
      detail::copy_match(op, offset, len);
    }
    op += len;
  }
  if (op != oe) return detail::fail("snappy: output shorter than declared", at());
  return out.size();
}

// ---------------------------------------------------------------------------
// 31. LZ4 block (Parquet's LZ4_RAW codec)
// ---------------------------------------------------------------------------

/// Decompress one LZ4 block into out; returns the bytes produced (must equal out.size() for
/// Parquet, which the caller checks against the page header). Same fast-path scheme as Snappy.
inline status lz4_block_decompress(std::span<const std::byte> in, std::span<std::byte> out) {
  const std::byte* ip = in.data();
  const std::byte* const ie = ip + in.size();
  std::byte* op = out.data();
  std::byte* const ob = out.data();
  std::byte* const oe = out.data() + out.size();
  const auto at = [&] { return std::size_t(ip - in.data()); };
  const auto ext_len = [&](std::size_t& len) {
    if (len != 15) return true;
    for (;;) {
      if (ip >= ie) return false;
      const std::size_t b = std::size_t(std::uint8_t(*ip++));
      if (len > std::numeric_limits<std::size_t>::max() - b) return false;
      len += b;
      if (b != 255) return true;
    }
  };
  if (in.empty()) return detail::fail("lz4: empty block", 0);
  for (;;) {
    if (ip >= ie) return detail::fail("lz4: truncated sequence", at());
    const std::size_t token = std::size_t(std::uint8_t(*ip++));
    std::size_t lit = token >> 4;
    if (lit < 15 && ie - ip >= 16 && oe - op >= 16) {
      detail::copy16(op, ip);
      ip += lit;
      op += lit;
    } else {
      if (!ext_len(lit)) return detail::fail("lz4: truncated literal length", at());
      if (std::size_t(ie - ip) < lit) return detail::fail("lz4: literals run past the input", at());
      if (std::size_t(oe - op) < lit) return detail::fail("lz4: literals overflow the output", at());
      if (lit) std::memcpy(op, ip, lit);  // lit may be 0 into an empty output: no null memcpy
      ip += lit;
      op += lit;
    }
    if (ip == ie) break;  // the last sequence carries literals only
    if (ie - ip < 2) return detail::fail("lz4: truncated match offset", at());
    const std::size_t offset = std::size_t(std::uint8_t(ip[0])) | (std::size_t(std::uint8_t(ip[1])) << 8);
    ip += 2;
    if (offset == 0 || offset > std::size_t(op - ob)) return detail::fail("lz4: match offset outside the output", at());
    std::size_t mlen = token & 15;
    if (!ext_len(mlen)) return detail::fail("lz4: truncated match length", at());
    mlen += 4;
    if (std::size_t(oe - op) >= mlen + 16) {
      detail::copy_match_wild(op, offset, mlen);
    } else {
      if (std::size_t(oe - op) < mlen) return detail::fail("lz4: match overflows the output", at());
      detail::copy_match(op, offset, mlen);
    }
    op += mlen;
  }
  return std::size_t(op - ob);
}

}  // namespace nanom::codec

#endif  // NANOM_CODEC_HPP_INCLUDED
