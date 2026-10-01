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
}  // namespace detail

// ---------------------------------------------------------------------------
// 30. Snappy (raw block format — what Parquet's SNAPPY codec stores)
// ---------------------------------------------------------------------------

/// Uncompressed length from the Snappy preamble (to size/validate the output before decoding).
inline std::optional<std::uint32_t> snappy_uncompressed_length(std::span<const std::byte> in) {
  auto r = varint_u32(from(in));
  if (!r) return std::nullopt;
  return r->value;
}

/// Decompress a raw Snappy block into exactly out.size() bytes (the preamble length must match).
inline status snappy_decompress(std::span<const std::byte> in, std::span<std::byte> out) {
  auto pre = varint_u32(from(in));
  if (!pre) return detail::fail("snappy: bad length preamble", 0);
  if (pre->value != out.size()) return detail::fail("snappy: length preamble does not match the page header", 0);
  const auto* ip = reinterpret_cast<const std::uint8_t*>(pre->rest.first);
  const auto* const ie = reinterpret_cast<const std::uint8_t*>(in.data() + in.size());
  std::byte* op = out.data();
  std::byte* const ob = out.data();
  std::byte* const oe = out.data() + out.size();
  const auto at = [&] { return std::size_t(reinterpret_cast<const std::byte*>(ip) - in.data()); };
  while (ip < ie) {
    const std::uint8_t tag = *ip++;
    if ((tag & 3) == 0) {  // literal
      std::size_t len = tag >> 2;
      if (len >= 60) {
        const std::size_t nb = len - 59;  // 1..4 length bytes
        if (std::size_t(ie - ip) < nb) return detail::fail("snappy: truncated literal length", at());
        len = 0;
        for (std::size_t i = 0; i < nb; ++i) len |= std::size_t(ip[i]) << (8 * i);
        ip += nb;
      }
      len += 1;
      if (len <= 16 && ie - ip >= 16 && oe - op >= 16) {
        // short literal with slack on both sides: one fixed 16-byte copy (the bytes past len are
        // inside the output and get overwritten by what follows)
        std::memcpy(op, ip, 16);
        ip += len;
        op += len;
        continue;
      }
      if (std::size_t(ie - ip) < len) return detail::fail("snappy: literal runs past the input", at());
      if (std::size_t(oe - op) < len) return detail::fail("snappy: literal overflows the output", at());
      std::memcpy(op, ip, len);
      ip += len;
      op += len;
      continue;
    }
    std::size_t len = 0, offset = 0;
    switch (tag & 3) {
      case 1:
        if (ie - ip < 1) return detail::fail("snappy: truncated copy", at());
        len = ((tag >> 2) & 7) + 4;
        offset = (std::size_t(tag >> 5) << 8) | ip[0];
        ip += 1;
        break;
      case 2:
        if (ie - ip < 2) return detail::fail("snappy: truncated copy", at());
        len = (tag >> 2) + 1;
        offset = std::size_t(ip[0]) | (std::size_t(ip[1]) << 8);
        ip += 2;
        break;
      default:
        if (ie - ip < 4) return detail::fail("snappy: truncated copy", at());
        len = (tag >> 2) + 1;
        offset = std::size_t(ip[0]) | (std::size_t(ip[1]) << 8) | (std::size_t(ip[2]) << 16) |
                 (std::size_t(ip[3]) << 24);
        ip += 4;
        break;
    }
    if (offset == 0 || offset > std::size_t(op - ob)) return detail::fail("snappy: copy offset outside the output", at());
    if (len <= 16 && offset >= 8 && oe - op >= 16) {
      // short match, non-overlapping within 8 bytes: two fixed 8-byte copies (sequential, so a
      // second chunk that overlaps the first reads bytes the first already wrote — LZ semantics)
      std::memcpy(op, op - offset, 8);
      std::memcpy(op + 8, op - offset + 8, 8);
      op += len;
      continue;
    }
    if (std::size_t(oe - op) < len) return detail::fail("snappy: copy overflows the output", at());
    detail::copy_match(op, offset, len);
    op += len;
  }
  if (op != oe) return detail::fail("snappy: output shorter than declared", at());
  return out.size();
}

// ---------------------------------------------------------------------------
// 31. LZ4 block (Parquet's LZ4_RAW codec)
// ---------------------------------------------------------------------------

/// Decompress one LZ4 block into out; returns the bytes produced (must equal out.size() for
/// Parquet, which the caller checks against the page header).
inline status lz4_block_decompress(std::span<const std::byte> in, std::span<std::byte> out) {
  const auto* ip = reinterpret_cast<const std::uint8_t*>(in.data());
  const auto* const ie = ip + in.size();
  std::byte* op = out.data();
  std::byte* const ob = out.data();
  std::byte* const oe = out.data() + out.size();
  const auto at = [&] { return std::size_t(reinterpret_cast<const std::byte*>(ip) - in.data()); };
  const auto ext_len = [&](std::size_t& len) {
    if (len != 15) return true;
    for (;;) {
      if (ip >= ie) return false;
      const std::uint8_t b = *ip++;
      if (len > std::numeric_limits<std::size_t>::max() - b) return false;
      len += b;
      if (b != 255) return true;
    }
  };
  if (in.empty()) return detail::fail("lz4: empty block", 0);
  for (;;) {
    if (ip >= ie) return detail::fail("lz4: truncated sequence", at());
    const std::uint8_t token = *ip++;
    std::size_t lit = token >> 4;
    if (!ext_len(lit)) return detail::fail("lz4: truncated literal length", at());
    if (std::size_t(ie - ip) < lit) return detail::fail("lz4: literals run past the input", at());
    if (std::size_t(oe - op) < lit) return detail::fail("lz4: literals overflow the output", at());
    if (lit) std::memcpy(op, ip, lit);  // lit may be 0 into an empty output: no null memcpy
    ip += lit;
    op += lit;
    if (ip == ie) break;  // the last sequence carries literals only
    if (ie - ip < 2) return detail::fail("lz4: truncated match offset", at());
    const std::size_t offset = std::size_t(ip[0]) | (std::size_t(ip[1]) << 8);
    ip += 2;
    if (offset == 0 || offset > std::size_t(op - ob)) return detail::fail("lz4: match offset outside the output", at());
    std::size_t mlen = token & 15;
    if (!ext_len(mlen)) return detail::fail("lz4: truncated match length", at());
    mlen += 4;
    if (std::size_t(oe - op) < mlen) return detail::fail("lz4: match overflows the output", at());
    detail::copy_match(op, offset, mlen);
    op += mlen;
  }
  return std::size_t(op - ob);
}

}  // namespace nanom::codec

#endif  // NANOM_CODEC_HPP_INCLUDED
