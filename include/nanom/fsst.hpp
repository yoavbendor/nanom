// SPDX-License-Identifier: Apache-2.0
// nanom/fsst.hpp — FSST string decompression (Fast Static Symbol Table, Boncz / Neumann / Leis 2020),
// with the symbol table serialized as Lance writes it (rust/compression/fsst in lancedb/lance).
//
// FSST compresses a string column with one table of up to 255 symbols of 1..8 bytes. A compressed
// value is a stream of codes: 255 escapes the next byte as a literal, any other code emits its
// symbol. Lance stores the table as a fixed kSymbolTableBytes (2312) bytes:
//   [u64 header][n * u64 symbol][n * u8 length], zero-padded,
//   header = "FSST" << 32 | encoder_switch << 24 | suffix_lim << 16 | terminator << 8 | n.
// encoder_switch 0 means the writer declined to compress (Lance skips inputs under 32 KiB): the
// "compressed" values are the originals and decode copies them through.
//
// The table, the codes and their lengths come from the file, so everything is checked before use:
// the table's size and magic, every declared symbol length (1..8), every code against the symbol
// count, and an escape with no byte after it. An undeclared code is an error, not an empty symbol.
// Integers are little-endian (Lance writes them native-endian, which is little-endian in practice).
//
// The encoder (training and compression) is in fsst_encode.hpp; reading code does not include it.
#ifndef NANOM_FSST_HPP_INCLUDED
#define NANOM_FSST_HPP_INCLUDED

#include "codec.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace nanom::codec::fsst {

/// Exact size of a serialized table: not a maximum; any other length is malformed.
inline constexpr std::size_t kSymbolTableBytes = 8 + 256 * 8 + 256;
/// The longest symbol, and therefore the most bytes one code expands to.
inline constexpr std::size_t kMaxSymbolLength = 8;
/// The code that escapes the next byte as a literal.
inline constexpr std::uint8_t kEscape = 255;

/// "FSST" in the header's top 32 bits; the low 32 hold encoder_switch / suffix_lim / terminator / n.
inline constexpr std::uint64_t kMagic = std::uint64_t{0x46535354} << 32;
inline constexpr std::uint64_t kEncoderSwitchBit = std::uint64_t{1} << 24;

struct symbol_table {
  /// encoder_switch was 0: values are stored verbatim and copied, not decoded.
  bool passthrough = true;
  std::uint32_t symbol_count = 0;
  /// Symbol bytes; only the first lengths[i] bytes of entry i are meaningful.
  std::array<std::array<std::uint8_t, kMaxSymbolLength>, 256> symbols{};
  /// Each declared symbol's length, 1..8.
  std::array<std::uint8_t, 256> lengths{};
};

/// The most bytes decode() can write for `n` code bytes: every code a whole 8-byte word, plus the
/// word the last one may copy past its symbol.
constexpr std::size_t max_decoded_size(std::size_t n) { return n * kMaxSymbolLength + kMaxSymbolLength; }

namespace detail {
inline std::uint64_t load_le64(const std::byte* p) {
  std::uint64_t v;
  std::memcpy(&v, p, 8);
  if constexpr (std::endian::native == std::endian::big) v = std::byteswap(v);
  return v;
}
}  // namespace detail

/// Parse a serialized table into `out`. `out` is written only on success, so a refused table never
/// leaves a half-built one behind. The error's `at` is the offending byte.
inline status parse_symbol_table(std::span<const std::byte> bytes, symbol_table& out) {
  if (bytes.size() != kSymbolTableBytes) return codec::detail::fail("fsst: symbol table size is not 2312 bytes", bytes.size());
  const std::uint64_t header = detail::load_le64(bytes.data());
  if ((header & kMagic) != kMagic) return codec::detail::fail("fsst: symbol table has the wrong magic", 0);
  symbol_table t;
  t.passthrough = (header & kEncoderSwitchBit) == 0;
  t.symbol_count = static_cast<std::uint32_t>(header & 0xFF);
  // Symbols first, then one length byte per symbol right after them (not after all 256 slots).
  std::size_t pos = 8;
  for (std::uint32_t i = 0; i < t.symbol_count; ++i, pos += kMaxSymbolLength)
    std::memcpy(t.symbols[i].data(), bytes.data() + pos, kMaxSymbolLength);
  for (std::uint32_t i = 0; i < t.symbol_count; ++i, ++pos) {
    const auto length = std::uint8_t(bytes[pos]);
    if (length < 1 || length > kMaxSymbolLength) return codec::detail::fail("fsst: symbol length is not 1..8", pos);
    t.lengths[i] = length;
  }
  out = t;
  return kSymbolTableBytes;
}

/// Decode one value's codes without bounds checks on `dst`, advancing it past the decoded bytes: the
/// caller guarantees max_decoded_size(in.size()) writable bytes there (symbols are copied as whole
/// 8-byte words). Codes are still checked: on a bad one it returns false, leaves `dst` where it was
/// and, given `error`, says why. The form for decoding many values into one buffer.
inline bool decode_unchecked(const symbol_table& table, std::span<const std::byte> in, std::byte*& dst,
                             codec_error* error = nullptr) {
  const auto* data = reinterpret_cast<const std::uint8_t*>(in.data());
  const std::size_t size = in.size();
  if (table.passthrough) {
    if (size) std::memcpy(dst, data, size);
    dst += size;
    return true;
  }
  std::byte* out = dst;
  for (std::size_t i = 0; i < size;) {
    const std::uint8_t code = data[i];
    if (code == kEscape) {
      if (i + 1 >= size) {
        if (error) *error = codec_error{"fsst: escape at the end of a value has no byte", i};
        return false;
      }
      *out++ = std::byte(data[i + 1]);
      i += 2;
      continue;
    }
    if (code >= table.symbol_count) {
      if (error) *error = codec_error{"fsst: code is not in the symbol table", i};
      return false;
    }
    std::memcpy(out, table.symbols[code].data(), kMaxSymbolLength);
    out += table.lengths[code];
    ++i;
  }
  dst = out;
  return true;
}

/// Decode one value's codes into `out`, which must hold max_decoded_size(in.size()) bytes (checked).
/// Returns the bytes decoded; the bytes of `out` past them are scratch.
inline status decode(const symbol_table& table, std::span<const std::byte> in, std::span<std::byte> out) {
  if (out.size() < max_decoded_size(in.size())) return codec::detail::fail("fsst: output is smaller than max_decoded_size", 0);
  std::byte* dst = out.data();
  codec_error error;
  if (!decode_unchecked(table, in, dst, &error)) return unexpected<codec_error>(error);
  return std::size_t(dst - out.data());
}

}  // namespace nanom::codec::fsst

#endif  // NANOM_FSST_HPP_INCLUDED
