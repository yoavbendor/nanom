// SPDX-License-Identifier: Apache-2.0
// nanom/fsst_encode.hpp — FSST compression: train a symbol table, compress values with it, and
// serialize the table as Lance stores it. The inverse of nanom/fsst.hpp.
//
// Training follows the paper and Lance's build_symbol_table (rust/compression/fsst): six rounds over
// a ~16 KiB sample, each compressing the sample with the current table, counting every symbol and
// every adjacent pair, and keeping the 255 candidates with the highest gain (count x length, single
// bytes x8); the table of the round that compressed the sample best wins. Three deliberate
// differences, none visible to a decoder: the sample is drawn with a fixed seed, so the same input
// always gives the same table; a candidate is identified by its bytes, so one string reached two
// ways is one candidate with the summed gain; and matching never reads past the end of a value.
//
// Compression takes, at each position, the longest symbol that matches, else an escape and the
// literal byte, so a value compresses to at most 2x its size.
//
// Symbols are matched against 8-byte words loaded in native order, as Lance's encoder does: the
// encoder assumes a little-endian host. The table it serializes is little-endian either way.
#ifndef NANOM_FSST_ENCODE_HPP_INCLUDED
#define NANOM_FSST_ENCODE_HPP_INCLUDED

#include "fsst.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <utility>
#include <vector>

namespace nanom::codec::fsst {

/// A trained table, ready to compress with. Symbol i is code i; code 255 is the escape.
struct encoder {
  struct slot {
    std::uint64_t value = 0;  ///< the symbol's bytes, little-endian, zero above `length`
    std::uint8_t length = 0;  ///< 0 = empty slot
    std::uint8_t code = 0;
  };
  static constexpr std::uint16_t kNone = 0xFFFF;

  std::uint32_t symbol_count = 0;
  std::array<std::uint64_t, 255> symbols{};
  std::array<std::uint8_t, 255> lengths{};
  /// Lookups: one-byte symbols by byte, two-byte ones by their (little-endian) u16, longer ones in a
  /// 1024-slot table hashed on their first three bytes (one symbol per slot).
  std::array<std::uint16_t, 256> byte_codes{};
  std::vector<std::uint16_t> short_codes;
  std::array<slot, 1024> long_codes{};
  /// For compression, by the next two bytes: (length << 8) | code of the best symbol of at most two
  /// bytes -- the two-byte one, else the one-byte one, else the escape (length 1). Built by train().
  std::vector<std::uint16_t> short_or_byte;
};

/// The most bytes compressing `n` bytes can produce (every byte escaped).
constexpr std::size_t max_compressed_size(std::size_t n) { return 2 * n; }

namespace enc_detail {

inline constexpr std::size_t kLongSlots = 1024;
inline constexpr std::size_t kSampleTarget = std::size_t{1} << 14;  // FSST_SAMPLETARGET
inline constexpr std::uint16_t kMaxSymbols = 255;                    // code 255 is the escape
/// Construction codes: 0..254 are real symbols, 256 + b is byte b escaped.
inline constexpr std::uint16_t kPseudo = 256;
inline constexpr std::size_t kCodes = 512;

inline std::uint64_t hash3(std::uint64_t word) {
  const auto w = word & 0xFFFFFF;
  const auto m = w * 2971215073ULL;  // FSST_HASH_PRIME
  return (m ^ (m >> 15)) & (kLongSlots - 1);
}

inline std::uint64_t mask(unsigned length) {
  return length >= 8 ? ~std::uint64_t{0} : ((std::uint64_t{1} << (8 * length)) - 1);
}

/// Up to 8 bytes at `p`, zero-filled past `remaining`.
inline std::uint64_t load(const std::uint8_t* p, std::size_t remaining) {
  std::uint64_t w = 0;
  std::memcpy(&w, p, std::min<std::size_t>(remaining, 8));
  return w;
}

inline void reset(encoder& e) {
  e.symbol_count = 0;
  e.byte_codes.fill(encoder::kNone);
  e.short_codes.assign(65536, encoder::kNone);
  e.long_codes.fill(encoder::slot{});
}

/// Add a symbol as the next code. False when its three-byte hash slot is taken: that symbol is
/// skipped, as in Lance.
inline bool add(encoder& e, std::uint64_t value, unsigned length) {
  const auto code = static_cast<std::uint16_t>(e.symbol_count);
  if (length == 1) {
    e.byte_codes[value & 0xFF] = code;
  } else if (length == 2) {
    e.short_codes[value & 0xFFFF] = code;
  } else {
    auto& s = e.long_codes[hash3(value)];
    if (s.length != 0) return false;
    s = encoder::slot{value, static_cast<std::uint8_t>(length), static_cast<std::uint8_t>(code)};
  }
  e.symbols[code] = value;
  e.lengths[code] = static_cast<std::uint8_t>(length);
  ++e.symbol_count;
  return true;
}

/// The longest symbol matching at `p`, or kNone.
inline std::uint16_t find(const encoder& e, const std::uint8_t* p, std::size_t remaining, unsigned& length) {
  const auto word = load(p, remaining);
  if (remaining >= 3) {
    const auto& s = e.long_codes[hash3(word)];
    if (s.length != 0 && s.length <= remaining && (word & mask(s.length)) == s.value) {
      length = s.length;
      return s.code;
    }
  }
  if (remaining >= 2) {
    const auto code = e.short_codes[word & 0xFFFF];
    if (code != encoder::kNone) {
      length = 2;
      return code;
    }
  }
  length = 1;
  return e.byte_codes[word & 0xFF];
}

using value_list = std::vector<std::span<const std::byte>>;

/// A deterministic sample of about kSampleTarget bytes: every value when they are that small,
/// otherwise values drawn at random (splitmix64, fixed seed) until the target is reached.
template <class ValueAt>
value_list make_sample(std::size_t n, ValueAt& value_at) {
  std::size_t total = 0;
  for (std::size_t i = 0; i < n; ++i) total += value_at(i).size();
  value_list sample;
  if (total <= kSampleTarget) {
    sample.reserve(n);
    for (std::size_t i = 0; i < n; ++i) sample.push_back(value_at(i));
    return sample;
  }
  std::uint64_t state = 0x9E3779B97F4A7C15ULL ^ total;
  std::size_t taken = 0;
  while (taken < kSampleTarget) {
    state += 0x9E3779B97F4A7C15ULL;
    auto z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z ^= z >> 31;
    const std::span<const std::byte> v = value_at(static_cast<std::size_t>(z % n));
    sample.push_back(v);
    taken += v.size();
  }
  return sample;
}

struct symbol {
  std::uint64_t value;
  unsigned length;
};

inline symbol symbol_of(const encoder& e, std::uint16_t code) {
  if (code >= kPseudo) return {static_cast<std::uint64_t>(code - kPseudo), 1};
  return {e.symbols[code], e.lengths[code]};
}

}  // namespace enc_detail

/// Train a table on `n` values, value_at(i) giving value i as a std::span<const std::byte> (a sample
/// of them is used if they are large; only the sampled ones are read past their size). False when no
/// symbol is worth having (empty input, say): store the values uncompressed.
template <class ValueAt>
bool train(std::size_t n, ValueAt&& value_at, encoder& out) {
  using namespace enc_detail;
  const auto sample = make_sample(n, value_at);
  encoder table;
  reset(table);
  encoder best = table;
  std::int64_t best_gain = std::numeric_limits<std::int64_t>::min();
  std::vector<std::uint16_t> count1(kCodes);
  std::vector<std::uint16_t> count2(kCodes * kCodes);
  // Rows of count2 written this round, so clearing it costs what was used rather than 512 KiB.
  std::vector<std::uint16_t> touched_rows;
  std::vector<bool> row_touched(kCodes);
  const auto bump = [](std::uint16_t& c) {
    if (c != 0xFFFF) ++c;
  };
  const auto code_at = [&table](const std::uint8_t* p, std::size_t remaining, unsigned& length) {
    const auto code = find(table, p, remaining, length);
    return code == encoder::kNone ? static_cast<std::uint16_t>(kPseudo + *p) : code;
  };

  for (const unsigned frac : {8U, 38U, 68U, 98U, 108U, 128U}) {
    // Compress the sample with the current table, counting symbols and adjacent pairs.
    std::fill(count1.begin(), count1.end(), std::uint16_t{0});
    for (const auto row : touched_rows) {
      std::fill_n(count2.begin() + static_cast<std::ptrdiff_t>(row * kCodes), kCodes, std::uint16_t{0});
      row_touched[row] = false;
    }
    touched_rows.clear();
    std::int64_t gain = 0;
    for (const auto& v : sample) {
      const auto* data = reinterpret_cast<const std::uint8_t*>(v.data());
      const std::size_t size = v.size();
      if (size == 0) continue;
      std::size_t pos = 0;
      unsigned length = 0;
      auto prev = code_at(data, size, length);
      pos += length;
      gain += std::max<std::int64_t>(0, static_cast<std::int64_t>(length) - 1 - (prev >= kPseudo ? 1 : 0));
      while (pos < size) {
        bump(count1[prev]);
        if (symbol_of(table, prev).length != 1) bump(count1[kPseudo + data[pos]]);
        const auto cur = code_at(data + pos, size - pos, length);
        gain += std::max<std::int64_t>(0, static_cast<std::int64_t>(length) - 1 - (cur >= kPseudo ? 1 : 0));
        if (frac < 128) {  // no pairs in the last round
          if (!row_touched[prev]) {
            row_touched[prev] = true;
            touched_rows.push_back(prev);
          }
          bump(count2[prev * kCodes + cur]);
          if (length > 1) bump(count2[prev * kCodes + kPseudo + data[pos]]);
        }
        pos += length;
        prev = cur;
      }
      bump(count1[prev]);
    }
    if (gain >= best_gain) {
      best_gain = gain;
      best = table;
    }

    // Candidates: every symbol seen, and every pair seen, weighted by count x length.
    std::map<std::pair<std::uint64_t, unsigned>, std::uint64_t> candidates;
    const auto consider = [&](symbol s, std::uint64_t count) {
      if (count < (5U * frac) / 128U) return;
      candidates[{s.value, s.length}] += count * s.length;
    };
    std::vector<std::uint16_t> live;
    for (std::uint16_t c = 0; c < table.symbol_count; ++c) live.push_back(c);
    for (std::uint16_t b = 0; b < 256; ++b) live.push_back(static_cast<std::uint16_t>(kPseudo + b));
    for (const auto c1 : live) {
      const auto n1 = count1[c1];
      if (n1 == 0) continue;
      const auto s1 = symbol_of(table, c1);
      // Single bytes count 8x: they cut the escape rate (the paper's heuristic).
      consider(s1, static_cast<std::uint64_t>(s1.length == 1 ? 8 : 1) * n1);
      if (frac >= 128 || s1.length == 8 || !row_touched[c1]) continue;
      for (const auto c2 : live) {
        const auto n2 = count2[c1 * kCodes + c2];
        if (n2 == 0) continue;
        const auto s2 = symbol_of(table, c2);
        const unsigned length = std::min(8U, s1.length + s2.length);
        const auto value = (s1.value | (s2.value << (8 * s1.length))) & mask(length);
        consider(symbol{value, length}, n2);
      }
    }
    std::vector<std::pair<std::uint64_t, std::pair<std::uint64_t, unsigned>>> ranked;
    ranked.reserve(candidates.size());
    for (const auto& [sym, g] : candidates) ranked.emplace_back(g, sym);
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
      return a.first != b.first ? a.first > b.first : a.second.first < b.second.first;
    });
    reset(table);
    for (const auto& [g, sym] : ranked) {
      if (table.symbol_count == kMaxSymbols) break;
      add(table, sym.first, sym.second);
    }
  }
  if (best.symbol_count == 0) return false;
  best.short_or_byte.resize(65536);
  for (std::uint32_t w = 0; w < 65536; ++w) {
    const auto two = best.short_codes[w];
    const auto one = best.byte_codes[w & 0xFF];
    best.short_or_byte[w] = two != encoder::kNone   ? static_cast<std::uint16_t>((2U << 8) | two)
                            : one != encoder::kNone ? static_cast<std::uint16_t>((1U << 8) | one)
                                                    : static_cast<std::uint16_t>((1U << 8) | kEscape);
  }
  out = std::move(best);
  return true;
}

/// train() over a list of values.
inline bool train(std::span<const std::span<const std::byte>> values, encoder& out) {
  return train(values.size(), [&](std::size_t i) { return values[i]; }, out);
}

/// Compress one value without bounds checks on `dst`: the caller guarantees
/// max_compressed_size(in.size()) writable bytes there. Returns the bytes written.
inline std::size_t compress_unchecked(const encoder& e, std::span<const std::byte> in, std::byte* dst) {
  using namespace enc_detail;
  const auto* data = reinterpret_cast<const std::uint8_t*>(in.data());
  const std::size_t size = in.size();
  auto* out = reinterpret_cast<std::uint8_t*>(dst);
  const auto* const begin = out;
  std::size_t pos = 0;
  if (!e.short_or_byte.empty()) {
    // While 8 bytes remain: one unaligned load, the long-symbol slot, then one lookup that settles
    // the two-byte / one-byte / escape cases. The code and the literal byte are both stored and
    // `out` advances past the literal only for an escape (it stays within 2 * size).
    while (pos + 8 <= size) {
      std::uint64_t word = 0;
      std::memcpy(&word, data + pos, 8);
      const auto& s = e.long_codes[hash3(word)];
      if (s.length != 0 && ((word ^ s.value) << (64 - 8 * s.length)) == 0) {
        *out++ = s.code;
        pos += s.length;
        continue;
      }
      const auto entry = e.short_or_byte[word & 0xFFFF];
      const auto code = static_cast<std::uint8_t>(entry & 0xFF);
      out[0] = code;
      out[1] = static_cast<std::uint8_t>(word & 0xFF);
      out += code == kEscape ? 2 : 1;
      pos += entry >> 8;
    }
    // The last < 8 bytes, the same way from a zero-padded copy (so the loads stay in bounds), with
    // no match allowed to run past the value.
    if (pos < size) {
      std::array<std::uint8_t, 16> tail{};
      const auto rest = size - pos;
      std::memcpy(tail.data(), data + pos, rest);
      std::size_t at = 0;
      while (at < rest) {
        std::uint64_t word = 0;
        std::memcpy(&word, tail.data() + at, 8);
        const auto remaining = rest - at;
        const auto& s = e.long_codes[hash3(word)];
        if (s.length != 0 && s.length <= remaining && ((word ^ s.value) << (64 - 8 * s.length)) == 0) {
          *out++ = s.code;
          at += s.length;
          continue;
        }
        std::uint16_t entry = 0;
        if (remaining >= 2) {
          entry = e.short_or_byte[word & 0xFFFF];
        } else {
          const auto one = e.byte_codes[word & 0xFF];
          entry = static_cast<std::uint16_t>((1U << 8) | (one != encoder::kNone ? one : kEscape));
        }
        const auto code = static_cast<std::uint8_t>(entry & 0xFF);
        out[0] = code;
        out[1] = static_cast<std::uint8_t>(word & 0xFF);
        out += code == kEscape ? 2 : 1;
        at += entry >> 8;
      }
    }
    return static_cast<std::size_t>(out - begin);
  }
  while (pos < size) {  // an encoder built without train(): the plain lookups
    unsigned length = 0;
    const auto code = find(e, data + pos, size - pos, length);
    if (code == encoder::kNone) {
      *out++ = kEscape;
      *out++ = data[pos];
      ++pos;
    } else {
      *out++ = static_cast<std::uint8_t>(code);
      pos += length;
    }
  }
  return static_cast<std::size_t>(out - begin);
}

/// Append the compression of one value to `out`.
inline void compress(const encoder& e, std::span<const std::byte> in, std::vector<std::byte>& out) {
  const auto at = out.size();
  out.resize(at + max_compressed_size(in.size()));
  out.resize(at + compress_unchecked(e, in, out.data() + at));
}

/// The kSymbolTableBytes table parse_symbol_table (and Lance) reads, encoder switch on.
inline std::array<std::byte, kSymbolTableBytes> serialize(const encoder& e) {
  std::array<std::byte, kSymbolTableBytes> out{};
  const auto put64 = [&](std::size_t at, std::uint64_t v) {
    if constexpr (std::endian::native == std::endian::big) v = std::byteswap(v);
    std::memcpy(out.data() + at, &v, 8);
  };
  put64(0, kMagic | kEncoderSwitchBit | e.symbol_count);
  std::size_t pos = 8;
  for (std::uint32_t i = 0; i < e.symbol_count; ++i, pos += 8) put64(pos, e.symbols[i]);
  for (std::uint32_t i = 0; i < e.symbol_count; ++i) out[pos++] = std::byte(e.lengths[i]);
  return out;
}

}  // namespace nanom::codec::fsst

#endif  // NANOM_FSST_ENCODE_HPP_INCLUDED
