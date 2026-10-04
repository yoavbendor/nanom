// SPDX-License-Identifier: Apache-2.0
// nanom/fastlanes.hpp — FastLanes 1024-value bit unpacking (Lance's InlineBitpacking and format 2.0
// Bitpacked pages; the kernel Lance vendors as lance-bitpacking = spiraldb/fastlanes).
//
// FastLanes packs a block of exactly 1024 unsigned values of one word type T (u8, u16, u32, u64) at
// `width` bits each, in a transposed layout so every row of the block is one SIMD-friendly loop over
// LANES = 1024 / bits(T) words. A block packed at `width` takes packed_words_1024<T>(width) words of
// T, i.e. 128 * width bytes, whatever T is. The value order is FastLanes' FL_ORDER: input element
// fl_index(row, lane) sits in lane `lane` of row `row`.
//
// Same safety rule as columnar.hpp — CHECK AT THE BOUNDARY, RUN UNCHECKED INSIDE: unpack_1024
// validates the width and the packed span once, then runs a loop whose width is a template constant
// (one instantiation per width, chosen through a table) so every shift and word boundary is folded.
// The encoder, pack_1024, is in columnar_encode.hpp; reading code does not include it.
#ifndef NANOM_FASTLANES_HPP_INCLUDED
#define NANOM_FASTLANES_HPP_INCLUDED

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>
#include <utility>

namespace nanom::columnar::fastlanes {

/// The FastLanes word types.
template <class T>
concept word = std::is_same_v<T, std::uint8_t> || std::is_same_v<T, std::uint16_t> ||
               std::is_same_v<T, std::uint32_t> || std::is_same_v<T, std::uint64_t>;

inline constexpr std::size_t kBlock = 1024;  ///< values per FastLanes block

/// Bits in T: the largest width a block of T can be packed at.
template <word T>
inline constexpr unsigned kBits = sizeof(T) * 8U;

/// Words of T one block packed at `width` bits takes (128 * width bytes).
template <word T>
constexpr std::size_t packed_words_1024(unsigned width) {
  return (kBlock * width) / kBits<T>;
}

namespace detail {

inline constexpr unsigned kFlOrder[8] = {0, 4, 2, 6, 1, 5, 3, 7};

/// Index of the input value in lane `lane` of row `row`.
constexpr std::size_t fl_index(std::size_t row, std::size_t lane) {
  return static_cast<std::size_t>(kFlOrder[row / 8U]) * 16U + (row % 8U) * 128U + lane;
}

template <word T>
constexpr T fl_mask(unsigned width) {
  if (width == 0U) return T(0);
  if (width >= kBits<T>) return static_cast<T>(~T(0));
  return static_cast<T>((T(1) << width) - T(1));
}

// Row-outer, lane-inner: for a fixed row, both fl_index(row, lane) and the packed words are
// contiguous in `lane`, so each inner loop is a contiguous run the compiler vectorizes. Width is a
// template constant, as in the Rust crate's macro-generated per-width functions.
template <word T, unsigned Width>
void unpack_w(const T* in, T* out) {
  constexpr unsigned bits = kBits<T>;
  constexpr std::size_t lanes = kBlock / bits;
  T src[128];  // lanes <= 128 (the u8 case)
  std::memcpy(src, in, lanes * sizeof(T));
  for (unsigned row = 0; row < bits; ++row) {
    const unsigned shift = (row * Width) % bits;
    const unsigned curr_word = (row * Width) / bits;
    const unsigned next_word = ((row + 1U) * Width) / bits;
    T* out_row = out + fl_index(row, 0);
    if (next_word > curr_word) {
      const unsigned remaining = ((row + 1U) * Width) % bits;
      const unsigned current_bits = Width - remaining;
      const T low_mask = fl_mask<T>(current_bits);
      for (std::size_t lane = 0; lane < lanes; ++lane)
        out_row[lane] = static_cast<T>((src[lane] >> shift) & low_mask);
      if (next_word < Width) {
        const T* next_in = in + lanes * next_word;
        const T high_mask = fl_mask<T>(remaining);
        for (std::size_t lane = 0; lane < lanes; ++lane) {
          src[lane] = next_in[lane];
          out_row[lane] = static_cast<T>(out_row[lane] | static_cast<T>((src[lane] & high_mask) << current_bits));
        }
      }
    } else {
      constexpr T mask = fl_mask<T>(Width);
      for (std::size_t lane = 0; lane < lanes; ++lane) out_row[lane] = static_cast<T>((src[lane] >> shift) & mask);
    }
  }
}

}  // namespace detail

/// Unpack one block without checks: `in` holds packed_words_1024<T>(width) words, `out` 1024 values,
/// and width <= kBits<T>. Callers that validated those once (unpack_1024 does) loop over this.
template <word T>
void unpack_1024_unchecked(unsigned width, const T* in, T* out) {
  constexpr unsigned bits = kBits<T>;
  constexpr std::size_t lanes = kBlock / bits;
  if (width == 0U) {
    std::memset(out, 0, kBlock * sizeof(T));
    return;
  }
  if (width == bits) {
    for (unsigned row = 0; row < bits; ++row)
      std::memcpy(out + detail::fl_index(row, 0), in + lanes * row, lanes * sizeof(T));
    return;
  }
  using fn = void (*)(const T*, T*);
  static constexpr auto table = []<unsigned... Ws>(std::integer_sequence<unsigned, Ws...>) {
    return std::array<fn, sizeof...(Ws)>{&detail::unpack_w<T, Ws + 1U>...};
  }(std::make_integer_sequence<unsigned, bits - 1U>{});
  table[width - 1U](in, out);
}

/// Unpack one block of 1024 values packed at `width` bits. False, writing nothing, when the width
/// is over kBits<T> or `packed` holds fewer than packed_words_1024<T>(width) words; extra words
/// are ignored.
template <word T>
bool unpack_1024(unsigned width, std::span<const T> packed, std::span<T, kBlock> out) {
  if (width > kBits<T> || packed.size() < packed_words_1024<T>(width)) return false;
  unpack_1024_unchecked<T>(width, packed.data(), out.data());
  return true;
}

}  // namespace nanom::columnar::fastlanes

#endif  // NANOM_FASTLANES_HPP_INCLUDED
