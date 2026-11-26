// SPDX-License-Identifier: Apache-2.0
// nanom/checksum.hpp — the checksums network and automotive formats carry: the Internet checksum
// (RFC 1071) with the IPv4/IPv6 pseudo-headers and incremental update (RFC 1624), and the CRCs the
// AUTOSAR CRC library (SWS_Crc) defines for E2E protection. Standalone: needs only the standard
// library, so it can be included on its own, and every function is usable in constant expressions.
//
//   Internet checksum (namespace nanom::inet)
//     inet::checksum(bytes)                       one span
//     inet::checksum({hdr, payload})              scatter/gather: any number of spans, any lengths
//     inet::sum s; s.add(a).add(b); s.checksum()  streaming accumulator (odd-length parts handled)
//     inet::pseudo_header_v4(src, dst, proto, len) / pseudo_header_v6(...)  bytes for UDP/TCP
//     inet::update16(csum, old, new) / update32   RFC 1624 eqn. 3: patch a stored checksum when a
//                                                 16-/32-bit field changes, without re-summing
//   CRCs (namespace nanom, table driven, slicing-by-8, tables generated at compile time)
//     crc8_sae_j1850  crc8_h2f  crc16_ccitt_false  crc16_arc  crc32  crc32_p4  crc64
//     crc32::compute(bytes)                       one shot
//     crc32 c; c.update(a).update(b); c.value()   streaming (start / update / finalize)
//     crc32::resume(previous_value)               AUTOSAR's "start value, not first call" chaining
//
// Both plug into emit.hpp's computed fields; see test_checksum.cpp for an IPv4 header checksum,
// a UDP checksum over its pseudo-header (emit_ctx::prefix), and an E2E-style CRC field.
#ifndef NANOM_CHECKSUM_HPP_INCLUDED
#define NANOM_CHECKSUM_HPP_INCLUDED

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string_view>
#include <type_traits>

#if defined(__GNUC__) || defined(__clang__)
#  define NANOM_CSUM_INLINE [[gnu::always_inline]] inline
#else
#  define NANOM_CSUM_INLINE inline
#endif

namespace nanom {

namespace detail {
template <class B>
concept checksum_byte = std::same_as<std::remove_cv_t<B>, std::byte> ||
                        std::same_as<std::remove_cv_t<B>, unsigned char> ||
                        std::same_as<std::remove_cv_t<B>, char> ||
                        std::same_as<std::remove_cv_t<B>, signed char>;

// Little-endian 64-bit load (byte i -> bits 8i..8i+7), valid in constant expressions.
template <class B>
constexpr std::uint64_t load_le64(const B* p) noexcept {
  if (std::is_constant_evaluated()) {
    std::uint64_t w = 0;
    for (int i = 7; i >= 0; --i) w = (w << 8) | std::uint8_t(p[i]);
    return w;
  }
  std::uint64_t w;
  std::memcpy(&w, p, 8);
  if constexpr (std::endian::native == std::endian::big) w = std::byteswap(w);
  return w;
}
template <class B>
constexpr std::uint64_t load_be64(const B* p) noexcept {
  if (std::is_constant_evaluated()) {
    std::uint64_t w = 0;
    for (int i = 0; i < 8; ++i) w = (w << 8) | std::uint8_t(p[i]);
    return w;
  }
  std::uint64_t w;
  std::memcpy(&w, p, 8);
  if constexpr (std::endian::native == std::endian::little) w = std::byteswap(w);
  return w;
}
}  // namespace detail

// ===========================================================================
// Internet checksum (RFC 1071)
// ===========================================================================
namespace inet {

namespace detail {
constexpr std::uint16_t fold64(std::uint64_t s) noexcept {
  s = (s & 0xffffffffu) + (s >> 32);
  s = (s & 0xffffffffu) + (s >> 32);
  s = (s & 0xffffu) + (s >> 16);
  s = (s & 0xffffu) + (s >> 16);
  return std::uint16_t(s);
}
constexpr std::uint16_t swap16(std::uint16_t v) noexcept { return std::uint16_t((v >> 8) | (v << 8)); }

/// The one's-complement sum of `n` bytes taken as big-endian 16-bit words starting at an even
/// position (a trailing odd byte is the high half of a zero-padded word), folded to 16 bits.
///
/// The hot loop adds the bytes as LITTLE-endian 32-bit halves of 64-bit loads into a 64-bit
/// accumulator, which cannot overflow for any span shorter than 2^34 bytes (each add is < 2^33),
/// so no carry has to be tracked per word. One's-complement addition is byte-order independent
/// (RFC 1071 section 2(B)): the little-endian sum is the byte swap of the big-endian one.
/// Short runs (a 20-byte IPv4 header, an 8-byte UDP header): byte loads summed as big-endian words,
/// small enough to inline. These bytes were usually just written, often a byte or two at a time
/// (the checksum field zeroed, a counter patched), and a wide load over such fresh narrow stores
/// cannot be store-forwarded -- it stalls for longer than this whole loop takes.
template <class B>
NANOM_CSUM_INLINE constexpr std::uint16_t sum_short(const B* p, std::size_t n) noexcept {
  std::uint32_t s = 0;
  std::size_t i = 0;
  for (; i + 1 < n; i += 2) s += std::uint32_t(std::uint8_t(p[i])) << 8 | std::uint8_t(p[i + 1]);
  if (i < n) s += std::uint32_t(std::uint8_t(p[i])) << 8;
  s = (s & 0xffffu) + (s >> 16);
  s = (s & 0xffffu) + (s >> 16);
  return std::uint16_t(s);
}
inline constexpr std::size_t kShortRun = 64;

template <class B>
constexpr std::uint16_t sum_even(const B* p, std::size_t n) noexcept {
  std::uint64_t acc = 0;
  // fold every 2^30 words so the accumulator never overflows, however long the span
  while (n >= 8) {
    std::size_t blocks = n / 8;
    if (blocks > (std::size_t(1) << 30)) blocks = std::size_t(1) << 30;
    std::uint64_t a0 = 0, a1 = 0;
    std::size_t i = 0;
    for (; i + 2 <= blocks; i += 2) {
      const std::uint64_t w0 = nanom::detail::load_le64(p + 8 * i);
      const std::uint64_t w1 = nanom::detail::load_le64(p + 8 * i + 8);
      a0 += (w0 & 0xffffffffu) + (w0 >> 32);
      a1 += (w1 & 0xffffffffu) + (w1 >> 32);
    }
    if (i < blocks) {
      const std::uint64_t w = nanom::detail::load_le64(p + 8 * i);
      a0 += (w & 0xffffffffu) + (w >> 32);
    }
    acc += fold64(a0);
    acc += fold64(a1);
    p += 8 * blocks;
    n -= 8 * blocks;
  }
  std::uint64_t tail = 0;  // < 8 bytes left, at an even offset: little-endian, zero-padded
  for (std::size_t i = 0; i < n; ++i) tail |= std::uint64_t(std::uint8_t(p[i])) << (8 * i);
  acc += (tail & 0xffffffffu) + (tail >> 32);
  return swap16(fold64(acc));  // little-endian word sum -> the big-endian (network) sum
}
}  // namespace detail

/// Streaming one's-complement accumulator. Add any number of byte runs of any lengths in order;
/// a run that starts at an odd position (because the bytes before it had odd total length) is
/// handled by RFC 1071's swap rule, so the parts never have to be joined.
class sum {
 public:
  constexpr sum() = default;

  /// Add a run of bytes.
  template <nanom::detail::checksum_byte B>
  NANOM_CSUM_INLINE constexpr sum& add(std::span<B> bytes) noexcept {
    if (bytes.empty()) return *this;
    std::uint16_t s = bytes.size() < detail::kShortRun ? detail::sum_short(bytes.data(), bytes.size())
                                                       : detail::sum_even(bytes.data(), bytes.size());
    if (odd_) s = detail::swap16(s);  // this run starts in the low half of a word
    acc_ += s;
    odd_ ^= (bytes.size() & 1) != 0;
    return *this;
  }
  NANOM_CSUM_INLINE constexpr sum& add(std::span<const std::byte> bytes) noexcept { return add<const std::byte>(bytes); }
  constexpr sum& add(std::string_view s) noexcept { return add(std::span<const char>(s.data(), s.size())); }
  /// Add one big-endian 16-bit word at the current (even) position.
  constexpr sum& add16(std::uint16_t w) noexcept {
    acc_ += odd_ ? detail::swap16(w) : w;
    return *this;
  }
  /// Add a 32-bit value as two big-endian words.
  constexpr sum& add32(std::uint32_t w) noexcept { return add16(std::uint16_t(w >> 16)).add16(std::uint16_t(w)); }
  /// Add a previously folded partial sum (e.g. a precomputed pseudo-header sum, word-aligned).
  constexpr sum& add_folded(std::uint16_t partial) noexcept {
    acc_ += partial;
    return *this;
  }

  /// The 16-bit one's-complement sum so far (not inverted).
  [[nodiscard]] constexpr std::uint16_t folded() const noexcept { return detail::fold64(acc_); }
  /// The checksum to store: the one's complement of the sum.
  [[nodiscard]] constexpr std::uint16_t checksum() const noexcept { return std::uint16_t(~folded()); }
  /// True when the bytes added INCLUDE a correct checksum field (the sum is all ones).
  [[nodiscard]] constexpr bool verifies() const noexcept { return folded() == 0xffff; }

 private:
  std::uint64_t acc_ = 0;  // at most ~2^48 16-bit adds before it could overflow
  bool          odd_ = false;
};

/// RFC 1071 checksum of one byte run (the value to store in the header, host order).
template <nanom::detail::checksum_byte B>
constexpr std::uint16_t checksum(std::span<B> bytes) noexcept {
  return sum{}.add(bytes).checksum();
}
NANOM_CSUM_INLINE constexpr std::uint16_t checksum(std::span<const std::byte> bytes) noexcept {
  return sum{}.add(bytes).checksum();
}
constexpr std::uint16_t checksum(std::string_view bytes) noexcept { return sum{}.add(bytes).checksum(); }
/// Checksum over several runs taken as one logical buffer (scatter/gather; any lengths).
constexpr std::uint16_t checksum(std::initializer_list<std::span<const std::byte>> parts) noexcept {
  sum s;
  for (auto p : parts) s.add(p);
  return s.checksum();
}
constexpr std::uint16_t checksum(std::span<const std::span<const std::byte>> parts) noexcept {
  sum s;
  for (auto p : parts) s.add(p);
  return s.checksum();
}
/// True if `bytes` (which include the stored checksum) verify.
constexpr bool verify(std::span<const std::byte> bytes) noexcept { return sum{}.add(bytes).verifies(); }
constexpr bool verify(std::initializer_list<std::span<const std::byte>> parts) noexcept {
  sum s;
  for (auto p : parts) s.add(p);
  return s.verifies();
}

/// The 12-byte IPv4 pseudo-header UDP and TCP checksums cover (RFC 768 / RFC 9293):
/// src, dst, zero, protocol, L4 length (header + payload).
constexpr std::array<std::byte, 12> pseudo_header_v4(const std::array<std::uint8_t, 4>& src,
                                                     const std::array<std::uint8_t, 4>& dst,
                                                     std::uint8_t protocol, std::uint16_t l4_length) noexcept {
  std::array<std::byte, 12> h{};
  for (std::size_t i = 0; i < 4; ++i) {
    h[i] = std::byte(src[i]);
    h[4 + i] = std::byte(dst[i]);
  }
  h[9] = std::byte(protocol);
  h[10] = std::byte(l4_length >> 8);
  h[11] = std::byte(l4_length);
  return h;
}
/// The 40-byte IPv6 pseudo-header (RFC 8200 section 8.1): src, dst, 32-bit upper-layer length,
/// three zero bytes, next header.
constexpr std::array<std::byte, 40> pseudo_header_v6(const std::array<std::uint8_t, 16>& src,
                                                     const std::array<std::uint8_t, 16>& dst,
                                                     std::uint32_t upper_length, std::uint8_t next_header) noexcept {
  std::array<std::byte, 40> h{};
  for (std::size_t i = 0; i < 16; ++i) {
    h[i] = std::byte(src[i]);
    h[16 + i] = std::byte(dst[i]);
  }
  h[32] = std::byte(upper_length >> 24);
  h[33] = std::byte(upper_length >> 16);
  h[34] = std::byte(upper_length >> 8);
  h[35] = std::byte(upper_length);
  h[39] = std::byte(next_header);
  return h;
}

/// UDP checksum value to store, given the pseudo-header and the UDP header (checksum field zero)
/// and payload parts: a computed 0 is sent as 0xFFFF (RFC 768; 0 means "no checksum" over IPv4).
constexpr std::uint16_t udp_checksum(std::initializer_list<std::span<const std::byte>> parts) noexcept {
  const std::uint16_t c = checksum(parts);
  return c == 0 ? std::uint16_t(0xffff) : c;
}

/// RFC 1624 eqn. 3 incremental update: the new checksum after one 16-bit word covered by `csum`
/// changes from `old_word` to `new_word`: HC' = ~(~HC + ~m + m'). Avoids the -0 pitfall of RFC 1141.
constexpr std::uint16_t update16(std::uint16_t csum, std::uint16_t old_word, std::uint16_t new_word) noexcept {
  std::uint32_t s = std::uint32_t(std::uint16_t(~csum)) + std::uint16_t(~old_word) + new_word;
  s = (s & 0xffffu) + (s >> 16);
  s = (s & 0xffffu) + (s >> 16);
  return std::uint16_t(~s);
}
/// The same for a 32-bit field (an IPv4 address, a TCP sequence number) at an even offset.
constexpr std::uint16_t update32(std::uint16_t csum, std::uint32_t old_value, std::uint32_t new_value) noexcept {
  return update16(update16(csum, std::uint16_t(old_value >> 16), std::uint16_t(new_value >> 16)),
                  std::uint16_t(old_value), std::uint16_t(new_value));
}

}  // namespace inet

// ===========================================================================
// CRCs (Rocksoft model), table driven: slicing-by-8 tables generated at compile time
// ===========================================================================

/// A CRC in the Rocksoft parameter model. `T` is the register (uint8/16/32/64_t, W = its width),
/// `Poly` the normal (MSB-first) polynomial, `Reflected` = refin = refout.
template <class T, T Poly, T Init, bool Reflected, T XorOut, T Check>
  requires(std::unsigned_integral<T> && sizeof(T) <= 8)
struct crc_params {
  using type = T;
  static constexpr unsigned width = 8 * sizeof(T);
  static constexpr T poly = Poly, init = Init, xorout = XorOut;
  static constexpr bool reflected = Reflected;
  static constexpr T check = Check;  ///< the CRC of the ASCII string "123456789"
};

namespace detail {
template <class T>
constexpr T reflect_bits(T v) noexcept {
  T r = 0;
  for (unsigned i = 0; i < 8 * sizeof(T); ++i) {
    r = T((r << 1) | (v & 1));
    v = T(v >> 1);
  }
  return r;
}

/// tables[k][b] = the register contribution of byte b followed by k zero bytes.
template <class P>
constexpr auto make_crc_tables() noexcept {
  using T = typename P::type;
  constexpr unsigned W = P::width;
  std::array<std::array<T, 256>, 8> t{};
  for (unsigned b = 0; b < 256; ++b) {
    T r;
    if constexpr (P::reflected) {
      const T rp = reflect_bits<T>(P::poly);
      r = T(b);
      for (int i = 0; i < 8; ++i) r = (r & 1) ? T((r >> 1) ^ rp) : T(r >> 1);
    } else {
      r = T(T(b) << (W - 8));
      for (int i = 0; i < 8; ++i) r = (r >> (W - 1)) & 1 ? T(T(r << 1) ^ P::poly) : T(r << 1);
    }
    t[0][b] = r;
  }
  for (unsigned k = 1; k < 8; ++k)
    for (unsigned b = 0; b < 256; ++b) {
      const T prev = t[k - 1][b];
      if constexpr (P::reflected) {
        if constexpr (W == 8) t[k][b] = t[0][prev & 0xff];
        else t[k][b] = T((prev >> 8) ^ t[0][prev & 0xff]);
      } else {
        if constexpr (W == 8) t[k][b] = t[0][prev];
        else t[k][b] = T(T(prev << 8) ^ t[0][(prev >> (W - 8)) & 0xff]);
      }
    }
  return t;
}
template <class P>
inline constexpr auto crc_tables = make_crc_tables<P>();
}  // namespace detail

/// A streaming CRC: construct (= start), update() any number of times, value() to finalize. The
/// state is just the register, so a crc is cheap to copy (e.g. to fork a common prefix).
template <class P>
class crc {
 public:
  using params     = P;
  using value_type = typename P::type;
  static constexpr unsigned width = P::width;

  constexpr crc() noexcept = default;

  /// Continue a CRC whose finalized value over the earlier bytes was `previous`: AUTOSAR's
  /// Crc_CalculateCRCxx(..., StartValue = previous, IsFirstCall = FALSE).
  [[nodiscard]] static constexpr crc resume(value_type previous) noexcept {
    crc c;
    c.reg_ = value_type(previous ^ P::xorout);  // refin == refout, so no reflection is needed
    return c;
  }

  template <nanom::detail::checksum_byte B>
  constexpr crc& update(std::span<B> bytes) noexcept {
    reg_ = run(reg_, bytes.data(), bytes.size());
    return *this;
  }
  constexpr crc& update(std::span<const std::byte> bytes) noexcept { return update<const std::byte>(bytes); }
  constexpr crc& update(std::string_view s) noexcept { return update(std::span<const char>(s.data(), s.size())); }
  constexpr crc& update(std::uint8_t byte) noexcept {
    reg_ = run(reg_, &byte, 1);
    return *this;
  }

  /// The CRC of everything added so far (does not change the state; keep updating if you like).
  [[nodiscard]] constexpr value_type value() const noexcept { return value_type(reg_ ^ P::xorout); }

  /// One shot.
  template <nanom::detail::checksum_byte B>
  [[nodiscard]] static constexpr value_type compute(std::span<B> bytes) noexcept {
    return crc{}.update(bytes).value();
  }
  [[nodiscard]] static constexpr value_type compute(std::span<const std::byte> bytes) noexcept {
    return crc{}.update(bytes).value();
  }
  [[nodiscard]] static constexpr value_type compute(std::string_view s) noexcept { return crc{}.update(s).value(); }

 private:
  static constexpr value_type initial() noexcept {
    return P::reflected ? detail::reflect_bits<value_type>(P::init) : P::init;
  }

  template <class B>
  static constexpr value_type run(value_type r, const B* p, std::size_t n) noexcept {
    constexpr unsigned W = P::width;
    const auto& t = detail::crc_tables<P>;
    if constexpr (P::reflected) {
      for (; n >= 8; p += 8, n -= 8) {
        const std::uint64_t x = nanom::detail::load_le64(p) ^ std::uint64_t(r);
        r = value_type(t[7][x & 0xff] ^ t[6][(x >> 8) & 0xff] ^ t[5][(x >> 16) & 0xff] ^
                       t[4][(x >> 24) & 0xff] ^ t[3][(x >> 32) & 0xff] ^ t[2][(x >> 40) & 0xff] ^
                       t[1][(x >> 48) & 0xff] ^ t[0][x >> 56]);
      }
      for (; n; ++p, --n) {
        const unsigned idx = (unsigned(r) ^ std::uint8_t(*p)) & 0xff;
        if constexpr (W == 8) r = t[0][idx];
        else r = value_type((r >> 8) ^ t[0][idx]);
      }
    } else {
      for (; n >= 8; p += 8, n -= 8) {
        const std::uint64_t x = nanom::detail::load_be64(p) ^ (std::uint64_t(r) << (64 - W));
        r = value_type(t[7][x >> 56] ^ t[6][(x >> 48) & 0xff] ^ t[5][(x >> 40) & 0xff] ^
                       t[4][(x >> 32) & 0xff] ^ t[3][(x >> 24) & 0xff] ^ t[2][(x >> 16) & 0xff] ^
                       t[1][(x >> 8) & 0xff] ^ t[0][x & 0xff]);
      }
      for (; n; ++p, --n) {
        const unsigned idx = (unsigned(r >> (W - 8)) ^ std::uint8_t(*p)) & 0xff;
        if constexpr (W == 8) r = t[0][idx];
        else r = value_type(value_type(r << 8) ^ t[0][idx]);
      }
    }
    return r;
  }

  value_type reg_ = initial();
};

// The AUTOSAR CRC library (SWS_Crc) set. Check values are the CRCs of "123456789" the spec lists.
// E2E profiles: P1/P11 CRC8 SAE-J1850, P2/P22 CRC8H2F, P4/P44 CRC32P4, P5/P6 CRC16 CCITT-FALSE,
// P7 CRC64. CRC16 ARC (Crc_CalculateCRC16ARC) and the IEEE CRC32 are in SWS_Crc as well.
/// CRC-8/SAE-J1850: poly 0x1D, init 0xFF, xorout 0xFF, not reflected. Check 0x4B.
using crc8_sae_j1850 = crc<crc_params<std::uint8_t, 0x1D, 0xFF, false, 0xFF, 0x4B>>;
/// CRC-8/AUTOSAR ("CRC8H2F"): poly 0x2F, init 0xFF, xorout 0xFF, not reflected. Check 0xDF.
using crc8_h2f = crc<crc_params<std::uint8_t, 0x2F, 0xFF, false, 0xFF, 0xDF>>;
/// CRC-16/CCITT-FALSE (CRC-16/IBM-3740): poly 0x1021, init 0xFFFF, xorout 0, not reflected. Check 0x29B1.
using crc16_ccitt_false = crc<crc_params<std::uint16_t, 0x1021, 0xFFFF, false, 0x0000, 0x29B1>>;
/// CRC-16/ARC: poly 0x8005, init 0, xorout 0, reflected. Check 0xBB3D.
using crc16_arc = crc<crc_params<std::uint16_t, 0x8005, 0x0000, true, 0x0000, 0xBB3D>>;
/// CRC-32 (IEEE 802.3, ISO-HDLC): poly 0x04C11DB7, init/xorout 0xFFFFFFFF, reflected. Check 0xCBF43926.
using crc32 = crc<crc_params<std::uint32_t, 0x04C11DB7, 0xFFFFFFFF, true, 0xFFFFFFFF, 0xCBF43926>>;
/// CRC-32/AUTOSAR ("CRC32P4"): poly 0xF4ACFB13, init/xorout 0xFFFFFFFF, reflected. Check 0x1697D06A.
using crc32_p4 = crc<crc_params<std::uint32_t, 0xF4ACFB13, 0xFFFFFFFF, true, 0xFFFFFFFF, 0x1697D06A>>;
/// AUTOSAR CRC64 = CRC-64/XZ: the ECMA-182 polynomial 0x42F0E1EBA9EA3693, init/xorout all ones,
/// reflected. Check 0x995DC9BBDF1939FA.
using crc64 = crc<crc_params<std::uint64_t, 0x42F0E1EBA9EA3693ull, ~0ull, true, ~0ull, 0x995DC9BBDF1939FAull>>;

}  // namespace nanom

#undef NANOM_CSUM_INLINE

#endif  // NANOM_CHECKSUM_HPP_INCLUDED
