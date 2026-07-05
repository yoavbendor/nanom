// SPDX-License-Identifier: Apache-2.0
// nanom/reflect.hpp — struct reflection & typed parsing (beyond nom, still "parse into your struct").
// fixed_string, the wire field types (be<>/le<>/ubits<>/ibits<>), the describe<T> seam
// (describe/Described/detail::fld/for_each_field), compile-time wire traits & layout, and the two
// struct parsers strct<T>() (by value) and overlay<T>()/view<T> (zero-copy, decode on access).
// The describe<T> seam has two interchangeable providers, included at the END of this header
// (outside namespace nanom): nanom26.hpp (C++26 P2996 reflection, macro-free) and describe_macro.hpp
// (the NANOM_DESCRIBE registration macro).
#ifndef NANOM_REFLECT_HPP_INCLUDED
#define NANOM_REFLECT_HPP_INCLUDED

#include "nom.hpp"

namespace nanom {

// ---------------------------------------------------------------------------
// 15. fixed_string — string literals as template parameters (get<"name">())
// ---------------------------------------------------------------------------

template <std::size_t N>
struct fixed_string {
  char data[N]{};
  constexpr fixed_string() = default;  // synthesized names (nanom26 reflection) fill data directly
  constexpr fixed_string(const char (&s)[N]) { std::copy_n(s, N, data); }
  constexpr std::string_view sv() const { return {data, N - 1}; }
  constexpr bool operator==(std::string_view s) const { return sv() == s; }
};

// ---------------------------------------------------------------------------
// 16. wire field types — endianness and bit width live in the TYPE
// ---------------------------------------------------------------------------

/// be<T> / le<T> — an explicitly big/little-endian wire scalar. Stored as raw
/// bytes (alignment 1, packing-safe); converts to/from host order on access.
/// Mixing be<> and le<> fields in one struct is fine.
template <class T, std::endian E>
  requires(std::integral<T> || std::floating_point<T>)
struct endian_scalar {
  using value_type = T;
  static constexpr std::endian order = E;
  std::array<std::byte, sizeof(T)> raw{};

  constexpr endian_scalar() = default;
  constexpr endian_scalar(T v) { set(v); }

  NANOM_HD constexpr T get() const {
    using U = detail::uint_for_bytes<sizeof(T)>;
    U u = 0;
    if constexpr (E == std::endian::big)
      for (std::size_t i = 0; i < sizeof(T); ++i) u = U(u << 8) | std::uint8_t(raw[i]);
    else
      for (std::size_t i = 0; i < sizeof(T); ++i) u |= U(U(std::uint8_t(raw[i])) << (8 * i));
    if constexpr (std::floating_point<T>) return std::bit_cast<T>(u);
    else                                  return std::bit_cast<T>(U(u));
  }
  NANOM_HD constexpr void set(T v) {
    using U = detail::uint_for_bytes<sizeof(T)>;
    U u = std::bit_cast<U>(v);
    if constexpr (E == std::endian::big)
      for (std::size_t i = 0; i < sizeof(T); ++i)
        raw[i] = std::byte((u >> (8 * (sizeof(T) - 1 - i))) & 0xff);
    else
      for (std::size_t i = 0; i < sizeof(T); ++i) raw[i] = std::byte((u >> (8 * i)) & 0xff);
  }
  NANOM_HD constexpr operator T() const { return get(); }
};
template <class T> using be = endian_scalar<T, std::endian::big>;
template <class T> using le = endian_scalar<T, std::endian::little>;

namespace detail {
template <unsigned Bits>
using uint_for_bits = uint_for_bytes<(Bits + 7) / 8>;
}

/// ubits<N> / ibits<N> — an N-bit unsigned/signed field. Consecutive bit
/// fields in a described struct are packed together; each run must end on a
/// byte boundary (checked at compile time). Default bit order is msb0
/// (network); pass bit_order::lsb0 for LSB-first register layouts. Orders may
/// be mixed field-by-field.
template <unsigned N, bit_order O = bit_order::msb0>
  requires(N >= 1 && N <= 64)
struct ubits {
  using value_type = detail::uint_for_bits<N>;
  static constexpr unsigned  bits  = N;
  static constexpr bit_order order = O;
  value_type v{};
  constexpr operator value_type() const { return v; }
};
template <unsigned N, bit_order O = bit_order::msb0>
  requires(N >= 2 && N <= 64)
struct ibits {
  using value_type = std::make_signed_t<detail::uint_for_bits<N>>;
  static constexpr unsigned  bits  = N;
  static constexpr bit_order order = O;
  value_type v{};
  constexpr operator value_type() const { return v; }
};

// ---------------------------------------------------------------------------
// 17. struct registration — NANOM_DESCRIBE (C++26: this macro layer is the
//     only thing P2996 reflection will replace)
// ---------------------------------------------------------------------------

/// Specialized by NANOM_DESCRIBE. The single customization point for all
/// reflection: strct(), overlay(), schema_of(), soa, to_json, csv…
template <class T>
struct describe;  // intentionally undefined for unregistered types

template <class T>
concept Described = requires {
  describe<std::remove_cv_t<T>>::fields();
  describe<std::remove_cv_t<T>>::name();
};

namespace detail {
/// One registered field: name + member pointer, all compile-time.
template <fixed_string Name, auto MemPtr>
struct fld {
  static constexpr auto name    = Name;
  static constexpr auto mem_ptr = MemPtr;
};
template <class M> struct member_type;
template <class C, class M> struct member_type<M C::*> { using type = M; };
template <auto P> using member_t = typename member_type<std::remove_cv_t<decltype(P)>>::type;

/// Visit every registered field of T in declaration order: v(f) receives a fld<> value — read
/// decltype(f)::name / ::mem_ptr / member_t<decltype(f)::mem_ptr>. THE one field-iteration
/// primitive: every walk over describe<T>::fields() in the library goes through here, so the
/// tuple-unpacking boilerplate lives in exactly one place.
template <class T, class V>
NANOM_HD constexpr void for_each_field(V&& v) {
  std::apply([&](auto... f) { (v(f), ...); }, describe<std::remove_cv_t<T>>::fields());
}
}  // namespace detail

// (The two describe<T> providers — nanom26.hpp reflection / describe_macro.hpp registration
// macro — are included at the END of this header, outside namespace nanom; see there.)

// ---------------------------------------------------------------------------
// 18. wire traits & compile-time layout
// ---------------------------------------------------------------------------

namespace detail {

template <class F> struct wire;  // wire representation of one field type

template <class T>
  requires(std::integral<T> || std::floating_point<T>)
struct wire<T> {                                 // native scalar: endianness
  static constexpr std::size_t bits = 8 * sizeof(T);   // chosen at parse time
  static constexpr bool is_bits = false;
  using decoded = T;
};
template <class T, std::endian E>
struct wire<endian_scalar<T, E>> {
  static constexpr std::size_t bits = 8 * sizeof(T);
  static constexpr bool is_bits = false;
  using decoded = T;
};
template <unsigned N, bit_order O>
struct wire<ubits<N, O>> {
  static constexpr std::size_t bits = N;
  static constexpr bool is_bits = true;
  using decoded = typename ubits<N, O>::value_type;
};
template <unsigned N, bit_order O>
struct wire<ibits<N, O>> {
  static constexpr std::size_t bits = N;
  static constexpr bool is_bits = true;
  using decoded = typename ibits<N, O>::value_type;
};
template <class U, std::size_t N>
struct wire<std::array<U, N>> {
  static constexpr std::size_t bits = N * wire<U>::bits;
  static constexpr bool is_bits = false;
  using decoded = std::array<typename wire<U>::decoded, N>;
  static_assert(!wire<U>::is_bits, "arrays of bit fields are not supported");
};
template <Described T>
struct wire<T> {
  static constexpr std::size_t bits = []() {
    std::size_t total = 0;
    for_each_field<T>([&](auto f) { total += wire<member_t<decltype(f)::mem_ptr>>::bits; });
    return total;
  }();
  static constexpr bool is_bits = false;
  using decoded = T;
};

template <class T>
constexpr std::size_t field_count_v = std::tuple_size_v<decltype(describe<T>::fields())>;

/// Bit offset of every field, computed once at compile time.
template <Described T>
NANOM_HD constexpr auto field_bit_offsets() {
  std::array<std::size_t, field_count_v<T>> off{};
  std::size_t cur = 0, i = 0;
  for_each_field<T>([&](auto f) {
    off[i++] = cur;
    cur += wire<member_t<decltype(f)::mem_ptr>>::bits;
  });
  return off;
}

/// Layout validity: every non-bit field byte-aligned, total a whole number of
/// bytes. Evaluated at compile time; strct/overlay static_assert on it.
template <Described T>
constexpr bool layout_ok() {
  constexpr auto off = field_bit_offsets<T>();
  bool ok = wire<T>::bits % 8 == 0;
  std::size_t i = 0;
  for_each_field<T>([&](auto f) {
    ok = ok && (wire<member_t<decltype(f)::mem_ptr>>::is_bits || off[i] % 8 == 0);
    ++i;
  });
  return ok;
}

}  // namespace detail

/// Serialized size of a described struct on the wire, in bytes.
template <Described T>
inline constexpr std::size_t wire_size_v = detail::wire<T>::bits / 8;

namespace detail {

template <class T> struct is_std_array : std::false_type {};
template <class U, std::size_t N> struct is_std_array<std::array<U, N>> : std::true_type {};
template <class T> constexpr bool is_std_array_v = is_std_array<T>::value;

/// A std::array of a plain 1-byte integral (MAC / IP address, name field): its
/// wire bytes ARE the value, so an overlay can hand back a zero-copy span.
template <class T> struct is_byte_array : std::false_type {};
template <class E, std::size_t N>
struct is_byte_array<std::array<E, N>>
    : std::bool_constant<std::is_integral_v<E> && sizeof(E) == 1> {};
template <class T> constexpr bool is_byte_array_v = is_byte_array<T>::value;

template <class F>
NANOM_HD constexpr F assign_field(const std::byte* p, std::size_t bitoff, std::endian dflt);

/// Decode one field value from wire bytes. `p` points at the struct start;
/// bitoff is the field's bit offset from p. Used by both strct() and view<T>.
template <class F>
NANOM_HD constexpr typename wire<F>::decoded decode_field(const std::byte* p, std::size_t bitoff,
                                                 std::endian dflt) {
  using D = typename wire<F>::decoded;
  if constexpr (std::integral<F> || std::floating_point<F>) {
    using U = uint_for_bytes<sizeof(F)>;
    const std::byte* q = p + bitoff / 8;
    U u = 0;
    if (dflt == std::endian::big)
      for (std::size_t i = 0; i < sizeof(F); ++i) u = U(u << 8) | std::uint8_t(q[i]);
    else
      for (std::size_t i = 0; i < sizeof(F); ++i) u |= U(U(std::uint8_t(q[i])) << (8 * i));
    return std::bit_cast<F>(U(u));
  } else if constexpr (requires { F::order; F::bits; }) {  // ubits / ibits
    using VT = typename F::value_type;
    constexpr unsigned N = F::bits;
    std::uint64_t raw;
    if constexpr (F::order == bit_order::msb0 && (7u + N) <= 64u) {
      // fast path: load the covering bytes as one big-endian word and
      // shift+mask — O(bytes) instead of read_bits' O(bits) loop. This is the
      // hot path for network headers (msb0) and is what makes overlay<>()
      // competitive with a hand-tuned overlay parser.
      const std::byte* q = p + bitoff / 8;
      const unsigned startbit = unsigned(bitoff % 8);
      const unsigned nbytes = (startbit + N + 7) / 8;
      std::uint64_t w = 0;
      for (unsigned i = 0; i < nbytes; ++i) w = (w << 8) | std::uint8_t(q[i]);
      const unsigned shift = nbytes * 8 - startbit - N;
      raw = (w >> shift) & (N >= 64 ? ~std::uint64_t(0) : ((std::uint64_t(1) << N) - 1));
    } else {
      input fake{p + bitoff / 8, p + (bitoff + N + 7) / 8, p};
      raw = read_bits(bit_input{fake, bitoff % 8}, N, F::order)->value;
    }
    if constexpr (std::is_signed_v<VT>) {
      using UV = std::make_unsigned_t<VT>;
      UV u = UV(raw);
      const UV sign = UV(1) << (N - 1);
      if (u & sign) u |= ~((sign << 1) - 1);          // sign-extend
      return std::bit_cast<VT>(u);
    } else {
      return VT(raw);
    }
  } else if constexpr (requires { F::order; typename F::value_type; }) {  // be/le
    // assemble the host value directly from the wire bytes in a single pass —
    // for widths 2/4/8 the compiler lowers this to one load + bswap, matching
    // a hand-tuned overlay parser (the old path copied to a temp, then that
    // temp re-assembled: two loops on the hottest reads — ethertype, ports…).
    using T = typename F::value_type;
    using U = uint_for_bytes<sizeof(T)>;
    const std::byte* q = p + bitoff / 8;
    U u = 0;
    if constexpr (F::order == std::endian::big)
      for (std::size_t i = 0; i < sizeof(T); ++i) u = U(U(u << 8) | std::uint8_t(q[i]));
    else
      for (std::size_t i = 0; i < sizeof(T); ++i) u |= U(U(std::uint8_t(q[i])) << (8 * i));
    return std::bit_cast<T>(u);
  } else if constexpr (is_std_array_v<F>) {
    using E = typename F::value_type;
    D out{};
    constexpr std::size_t eb = wire<E>::bits;
    for (std::size_t i = 0; i < out.size(); ++i)
      out[i] = decode_field<E>(p, bitoff + i * eb, dflt);
    return out;
  } else {  // nested described struct
    D out{};
    constexpr auto offs = field_bit_offsets<F>();
    std::size_t i = 0;
    for_each_field<F>([&](auto f) {
      out.*(decltype(f)::mem_ptr) =
          assign_field<member_t<decltype(f)::mem_ptr>>(p, bitoff + offs[i++], dflt);
    });
    return out;
  }
}

/// Like decode_field, but produces the FIELD type (so be<u16> members keep
/// their raw wire bytes instead of being converted to host order).
template <class F>
NANOM_HD constexpr F assign_field(const std::byte* p, std::size_t bitoff, std::endian dflt) {
  if constexpr (requires(F f) { f.raw; typename F::value_type; }) {  // be/le: copy raw
    F out;
    for (std::size_t i = 0; i < out.raw.size(); ++i) out.raw[i] = p[bitoff / 8 + i];
    return out;
  } else if constexpr (requires { F::order; F::bits; }) {  // ubits/ibits
    return F{decode_field<F>(p, bitoff, dflt)};
  } else if constexpr (is_std_array_v<F>) {
    using E = typename F::value_type;
    F out{};
    constexpr std::size_t eb = wire<E>::bits;
    for (std::size_t i = 0; i < out.size(); ++i)
      out[i] = assign_field<E>(p, bitoff + i * eb, dflt);
    return out;
  } else if constexpr (std::integral<F> || std::floating_point<F>) {
    return decode_field<F>(p, bitoff, dflt);
  } else {  // nested described struct
    F out{};
    constexpr auto offs = field_bit_offsets<F>();
    std::size_t i = 0;
    for_each_field<F>([&](auto f) {
      out.*(decltype(f)::mem_ptr) =
          assign_field<member_t<decltype(f)::mem_ptr>>(p, bitoff + offs[i++], dflt);
    });
    return out;
  }
}

template <Described T, fixed_string Name>
NANOM_HD constexpr std::size_t field_index() {
  std::size_t idx = std::size_t(-1), i = 0;
  for_each_field<T>([&](auto f) {
    if (decltype(f)::name == Name.sv()) idx = i;
    ++i;
  });
  return idx;
}
template <Described T, std::size_t I>
using field_type_at = member_t<std::remove_cvref_t<decltype(std::get<I>(describe<T>::fields()))>::mem_ptr>;

}  // namespace detail

// ---------------------------------------------------------------------------
// 19. strct<T>() — parse a registered struct by value; the workhorse
// ---------------------------------------------------------------------------

/// strct<T>() — a parser producing T. Walks the registered fields in order:
/// be<>/le<> fields keep wire bytes, plain scalars use `dflt` endianness
/// (default: host), bit fields consume bits, arrays and nested described
/// structs recurse. Fixed wire size (wire_size_v<T>), so it composes freely:
/// many0(strct<eth_hdr>()), length_value(be_u16, strct<tlv>()), …
template <Described T>
constexpr auto strct(std::endian dflt = std::endian::native) {
  static_assert(detail::layout_ok<T>(),
                "nanom: bit fields must pack to byte boundaries and every "
                "non-bit field must start byte-aligned");
  return [dflt](input in) -> result<T> {
    constexpr std::size_t need = wire_size_v<T>;
    if (in.size() < need) return make_incomplete(in, need - in.size());
    T out{};
    constexpr auto offs = detail::field_bit_offsets<T>();
    std::size_t i = 0;
    detail::for_each_field<T>([&](auto f) {
      out.*(decltype(f)::mem_ptr) =
          detail::assign_field<detail::member_t<decltype(f)::mem_ptr>>(in.first, offs[i++], dflt);
    });
    return done{std::move(out), in.advance(need)};
  };
}

// ---------------------------------------------------------------------------
// 20. view<T> / overlay<T>() — zero-copy lazy access: get<"field">()
// ---------------------------------------------------------------------------

namespace detail {
NANOM_HD inline constexpr void guard_view_pointer(const std::byte* p) {
  if consteval {
    (void)p;
    return;
  }
#if NANOM_GUARD_VIEWS
  assert(p != nullptr && "nanom: view access on null/uninitialized overlay");
#else
  (void)p;
#endif
}
}  // namespace detail

/// Zero-copy lifetime contracts (enforced by documentation + debug guards; see
/// docs/MEMORY_SAFETY.md). constexpr flags let tests assert the API surface.
inline constexpr bool overlay_wire_must_be_immutable = true;
inline constexpr bool span_lifetime_is_caller_scoped   = true;

/// A zero-copy overlay of T's wire format over the original buffer. Fields
/// decode on access (endian conversion / bit extraction), nothing is stored.
template <Described T>
struct view {
  const std::byte* p    = nullptr;
  std::endian      dflt = std::endian::native;  ///< order for plain scalars

  NANOM_HD constexpr bool valid() const noexcept { return p != nullptr; }

  /// Decoded value of the named field. Unknown names are a compile error.
  template <fixed_string Name>
  NANOM_HD constexpr auto get() const {
    detail::guard_view_pointer(p);
    constexpr std::size_t I = detail::field_index<T, Name>();
    static_assert(I != std::size_t(-1),
                  "nanom: no such field in this struct — check NANOM_DESCRIBE");
    using F = detail::field_type_at<T, I>;
    constexpr std::size_t off = detail::field_bit_offsets<T>()[I];
    if constexpr (Described<F>) {
      return view<F>{p + off / 8, dflt};
    } else if constexpr (detail::is_byte_array_v<F>) {
      // byte array (MAC / IPv4 / IPv6 address, name field…): the wire bytes ARE
      // the value, so return a zero-copy span into the buffer instead of
      // materializing a std::array. get<"src">()[0] is then a single byte load.
      return std::span<const typename F::value_type, std::tuple_size_v<F>>(
          reinterpret_cast<const typename F::value_type*>(p + off / 8), std::tuple_size_v<F>);
    } else {
      return detail::decode_field<F>(p, off, dflt);
    }
  }
  /// The struct's raw wire bytes.
  NANOM_HD constexpr bytes raw() const {
    detail::guard_view_pointer(p);
    return {p, wire_size_v<T>};
  }
  /// Materialize a full T (same as strct would produce).
  NANOM_HD constexpr T to_struct() const {
    detail::guard_view_pointer(p);
    T out{};
    constexpr auto offs = detail::field_bit_offsets<T>();
    std::size_t i = 0;
    detail::for_each_field<T>([&](auto f) {
      out.*(decltype(f)::mem_ptr) =
          detail::assign_field<detail::member_t<decltype(f)::mem_ptr>>(p, offs[i++], dflt);
    });
    return out;
  }
};

/// overlay<T>() — parser yielding a view<T> (bounds-checked, zero-copy).
template <Described T>
constexpr auto overlay(std::endian dflt = std::endian::native) {
  static_assert(detail::layout_ok<T>(),
                "nanom: bit fields must pack to byte boundaries and every "
                "non-bit field must start byte-aligned");
  return [dflt](input in) -> result<view<T>> {
    constexpr std::size_t need = wire_size_v<T>;
    if (in.size() < need) return make_incomplete(in, need - in.size());
    return done{view<T>{in.first, dflt}, in.advance(need)};
  };
}
}  // namespace nanom

// --- the two describe<T> providers ------------------------------------------------------------
// The seam above (describe<T> -> tuple of detail::fld<Name, MemPtr>) is synthesized either by C++26
// reflection or by the preprocessor macro. Both are included here, at global scope, once the seam is
// fully defined:
//   * nanom26.hpp — P2996 reflection auto-describes every eligible struct, macro-free (primary);
//   * describe_macro.hpp — NANOM_DESCRIBE (C++23); under reflection it degrades to a coverage
//     static_assert. Define NANOM_DESCRIBE_FORCE_MACRO to force explicit registration.
#if NANOM_HAS_REFLECTION
#include "nanom26.hpp"
#endif
#include "describe_macro.hpp"

#endif  // NANOM_REFLECT_HPP_INCLUDED
