// SPDX-License-Identifier: Apache-2.0
// nanom/emit.hpp — WRITE fixed-layout described structs: the inverse of strct<T>() / overlay<T>().
//
// The same description that parses a header writes it, field by field and bit by bit:
//
//   struct udp_hdr { nm::be<u16> src_port, dst_port, length, checksum; };
//   NANOM_DESCRIBE(udp_hdr, src_port, dst_port, length, checksum);
//
//   auto bytes = nm::to_bytes(hdr);                    // std::array<std::byte, 8>, constexpr
//   auto n = nm::emit(hdr, out_span);                  // into a buffer (never written past)
//   auto m = nm::emit_frame(hdr, payload, sink);       // header + payload into any byte_sink
//
// Fields are written exactly as strct<T>() reads them: be<> / le<> keep their wire bytes, plain
// scalars use the `dflt` byte order, ubits / ibits are packed msb0 or lsb0 at their compile-time
// bit offsets, arrays and nested described structs recurse. So strct(emit(x)) == x, and for any
// byte string b of the right size, emit(strct(b)) == b.
//
// Computed fields (binrw's `calc`): specialize nm::computed<T> to derive fields while writing —
// lengths from the payload, checksums over the encoded bytes:
//
//   template <> struct nm::computed<udp_hdr> {
//     static constexpr auto fields = std::tuple{
//       nm::calc<"length">([](const udp_hdr&, const nm::emit_ctx& c) { return 8 + c.payload.size(); }),
//       nm::checksum<"checksum">([](std::span<const std::byte> hdr, const nm::emit_ctx& c) { ... }),
//     };
//   };
//
//   calc<"f">(fn(const T&, const emit_ctx&))        runs before encoding (in order);
//   checksum<"f">(fn(bytes, const emit_ctx&))       runs after, over the encoded struct with field
//                                                   f zeroed, then f is written in place.
// A computed value is range-checked into its field (a length that does not fit a be<u16> is an
// error, never a truncation). verify_computed(bytes, ctx) checks stored values on the read side.
//
// Errors (encode_error, see nanom/sink.hpp): a ubits / ibits value outside its N bits, a computed
// value that does not fit its field, an output buffer smaller than wire_size_v<T>, a sink that
// refuses bytes. Reading code never includes this header.
#ifndef NANOM_EMIT_HPP_INCLUDED
#define NANOM_EMIT_HPP_INCLUDED

#include "reflect.hpp"
#include "sink.hpp"

#include <tuple>

namespace nanom {

// ---------------------------------------------------------------------------
// 43. computed fields
// ---------------------------------------------------------------------------

/// What computed fields may look at: the bytes written after the struct (a frame's payload).
struct emit_ctx {
  std::span<const std::byte> payload{};
};

template <fixed_string Name, class Fn>
struct calc_t {
  static constexpr auto name = Name;
  Fn fn;
};
template <fixed_string Name, class Fn>
struct checksum_t {
  static constexpr auto name = Name;
  Fn fn;
};
/// A field computed from the value and the context before encoding: fn(const T&, const emit_ctx&).
template <fixed_string Name, class Fn>
constexpr calc_t<Name, Fn> calc(Fn fn) { return {fn}; }
/// A field computed from the encoded struct (with this field zeroed) and the context:
/// fn(std::span<const std::byte>, const emit_ctx&).
template <fixed_string Name, class Fn>
constexpr checksum_t<Name, Fn> checksum(Fn fn) { return {fn}; }

/// Specialize with `static constexpr auto fields = std::tuple{calc<"…">(…), checksum<"…">(…)};`.
template <class T>
struct computed {
  static constexpr auto fields = std::tuple<>{};
};

namespace detail {

template <class T> struct is_calc : std::false_type {};
template <fixed_string N, class F> struct is_calc<calc_t<N, F>> : std::true_type {};
template <class T> struct is_checksum : std::false_type {};
template <fixed_string N, class F> struct is_checksum<checksum_t<N, F>> : std::true_type {};

// ---- bit writing: the exact inverse of read_bits ------------------------------------------------
constexpr void write_bits(std::byte* p, std::size_t bitoff, unsigned n, std::uint64_t v, bit_order ord) {
  std::byte* q = p + bitoff / 8;
  std::size_t bit = bitoff % 8;
  for (unsigned got = 0; got < n;) {
    const unsigned avail = unsigned(8 - bit);
    const unsigned use = std::min(avail, n - got);
    const unsigned mask = (1u << use) - 1;
    unsigned piece, shift;
    if (ord == bit_order::msb0) {
      piece = unsigned(v >> (n - got - use)) & mask;  // the next `use` bits from the top
      shift = avail - use;
    } else {
      piece = unsigned(v >> got) & mask;              // the next `use` bits from the bottom
      shift = unsigned(bit);
    }
    const unsigned keep = ~(mask << shift) & 0xffu;
    *q = std::byte((unsigned(std::uint8_t(*q)) & keep) | (piece << shift));
    got += use;
    bit += use;
    if (bit == 8) {
      bit = 0;
      ++q;
    }
  }
}

template <class U>
constexpr void store_uint(std::byte* q, U u, std::size_t nbytes, std::endian order) {
  for (std::size_t i = 0; i < nbytes; ++i) {
    const std::size_t sh = order == std::endian::big ? 8 * (nbytes - 1 - i) : 8 * i;
    q[i] = std::byte(std::uint8_t(u >> sh));
  }
}

/// Write one field value at bitoff (inverse of assign_field). Returns null, or why it failed.
template <class F>
constexpr const char* emit_field(const F& v, std::byte* p, std::size_t bitoff, std::endian dflt) {
  if constexpr (requires { v.raw; typename F::value_type; F::order; }) {  // be / le: wire bytes
    for (std::size_t i = 0; i < v.raw.size(); ++i) p[bitoff / 8 + i] = v.raw[i];
    return nullptr;
  } else if constexpr (requires { F::order; F::bits; }) {  // ubits / ibits
    using VT = typename F::value_type;
    constexpr unsigned N = F::bits;
    std::uint64_t raw;
    if constexpr (std::is_signed_v<VT>) {
      const std::int64_t s = std::int64_t(v.v);
      raw = std::uint64_t(s);
      if constexpr (N < 64) {
        constexpr std::int64_t lo = -(std::int64_t(1) << (N - 1)), hi = (std::int64_t(1) << (N - 1)) - 1;
        if (s < lo || s > hi) return "a value outside its signed bit field";
        raw &= (std::uint64_t(1) << N) - 1;
      }
    } else {
      raw = std::uint64_t(v.v);
      if constexpr (N < 64)
        if ((raw >> N) != 0) return "a value wider than its bit field";
    }
    write_bits(p, bitoff, N, raw, F::order);
    return nullptr;
  } else if constexpr (is_std_array_v<F>) {
    using E = typename F::value_type;
    constexpr std::size_t eb = wire<E>::bits;
    for (std::size_t i = 0; i < v.size(); ++i)
      if (const char* e = emit_field<E>(v[i], p, bitoff + i * eb, dflt)) return e;
    return nullptr;
  } else if constexpr (std::integral<F> || std::floating_point<F>) {
    using U = uint_for_bytes<sizeof(F)>;
    store_uint(p + bitoff / 8, std::bit_cast<U>(v), sizeof(F), dflt);
    return nullptr;
  } else {  // nested described struct
    constexpr auto offs = field_bit_offsets<F>();
    const char* err = nullptr;
    std::size_t i = 0;
    for_each_field<F>([&](auto f) {
      const std::size_t o = offs[i++];
      if (!err) err = emit_field<member_t<decltype(f)::mem_ptr>>(v.*(decltype(f)::mem_ptr), p, bitoff + o, dflt);
    });
    return err;
  }
}

/// Field name of the first failing field (for error reports): re-walks T's top-level fields.
template <class T>
constexpr std::string_view first_bad_field(const T& v, std::endian dflt) {
  std::array<std::byte, wire_size_v<T>> scratch{};
  constexpr auto offs = field_bit_offsets<T>();
  std::string_view bad;
  std::size_t i = 0;
  for_each_field<T>([&](auto f) {
    const std::size_t o = offs[i++];
    if (bad.empty() && emit_field<member_t<decltype(f)::mem_ptr>>(v.*(decltype(f)::mem_ptr), scratch.data(), o, dflt))
      bad = decltype(f)::name.sv();
  });
  return bad;
}

/// Store an integer result into field type F, refusing a value that does not fit.
template <class F, class V>
constexpr bool set_computed(F& field, V value) {
  if constexpr (requires { field.raw; typename F::value_type; F::order; }) {  // be / le
    using T = typename F::value_type;
    if (!std::in_range<T>(value)) return false;
    field.set(T(value));
    return true;
  } else if constexpr (requires { F::order; F::bits; }) {  // ubits / ibits
    using VT = typename F::value_type;
    constexpr unsigned N = F::bits;
    if constexpr (std::is_signed_v<VT>) {
      if (!std::in_range<std::int64_t>(value)) return false;
      if constexpr (N < 64) {
        const auto s = std::int64_t(value);
        if (s < -(std::int64_t(1) << (N - 1)) || s > (std::int64_t(1) << (N - 1)) - 1) return false;
      }
    } else {
      if (!std::in_range<std::uint64_t>(value)) return false;
      if constexpr (N < 64)
        if ((std::uint64_t(value) >> N) != 0) return false;
    }
    field.v = VT(value);
    return true;
  } else if constexpr (std::integral<F>) {
    if (!std::in_range<F>(value)) return false;
    field = F(value);
    return true;
  } else {
    static_assert(sizeof(F) == 0, "nanom: a computed field must be an integer, be<>/le<> or bit field");
  }
}

template <class T, fixed_string Name>
constexpr auto& field_ref(T& v) {
  constexpr std::size_t I = field_index<T, Name>();
  static_assert(I != std::size_t(-1), "nanom: computed<T> names a field T does not have");
  using FD = std::remove_cvref_t<decltype(std::get<I>(describe<T>::fields()))>;
  return v.*(FD::mem_ptr);
}

/// Encode v (computed fields applied) into exactly wire_size_v<T> bytes at p.
template <Described T>
constexpr expected<std::size_t, encode_error> emit_struct(const T& value, std::byte* p, std::endian dflt,
                                                         const emit_ctx& ctx) {
  static_assert(layout_ok<T>(),
                "nanom: bit fields must pack to byte boundaries, every non-bit field must start byte-aligned, "
                "and msb0 / lsb0 runs must not share a byte");
  constexpr std::size_t size = wire_size_v<T>;
  constexpr auto offs = field_bit_offsets<T>();
  T v = value;
  const auto& specs = computed<T>::fields;
  // 1. calc fields, in order
  std::string_view bad;
  std::apply(
      [&](const auto&... spec) {
        (
            [&] {
              using S = std::remove_cvref_t<decltype(spec)>;
              if constexpr (is_calc<S>::value) {
                if (bad.empty() && !set_computed(field_ref<T, S::name>(v), spec.fn(std::as_const(v), ctx)))
                  bad = S::name.sv();
              }
            }(),
            ...);
      },
      specs);
  if (!bad.empty())
    return unexpected<encode_error>(encode_error{"a computed value that does not fit its field", describe<T>::name(), bad});
  // 2. every field
  for (std::size_t k = 0; k < size; ++k) p[k] = std::byte{0};
  {
    const char* err = nullptr;
    std::size_t i = 0;
    for_each_field<T>([&](auto f) {
      const std::size_t o = offs[i++];
      if (!err) err = emit_field<member_t<decltype(f)::mem_ptr>>(v.*(decltype(f)::mem_ptr), p, o, dflt);
    });
    if (err) return unexpected<encode_error>(encode_error{err, describe<T>::name(), first_bad_field(v, dflt)});
  }
  // 3. checksum fields: computed over the encoding with the field zeroed, then written in place
  std::apply(
      [&](const auto&... spec) {
        (
            [&] {
              using S = std::remove_cvref_t<decltype(spec)>;
              if constexpr (is_checksum<S>::value) {
                if (!bad.empty()) return;
                constexpr std::size_t I = field_index<T, S::name>();
                static_assert(I != std::size_t(-1), "nanom: computed<T> names a field T does not have");
                using F = field_type_at<T, I>;
                auto& fld = field_ref<T, S::name>(v);
                F zero{};
                (void)emit_field<F>(zero, p, offs[I], dflt);
                if (!set_computed(fld, spec.fn(std::span<const std::byte>(p, size), ctx)) ||
                    emit_field<F>(fld, p, offs[I], dflt))
                  bad = S::name.sv();
              }
            }(),
            ...);
      },
      specs);
  if (!bad.empty())
    return unexpected<encode_error>(encode_error{"a computed value that does not fit its field", describe<T>::name(), bad});
  return size;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// 44. emit / to_bytes / emit_frame / verify_computed
// ---------------------------------------------------------------------------

/// The wire bytes of v (computed fields applied). Usable in constant expressions.
template <Described T>
constexpr expected<std::array<std::byte, wire_size_v<T>>, encode_error> to_bytes(
    const T& v, const emit_ctx& ctx = {}, std::endian dflt = std::endian::native) {
  std::array<std::byte, wire_size_v<T>> out{};
  auto r = detail::emit_struct(v, out.data(), dflt, ctx);
  if (!r) return unexpected<encode_error>(r.error());
  return out;
}

/// Encode v into the start of `out` (which must hold wire_size_v<T> bytes); returns the size.
template <Described T>
constexpr expected<std::size_t, encode_error> emit(const T& v, std::span<std::byte> out, const emit_ctx& ctx = {},
                                                   std::endian dflt = std::endian::native) {
  if (out.size() < wire_size_v<T>)
    return unexpected<encode_error>(encode_error{"an output buffer smaller than the struct", describe<T>::name(), {}});
  return detail::emit_struct(v, out.data(), dflt, ctx);
}

/// Encode v into any byte sink.
template <Described T, byte_sink S>
expected<std::size_t, encode_error> emit_to(const T& v, S& sink, const emit_ctx& ctx = {},
                                            std::endian dflt = std::endian::native) {
  auto b = to_bytes(v, ctx, dflt);
  if (!b) return unexpected<encode_error>(b.error());
  if (!sink.put(b->data(), b->size()))
    return unexpected<encode_error>(encode_error{"the sink refused the bytes (full or failed)", describe<T>::name(), {}});
  return b->size();
}

/// A frame: v (with computed fields seeing `payload`), then the payload itself, passed to the sink
/// as is (no copy). Returns the total bytes written.
template <Described T, byte_sink S>
expected<std::size_t, encode_error> emit_frame(const T& v, std::span<const std::byte> payload, S& sink,
                                               std::endian dflt = std::endian::native) {
  auto n = emit_to(v, sink, emit_ctx{payload}, dflt);
  if (!n) return n;
  if (!payload.empty() && !sink.put(payload.data(), payload.size()))
    return unexpected<encode_error>(encode_error{"the sink refused the bytes (full or failed)", describe<T>::name(), {}});
  return *n + payload.size();
}

/// Read side: do the computed fields stored in `wire` (wire_size_v<T> bytes) match what writing the
/// decoded value would compute? (A received IPv4 header's checksum and total length, say.)
template <Described T>
constexpr bool verify_computed(std::span<const std::byte> wire, const emit_ctx& ctx = {},
                               std::endian dflt = std::endian::native) {
  if (wire.size() < wire_size_v<T>) return false;
  auto v = strct<T>(dflt)(from(wire));
  if (!v) return false;
  auto again = to_bytes(v->value, ctx, dflt);
  if (!again) return false;
  for (std::size_t i = 0; i < wire_size_v<T>; ++i)
    if ((*again)[i] != wire[i]) return false;
  return true;
}

}  // namespace nanom

#endif  // NANOM_EMIT_HPP_INCLUDED
