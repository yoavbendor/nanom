// SPDX-License-Identifier: Apache-2.0
// nanom/craft.hpp — composable binary crafting / serialization combinators (`nanom::craft`).
//
// Opt-in write-side header (Rule Zero: reading headers like nanom/nom.hpp, nanom/reflect.hpp, and
// nanom/nanom.hpp NEVER include this header).
//
// Four-layer distinction from parser combinators (`nanom::`):
//   1. Dedicated namespace `nanom::craft` (idiomatic alias `namespace nc = nanom::craft;`).
//   2. Non-colliding, write-oriented verbs (`put_*`, `cat`, `frame`, `each`, `when`,
//      `length_prefix`, `align_to`, `framed_by`, `prefixed_with`, `padded_to`, `write`, `size_of`).
//   3. Disjoint `Crafter` concept (`crafter_tag` + `.write(sink)` instead of `operator()(input)`):
//      a Crafter can NEVER satisfy `nanom::Parser` and vice versa.
//   4. Distinct operators: `+` for byte-stream concatenation (`c1 + c2`), and `|` ONLY with
//      `nanom::craft::craft_adaptor` (strictly disjoint from `nanom::parser_adaptor`).
//
// Zero-temp-vector back-patching: `frame` / `framed_by` and fixed-width `length_prefix` /
// `prefixed_with` reserve their header/length slot directly in `span_sink` or `vector_sink`,
// stream the inner crafter straight into the sink, and back-patch lengths & checksums in place.
#ifndef NANOM_CRAFT_HPP_INCLUDED
#define NANOM_CRAFT_HPP_INCLUDED

#include "emit.hpp"

#include <iterator>
#include <ranges>

namespace nanom::craft {

// ---------------------------------------------------------------------------
// 45. Crafter tag, concept, and execution entry points
// ---------------------------------------------------------------------------

struct crafter_tag {};

/// A composable serializer: derives from crafter_tag, NEVER satisfies nanom::Parser,
/// and writes into any byte_sink via `.write(sink)`.
template <class C>
concept Crafter =
    std::derived_from<std::remove_cvref_t<C>, crafter_tag> &&
    !::nanom::Parser<std::remove_cvref_t<C>>;

/// Execute a crafter into any byte_sink; returns total bytes written or encode_error.
template <Crafter C, byte_sink S>
expected<std::size_t, encode_error> write(const C& c, S& sink) {
  return c.write(sink);
}

/// Exact encoded byte size of a crafter (via counting_sink, nothing stored).
template <Crafter C>
expected<std::size_t, encode_error> size_of(const C& c) {
  counting_sink s;
  return c.write(s);
}

/// Convenience helper: execute a crafter into a fresh std::vector<std::byte>.
template <Crafter C>
expected<std::vector<std::byte>, encode_error> to_vector(const C& c) {
  std::vector<std::byte> out;
  vector_sink s{&out};
  auto r = c.write(s);
  if (!r) return unexpected<encode_error>(r.error());
  return out;
}

namespace detail {

inline unexpected<encode_error> sink_refused(std::string_view msg = "craft") {
  return unexpected<encode_error>(
      encode_error{"the sink refused the bytes (full or failed)", msg, {}});
}

template <std::size_t Bytes, std::endian Order>
struct put_uint_crafter : crafter_tag {
  static constexpr std::size_t fixed_size = Bytes;
  std::uint64_t val{};

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    if constexpr (Bytes < 8) {
      if ((val >> (8 * Bytes)) != 0)
        return unexpected<encode_error>(
            encode_error{"an integer value wider than its wire width", "craft::put_uint", {}});
    }
    std::byte buf[Bytes];
    if constexpr (Order == std::endian::big) {
      for (std::size_t i = 0; i < Bytes; ++i)
        buf[i] = std::byte(std::uint8_t(val >> (8 * (Bytes - 1 - i))));
    } else {
      for (std::size_t i = 0; i < Bytes; ++i)
        buf[i] = std::byte(std::uint8_t(val >> (8 * i)));
    }
    if (!sink.put(buf, Bytes)) return sink_refused("craft::put_uint");
    return Bytes;
  }
};

template <std::size_t Bytes, std::endian Order, class ArgT>
struct put_uint_fn {
  static constexpr std::size_t fixed_size = Bytes;

  constexpr put_uint_crafter<Bytes, Order> operator()(ArgT v) const noexcept {
    return {{}, static_cast<std::uint64_t>(v)};
  }

  /// Range-checked factory from std::size_t (used by length_prefix / prefixed_with).
  static constexpr expected<put_uint_crafter<Bytes, Order>, encode_error> from_size(
      std::size_t n) noexcept {
    if constexpr (Bytes < 8) {
      if ((std::uint64_t(n) >> (8 * Bytes)) != 0)
        return unexpected<encode_error>(
            encode_error{"a length prefix that does not fit its wire width", "craft::length_prefix", {}});
    }
    return put_uint_crafter<Bytes, Order>{{}, std::uint64_t(n)};
  }
};

struct put_uleb128_crafter : crafter_tag {
  std::uint64_t val{};

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    std::byte buf[10];
    std::size_t n = 0;
    std::uint64_t v = val;
    do {
      std::uint8_t b = std::uint8_t(v & 0x7fu);
      v >>= 7;
      if (v) b |= 0x80u;
      buf[n++] = std::byte(b);
    } while (v);
    if (!sink.put(buf, n)) return sink_refused("craft::put_uleb128");
    return n;
  }
};

struct put_uleb128_fn {
  constexpr put_uleb128_crafter operator()(std::uint64_t v) const noexcept {
    return {{}, v};
  }
};

struct put_bytes_crafter : crafter_tag {
  std::span<const std::byte> data;

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    if (!data.empty() && !sink.put(data.data(), data.size()))
      return sink_refused("craft::put_bytes");
    return data.size();
  }
};

struct put_pad_crafter : crafter_tag {
  std::size_t n{};
  std::byte   fill{0};

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    if (!n) return std::size_t{0};
    if constexpr (std::is_same_v<S, counting_sink>) {
      sink.put(nullptr, n);
      return n;
    } else {
      std::byte chunk[64];
      std::memset(chunk, std::to_integer<int>(fill), std::min<std::size_t>(n, sizeof(chunk)));
      std::size_t rem = n;
      while (rem) {
        const std::size_t step = std::min<std::size_t>(rem, sizeof(chunk));
        if (!sink.put(chunk, step)) return sink_refused("craft::put_pad");
        rem -= step;
      }
      return n;
    }
  }
};

template <Described H, class Ctx>
struct put_struct_crafter : crafter_tag {
  H           hdr;
  Ctx         ctx;
  std::endian dflt = std::endian::native;

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    return ::nanom::emit_to(hdr, sink, ctx, dflt);
  }
};

template <Crafter... Cs>
struct cat_crafter : crafter_tag {
  std::tuple<Cs...> parts;

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    std::size_t total = 0;
    std::optional<encode_error> err;
    std::apply(
        [&](const auto&... c) {
          (
              [&] {
                if (err) return;
                auto r = c.write(sink);
                if (!r) err = r.error();
                else total += *r;
              }(),
              ...);
        },
        parts);
    if (err) return unexpected<encode_error>(*err);
    return total;
  }
};

template <Described H, class Ctx, Crafter Body>
struct frame_crafter : crafter_tag {
  H           hdr;
  Ctx         ctx;
  Body        body;
  std::endian dflt = std::endian::native;

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    constexpr std::size_t hsz = wire_size_v<H>;
    if constexpr (std::is_same_v<S, counting_sink>) {
      if constexpr (!::nanom::detail::has_computed_v<H>) {
        std::array<std::byte, hsz> tmp{};
        auto hr = ::nanom::emit(hdr, std::span<std::byte>(tmp), ctx, dflt);
        if (!hr) return hr;
      } else {
        // The computed fields need the payload, which counting does not keep; still refuse an
        // out-of-range ordinary field, as writing the same frame would.
        auto hr = ::nanom::detail::check_noncomputed_fields(hdr, dflt);
        if (!hr) return hr;
      }
      if (!sink.put(nullptr, hsz)) return sink_refused(describe<H>::name());
      auto bn = body.write(sink);
      if (!bn) return bn;
      return hsz + *bn;
    } else if constexpr (std::is_same_v<S, span_sink>) {
      auto slot = sink.reserve(hsz);
      if (!slot) return sink_refused(describe<H>::name());
      const std::size_t body_start = sink.used;
      auto bn = body.write(sink);
      if (!bn) return bn;
      Ctx actual_ctx = ctx;
      if constexpr (requires { actual_ctx.payload; }) {
        actual_ctx.payload = std::span<const std::byte>(sink.out.data() + body_start, *bn);
      }
      auto hr = ::nanom::emit(hdr, *slot, actual_ctx, dflt);
      if (!hr) return hr;
      return hsz + *bn;
    } else if constexpr (std::is_same_v<S, vector_sink>) {
      const std::size_t hdr_off = sink.reserve_slot(hsz);
      const std::size_t body_start = sink.out->size();
      auto bn = body.write(sink);
      if (!bn) return bn;
      Ctx actual_ctx = ctx;
      if constexpr (requires { actual_ctx.payload; }) {
        actual_ctx.payload = std::span<const std::byte>(sink.out->data() + body_start, *bn);
      }
      auto hr = ::nanom::emit(hdr, std::span<std::byte>(sink.out->data() + hdr_off, hsz),
                              actual_ctx, dflt);
      if (!hr) return hr;
      return hsz + *bn;
    } else if constexpr (!::nanom::detail::has_computed_v<H>) {
      auto hr = ::nanom::emit_to(hdr, sink, ctx, dflt);
      if (!hr) return hr;
      auto bn = body.write(sink);
      if (!bn) return bn;
      return *hr + *bn;
    } else {
      // Non-patchable streaming sink with computed header: stage body once to compute length/checksum.
      std::vector<std::byte> staged;
      vector_sink vs{&staged};
      auto bn = body.write(vs);
      if (!bn) return bn;
      Ctx actual_ctx = ctx;
      if constexpr (requires { actual_ctx.payload; }) {
        actual_ctx.payload = staged;
      }
      auto hr = ::nanom::emit_to(hdr, sink, actual_ctx, dflt);
      if (!hr) return hr;
      if (!staged.empty() && !sink.put(staged.data(), staged.size()))
        return sink_refused(describe<H>::name());
      return *hr + staged.size();
    }
  }
};

template <class RangeRef, class Fn>
struct each_crafter : crafter_tag {
  RangeRef range;
  Fn       fn;

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    std::size_t total = 0;
    for (const auto& elem : range) {
      auto c = fn(elem);
      static_assert(Crafter<decltype(c)>, "nanom::craft::each: callback must return a Crafter");
      auto r = c.write(sink);
      if (!r) return r;
      total += *r;
    }
    return total;
  }
};

template <Crafter C>
struct when_crafter : crafter_tag {
  bool cond{};
  C    inner;

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    if (!cond) return std::size_t{0};
    return inner.write(sink);
  }
};

template <class LenFn, Crafter Body>
struct length_prefix_crafter : crafter_tag {
  LenFn len_fn;
  Body  body;

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    if constexpr (requires { LenFn::fixed_size; LenFn::from_size(std::size_t{0}); }) {
      constexpr std::size_t psz = LenFn::fixed_size;
      if constexpr (std::is_same_v<S, span_sink>) {
        auto slot = sink.reserve(psz);
        if (!slot) return sink_refused("craft::length_prefix");
        auto bn = body.write(sink);
        if (!bn) return bn;
        auto lc = LenFn::from_size(*bn);
        if (!lc) return unexpected<encode_error>(lc.error());
        span_sink patch{*slot};
        auto ln = lc->write(patch);
        if (!ln) return ln;
        return psz + *bn;
      } else if constexpr (std::is_same_v<S, vector_sink>) {
        const std::size_t off = sink.reserve_slot(psz);
        auto bn = body.write(sink);
        if (!bn) return bn;
        auto lc = LenFn::from_size(*bn);
        if (!lc) return unexpected<encode_error>(lc.error());
        span_sink patch{std::span<std::byte>(sink.out->data() + off, psz)};
        auto ln = lc->write(patch);
        if (!ln) return ln;
        return psz + *bn;
      } else {
        auto bn = ::nanom::craft::size_of(body);
        if (!bn) return bn;
        auto lc = LenFn::from_size(*bn);
        if (!lc) return unexpected<encode_error>(lc.error());
        auto ln = lc->write(sink);
        if (!ln) return ln;
        auto wn = body.write(sink);
        if (!wn) return wn;
        return *ln + *wn;
      }
    } else {
      auto bn = ::nanom::craft::size_of(body);
      if (!bn) return bn;
      auto lc = len_fn(*bn);
      static_assert(Crafter<decltype(lc)>, "nanom::craft::length_prefix: len_fn(size) must return a Crafter");
      auto ln = lc.write(sink);
      if (!ln) return ln;
      auto wn = body.write(sink);
      if (!wn) return wn;
      return *ln + *wn;
    }
  }
};

template <Crafter Body>
struct align_crafter : crafter_tag {
  Body        body;
  std::size_t alignment = 1;
  std::byte   pad{0};

  template <byte_sink S>
  expected<std::size_t, encode_error> write(S& sink) const {
    auto bn = body.write(sink);
    if (!bn) return bn;
    if (alignment <= 1) return *bn;
    const std::size_t rem = *bn % alignment;
    if (rem == 0) return *bn;
    const std::size_t pad_n = alignment - rem;
    auto pn = put_pad_crafter{{}, pad_n, pad}.write(sink);
    if (!pn) return pn;
    return *bn + *pn;
  }
};

}  // namespace detail

// ---------------------------------------------------------------------------
// 46. Leaf emitters (`put_*`) — function objects so they pass cleanly to prefixed_with(...)
// ---------------------------------------------------------------------------

inline constexpr detail::put_uint_fn<1, std::endian::big,    std::uint8_t>  put_u8{};
inline constexpr detail::put_uint_fn<2, std::endian::big,    std::uint16_t> put_be16{};
inline constexpr detail::put_uint_fn<3, std::endian::big,    std::uint32_t> put_be24{};
inline constexpr detail::put_uint_fn<4, std::endian::big,    std::uint32_t> put_be32{};
inline constexpr detail::put_uint_fn<6, std::endian::big,    std::uint64_t> put_be48{};
inline constexpr detail::put_uint_fn<8, std::endian::big,    std::uint64_t> put_be64{};
inline constexpr detail::put_uint_fn<2, std::endian::little, std::uint16_t> put_le16{};
inline constexpr detail::put_uint_fn<3, std::endian::little, std::uint32_t> put_le24{};
inline constexpr detail::put_uint_fn<4, std::endian::little, std::uint32_t> put_le32{};
inline constexpr detail::put_uint_fn<6, std::endian::little, std::uint64_t> put_le48{};
inline constexpr detail::put_uint_fn<8, std::endian::little, std::uint64_t> put_le64{};
inline constexpr detail::put_uleb128_fn                                     put_uleb128{};

constexpr detail::put_bytes_crafter put_bytes(std::span<const std::byte> data) noexcept {
  return {{}, data};
}
inline detail::put_bytes_crafter put_bytes(std::span<const std::uint8_t> data) noexcept {
  return {{}, std::as_bytes(data)};
}
inline detail::put_bytes_crafter put_lit(std::string_view s) noexcept {
  return {{}, std::span<const std::byte>(reinterpret_cast<const std::byte*>(s.data()), s.size())};
}
constexpr detail::put_pad_crafter put_pad(std::size_t n, std::byte fill = std::byte{0}) noexcept {
  return {{}, n, fill};
}
template <Described H, class Ctx = emit_ctx>
constexpr detail::put_struct_crafter<H, Ctx> put_struct(const H& hdr, const Ctx& ctx = Ctx{},
                                                        std::endian dflt = std::endian::native) {
  return {{}, hdr, ctx, dflt};
}

// ---------------------------------------------------------------------------
// 47. Structural crafters
// ---------------------------------------------------------------------------

/// Concatenate any number of crafters sequentially.
template <Crafter... Cs>
  requires(sizeof...(Cs) >= 1)
constexpr detail::cat_crafter<std::decay_t<Cs>...> cat(Cs&&... cs) {
  return {{}, std::tuple<std::decay_t<Cs>...>{std::forward<Cs>(cs)...}};
}

/// Frame `body` with header `hdr` (with optional custom Ctx), back-patching computed lengths
/// and checksums in place on span_sink / vector_sink with zero intermediate buffer allocations.
template <Described H, Crafter Body>
constexpr detail::frame_crafter<H, emit_ctx, std::decay_t<Body>> frame(
    const H& hdr, Body&& body, std::endian dflt = std::endian::native) {
  return {{}, hdr, emit_ctx{}, std::forward<Body>(body), dflt};
}
template <Described H, class Ctx, Crafter Body>
  requires(!Crafter<Ctx>)
constexpr detail::frame_crafter<H, std::decay_t<Ctx>, std::decay_t<Body>> frame(
    const H& hdr, Ctx&& ctx, Body&& body, std::endian dflt = std::endian::native) {
  return {{}, hdr, std::forward<Ctx>(ctx), std::forward<Body>(body), dflt};
}

/// Emit one crafter per element of `range` (borrows lvalue ranges, moves rvalue ranges).
template <std::ranges::input_range R, class Fn>
constexpr auto each(R&& range, Fn fn) {
  using Store = std::conditional_t<std::is_lvalue_reference_v<R>, R, std::decay_t<R>>;
  return detail::each_crafter<Store, std::decay_t<Fn>>{{}, std::forward<R>(range), std::move(fn)};
}

/// Conditionally emit `inner` when `cond` is true, else 0 bytes.
template <Crafter C>
constexpr detail::when_crafter<std::decay_t<C>> when(bool cond, C&& inner) {
  return {{}, cond, std::forward<C>(inner)};
}

/// Prefix `body` with its byte length encoded by `len_fn` (e.g. nc::put_u8, nc::put_be16, nc::put_uleb128).
template <class LenFn, Crafter Body>
constexpr detail::length_prefix_crafter<std::decay_t<LenFn>, std::decay_t<Body>> length_prefix(
    LenFn&& len_fn, Body&& body) {
  return {{}, std::forward<LenFn>(len_fn), std::forward<Body>(body)};
}

/// Emit `body` followed by enough `pad` bytes so the total emitted size is a multiple of `alignment`.
template <Crafter Body>
constexpr detail::align_crafter<std::decay_t<Body>> align_to(std::size_t alignment, Body&& body,
                                                             std::byte pad = std::byte{0}) {
  return {{}, std::forward<Body>(body), alignment, pad};
}

// ---------------------------------------------------------------------------
// 48. Distinct composition operators: `+` (concat) and `|` (craft_adaptor wrapping)
// ---------------------------------------------------------------------------

/// Byte-stream concatenation (`c1 + c2` -> `cat(c1, c2)`). Strictly constrained to Crafter.
template <Crafter C1, Crafter C2>
constexpr auto operator+(C1&& a, C2&& b) {
  return cat(std::forward<C1>(a), std::forward<C2>(b));
}

/// Wrapping/framing pipe adaptor — strictly disjoint from nanom::parser_adaptor.
template <class F>
struct craft_adaptor {
  F fn;
};
template <class F>
craft_adaptor(F) -> craft_adaptor<F>;

template <Crafter C, class F>
constexpr auto operator|(C&& c, craft_adaptor<F> a) {
  return a.fn(std::forward<C>(c));
}

template <class F, class G>
constexpr auto operator|(craft_adaptor<F> a, craft_adaptor<G> b) {
  return craft_adaptor{[a = std::move(a), b = std::move(b)]<Crafter C>(C&& c) {
    return b.fn(a.fn(std::forward<C>(c)));
  }};
}

/// Wrap a body crafter in header `hdr` (with optional custom `ctx`): `body | nc::framed_by(ip)`
template <Described H>
constexpr auto framed_by(H hdr, std::endian dflt = std::endian::native) {
  return craft_adaptor{[hdr = std::move(hdr), dflt]<Crafter Body>(Body&& body) {
    return frame(hdr, std::forward<Body>(body), dflt);
  }};
}
template <Described H, class Ctx>
  requires(!std::same_as<std::decay_t<Ctx>, std::endian> && !Crafter<Ctx>)
constexpr auto framed_by(H hdr, Ctx ctx, std::endian dflt = std::endian::native) {
  return craft_adaptor{[hdr = std::move(hdr), ctx = std::move(ctx), dflt]<Crafter Body>(Body&& body) {
    return frame(hdr, ctx, std::forward<Body>(body), dflt);
  }};
}

/// Prefix a body crafter with its encoded length: `body | nc::prefixed_with(nc::put_be16)`
template <class LenFn>
constexpr auto prefixed_with(LenFn len_fn) {
  return craft_adaptor{[len_fn = std::move(len_fn)]<Crafter Body>(Body&& body) {
    return length_prefix(len_fn, std::forward<Body>(body));
  }};
}

/// Pad a body crafter to a multiple of `alignment`: `body | nc::padded_to(4)`
constexpr auto padded_to(std::size_t alignment, std::byte pad = std::byte{0}) {
  return craft_adaptor{[alignment, pad]<Crafter Body>(Body&& body) {
    return align_to(alignment, std::forward<Body>(body), pad);
  }};
}

}  // namespace nanom::craft

#endif  // NANOM_CRAFT_HPP_INCLUDED
