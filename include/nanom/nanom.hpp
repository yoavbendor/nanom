// ============================================================================
// nanom — a nom-inspired single-header C++23 binary parser combinator library
// with struct registration, schema generation and columnar (SoA) storage.
//
//   https://github.com/yoavbendor/nanom
//
// Quick start (see README.md for more copy-paste examples):
//
//   #include <nanom/nanom.hpp>
//   namespace nm = nanom;
//
//   struct eth_hdr {
//     std::array<std::uint8_t,6> dst, src;
//     nm::be<std::uint16_t>      eth_type;
//   };
//   NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);
//
//   nm::input in = nm::from(buffer);
//   auto r = nm::strct<eth_hdr>()(in);              // parse by value
//   if (!r) { std::puts(r.error().render(in).c_str()); return; }
//   std::uint16_t t = r->value.eth_type;            // decoded, host order
//   nm::input rest = r->rest;                       // zero-copy remainder
//
// Everything a rust-nom user knows exists under the same name (see
// docs/CHEATSHEET.md): tag, take, take_while1, alt, opt, many0, preceded,
// delimited, separated_list0, length_data, map, verify, cut, context, be_u16…
//
// SPDX-License-Identifier: Apache-2.0
// ============================================================================
#ifndef NANOM_HPP_INCLUDED
#define NANOM_HPP_INCLUDED

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <version>
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
#include <expected>
#define NANOM_HAS_STD_EXPECTED 1
#else
#define NANOM_HAS_STD_EXPECTED 0
#endif
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

// NANOM_HD marks the functions on the zero-copy decode path as callable from a
// GPU kernel. On a normal host build it expands to nothing (zero cost, zero API
// change); under a CUDA/HIP compiler it becomes __host__ __device__ so the exact
// same overlay/decode code runs on the device. The failure/formatting paths
// (error::render, soa storage, the combinators that allocate) are deliberately
// NOT annotated — they stay host-only. See docs/GPU.md and include/nanom/bulk.hpp.
#ifndef NANOM_HD
#  if defined(__CUDACC__) || defined(__HIPCC__) || defined(__CUDA__)
#    define NANOM_HD __host__ __device__
#  else
#    define NANOM_HD
#  endif
#endif

namespace nanom {


// ---------------------------------------------------------------------------
// 0. expected — std::expected where available, a minimal stand-in otherwise
//    (clang < 19 with libstdc++ ships the header but disables it)
// ---------------------------------------------------------------------------

#if NANOM_HAS_STD_EXPECTED
template <class T, class E> using expected = std::expected<T, E>;
template <class E>          using unexpected = std::unexpected<E>;
#else
template <class E>
class unexpected {
 public:
  constexpr explicit unexpected(E e) : e_(std::move(e)) {}
  constexpr const E& error() const& { return e_; }
  constexpr E&&      error() &&     { return std::move(e_); }
 private:
  E e_;
};

/// Just enough of std::expected for nanom's needs.
template <class T, class E>
class expected {
 public:
  using value_type = T;
  template <class U>
    requires std::constructible_from<T, U&&> &&
             (!std::same_as<std::remove_cvref_t<U>, expected>) &&
             (!std::same_as<std::remove_cvref_t<U>, unexpected<E>>)
  constexpr expected(U&& u) : v_(std::in_place, std::forward<U>(u)) {}
  constexpr expected(unexpected<E> u) : e_(std::move(u).error()) {}

  constexpr bool has_value() const { return v_.has_value(); }
  constexpr explicit operator bool() const { return has_value(); }
  constexpr T&       operator*()        { return *v_; }
  constexpr const T& operator*() const  { return *v_; }
  constexpr T*       operator->()       { return &*v_; }
  constexpr const T* operator->() const { return &*v_; }
  constexpr E&       error()            { return e_; }
  constexpr const E& error() const      { return e_; }

 private:
  std::optional<T> v_;
  E                e_{};
};
#endif

// ---------------------------------------------------------------------------
// 1. input / bytes — zero-copy views over the buffer being parsed
// ---------------------------------------------------------------------------

using bytes = std::span<const std::byte>;

/// A cursor into the buffer under parse. Copying is free; parsers never copy
/// or allocate the underlying data. `base` is kept so errors can report
/// absolute offsets.
struct input {
  const std::byte* first = nullptr;
  const std::byte* last  = nullptr;
  const std::byte* base  = nullptr;
  /// streaming mode: running out of bytes yields an `incomplete` error
  /// (fetch more and retry) instead of a plain backtrackable error. Enable
  /// with nm::streaming(in). Default is complete/whole-buffer mode.
  bool live = false;

  constexpr input() = default;
  constexpr input(bytes b)
      : first(b.data()), last(b.data() + b.size()), base(b.data()) {}
  constexpr input(const std::byte* f, const std::byte* l, const std::byte* b,
                  bool lv = false)
      : first(f), last(l), base(b), live(lv) {}

  NANOM_HD constexpr std::size_t size()   const { return std::size_t(last - first); }
  NANOM_HD constexpr bool        empty()  const { return first == last; }
  NANOM_HD constexpr std::size_t offset() const { return std::size_t(first - base); }
  constexpr bytes       span()   const { return {first, size()}; }
  NANOM_HD constexpr std::uint8_t operator[](std::size_t i) const {
    return std::uint8_t(first[i]);
  }
  /// Cursor advanced by n bytes (precondition: n <= size()).
  NANOM_HD constexpr input advance(std::size_t n) const { return {first + n, last, base, live}; }
  /// First n bytes as a zero-copy span (precondition: n <= size()).
  NANOM_HD constexpr bytes take_span(std::size_t n) const { return {first, n}; }
};

/// Make an input from anything byte-like.
constexpr input from(bytes b) { return input(b); }
inline input from(std::string_view s) {
  return input(bytes(reinterpret_cast<const std::byte*>(s.data()), s.size()));
}
inline input from(const void* data, std::size_t len) {
  return input(bytes(static_cast<const std::byte*>(data), len));
}
template <class T, std::size_t N>
  requires(sizeof(T) == 1)
constexpr input from(const std::array<T, N>& a) {
  return from(a.data(), N);
}

/// Mark an input as a stream prefix: parsers that hit the end will report
/// `incomplete` with the byte count still needed, so the caller can refill
/// and retry (nom's streaming mode; default inputs behave like nom complete).
constexpr input streaming(input in) { in.live = true; return in; }

/// View a span of raw bytes as text (zero-copy).
inline std::string_view as_str(bytes b) {
  return {reinterpret_cast<const char*>(b.data()), b.size()};
}

// ---------------------------------------------------------------------------
// 2. error — POD, allocation-free until render()
// ---------------------------------------------------------------------------

/// nom's three-way error model:
///   err        recoverable — alt/opt/many will backtrack over it
///   fail       unrecoverable (produced by cut()) — propagates immediately
///   incomplete need more input (streaming) — complete() turns it into err
enum class errk : std::uint8_t { err, fail, incomplete };

/// Depth of the inline context() chain kept on the error. 4 is deeper than any
/// realistic hand-written parser nests context() frames; keeping it small
/// matters because std::expected sizes result<T> to max(sizeof(done<T>),
/// sizeof(error)), so a fat error taxes every parser return on the SUCCESS
/// path too. offsets are 32-bit for the same reason (a parse buffer over 4 GiB
/// is out of scope; the whole point is zero-copy in-memory parsing).
inline constexpr std::size_t max_context = 4;

struct error {
  struct frame { const char* label; std::uint32_t offset; };

  errk          kind     = errk::err;
  std::uint8_t  nctx     = 0;
  std::uint32_t offset   = 0;        ///< absolute byte offset of the failure
  const char*   expected = "";       ///< static string: what was expected here
  std::uint32_t needed   = 0;        ///< for incomplete: bytes missing (0 = unknown)
  std::array<frame, max_context> ctx{};  ///< context() chain, innermost first

  constexpr void push_context(const char* label, std::size_t off) {
    if (nctx < ctx.size()) ctx[nctx++] = {label, std::uint32_t(off)};
  }

  /// Pretty, localized message: offset, context chain, hex window with caret.
  /// This is the only error function that allocates.
  std::string render(input whole) const {
    std::string out;
    out += "parse ";
    out += kind == errk::incomplete ? "incomplete" : kind == errk::fail ? "failure" : "error";
    out += " at offset " + std::to_string(offset);
    if (needed)
      out += " (need " + std::to_string(needed) + " more byte(s))";
    out += ": expected ";
    out += expected;
    for (std::uint8_t i = 0; i < nctx; ++i) {
      out += "\n  in ";
      out += ctx[i].label;
      out += " (starting at offset " + std::to_string(ctx[i].offset) + ")";
    }
    // hex window: up to 8 bytes before and after the failure point
    const std::size_t total = std::size_t(whole.last - whole.base);
    const std::size_t off = offset;  // widen the 32-bit field for arithmetic
    if (off <= total) {
      const std::size_t lo = off >= 8 ? off - 8 : 0;
      const std::size_t hi = std::min(off + 8, total);
      static constexpr char hexd[] = "0123456789abcdef";
      std::string line = "  ", caret = "  ";
      for (std::size_t i = lo; i < hi; ++i) {
        const auto b = std::uint8_t(whole.base[i]);
        line += hexd[b >> 4]; line += hexd[b & 15]; line += ' ';
        caret += (i == off) ? "^^ " : "   ";
      }
      if (off == total) caret += "^^ (end of input)";
      out += "\n" + line + "\n" + caret;
    }
    return out;
  }
};

/// Wrap an error for propagation between differently-typed results.
inline unexpected<error> unexp(error e) { return unexpected<error>(std::move(e)); }

// ---------------------------------------------------------------------------
// 3. result<T> — nom's IResult: value + remaining input, or error
// ---------------------------------------------------------------------------

/// Successful parse: the produced value plus the un-consumed rest.
template <class T>
struct done {
  using type = T;
  T     value;
  input rest;
};
template <class T> done(T, input) -> done<T>;

template <class T>
using result = expected<done<T>, error>;

struct unit {};  ///< value of parsers that produce nothing (eof, not_, tag ok…)

/// Build a recoverable error at the current position.
inline unexpected<error> make_err(input at, const char* expected) {
  error e; e.kind = errk::err; e.offset = std::uint32_t(at.offset()); e.expected = expected;
  return unexp(e);
}
/// Ran out of input: `incomplete` on streaming inputs (caller refills and
/// retries), a plain backtrackable error on complete ones. `needed` is kept
/// either way for diagnostics.
inline unexpected<error> make_incomplete(input at, std::size_t needed) {
  error e; e.kind = at.live ? errk::incomplete : errk::err;
  e.offset = std::uint32_t(at.offset() + at.size());
  e.expected = "more input"; e.needed = std::uint32_t(needed);
  return unexp(e);
}

// ---------------------------------------------------------------------------
// 4. the Parser concept
// ---------------------------------------------------------------------------

namespace detail {
template <class R>            struct is_result : std::false_type {};
template <class T>            struct is_result<result<T>> : std::true_type {};
}  // namespace detail

/// A parser is any callable: (input) -> result<T>. Lambdas qualify; there is
/// no base class and no type erasure on the hot path.
template <class P>
concept Parser = std::invocable<const P&, input> &&
                 detail::is_result<std::invoke_result_t<const P&, input>>::value;

/// The value type a parser produces.
template <Parser P>
using parsed_t = typename std::invoke_result_t<const P&, input>::value_type::type;

// ---------------------------------------------------------------------------
// 5. primitive byte parsers (nom::bytes)
// ---------------------------------------------------------------------------

/// tag("GET") / tag(bytes) — match an exact byte sequence, yield it zero-copy.
/// NOTE: stores the pattern by reference; use with string literals or
/// outliving buffers (same rule as nom).
constexpr auto tag(std::string_view pattern) {
  return [pattern](input in) -> result<bytes> {
    if (in.size() < pattern.size()) return make_incomplete(in, pattern.size() - in.size());
    if (std::memcmp(in.first, pattern.data(), pattern.size()) != 0)
      return make_err(in, "tag");
    return done{in.take_span(pattern.size()), in.advance(pattern.size())};
  };
}
constexpr auto tag(bytes pattern) {
  return [pattern](input in) -> result<bytes> {
    if (in.size() < pattern.size()) return make_incomplete(in, pattern.size() - in.size());
    if (std::memcmp(in.first, pattern.data(), pattern.size()) != 0)
      return make_err(in, "tag");
    return done{in.take_span(pattern.size()), in.advance(pattern.size())};
  };
}

namespace detail {
constexpr char lower(char c) { return (c >= 'A' && c <= 'Z') ? char(c + 32) : c; }
}

/// tag_no_case("http") — ASCII case-insensitive tag.
constexpr auto tag_no_case(std::string_view pattern) {
  return [pattern](input in) -> result<bytes> {
    if (in.size() < pattern.size()) return make_incomplete(in, pattern.size() - in.size());
    for (std::size_t i = 0; i < pattern.size(); ++i)
      if (detail::lower(char(in[i])) != detail::lower(pattern[i]))
        return make_err(in, "tag_no_case");
    return done{in.take_span(pattern.size()), in.advance(pattern.size())};
  };
}

/// take(n) — exactly n bytes, zero-copy.
constexpr auto take(std::size_t n) {
  return [n](input in) -> result<bytes> {
    if (in.size() < n) return make_incomplete(in, n - in.size());
    return done{in.take_span(n), in.advance(n)};
  };
}

namespace detail {
/// Shared engine for the take_while / take_till family.
template <class Pred>
constexpr result<bytes> take_pred(input in, Pred&& pred, std::size_t min,
                                  std::size_t max, const char* what) {
  std::size_t i = 0;
  const std::size_t cap = std::min(max, in.size());
  while (i < cap && pred(std::uint8_t(in[i]))) ++i;
  if (i < min) {
    if (i == in.size()) return make_incomplete(in, min - i);
    return make_err(in.advance(i), what);
  }
  return done{in.take_span(i), in.advance(i)};
}
constexpr std::size_t nmax = std::numeric_limits<std::size_t>::max();
}  // namespace detail

/// take_while(pred) — longest (possibly empty) prefix where pred(byte) holds.
template <class Pred>
constexpr auto take_while(Pred pred) {
  return [pred](input in) { return detail::take_pred(in, pred, 0, detail::nmax, ""); };
}
/// take_while1(pred) — like take_while but the prefix must be non-empty.
template <class Pred>
constexpr auto take_while1(Pred pred) {
  return [pred](input in) {
    return detail::take_pred(in, pred, 1, detail::nmax, "take_while1: at least one matching byte");
  };
}
/// take_while_m_n(m, n, pred) — between m and n matching bytes.
template <class Pred>
constexpr auto take_while_m_n(std::size_t m, std::size_t n, Pred pred) {
  return [m, n, pred](input in) {
    return detail::take_pred(in, pred, m, n, "take_while_m_n: not enough matching bytes");
  };
}
/// take_till(pred) — longest prefix where pred does NOT hold.
template <class Pred>
constexpr auto take_till(Pred pred) {
  return [pred](input in) {
    return detail::take_pred(in, [pred](std::uint8_t b) { return !pred(b); }, 0,
                             detail::nmax, "");
  };
}
template <class Pred>
constexpr auto take_till1(Pred pred) {
  return [pred](input in) {
    return detail::take_pred(in, [pred](std::uint8_t b) { return !pred(b); }, 1,
                             detail::nmax, "take_till1: at least one byte before terminator");
  };
}

/// take_until("\r\n") — everything before the first occurrence of the needle
/// (needle not consumed). Incomplete if the needle never appears.
constexpr auto take_until(std::string_view needle) {
  return [needle](input in) -> result<bytes> {
    auto hay = in.span();
    auto ned = bytes(reinterpret_cast<const std::byte*>(needle.data()), needle.size());
    auto it = std::search(hay.begin(), hay.end(), ned.begin(), ned.end());
    if (it == hay.end()) return make_incomplete(in, 1);
    const std::size_t n = std::size_t(it - hay.begin());
    return done{in.take_span(n), in.advance(n)};
  };
}

/// is_a("0123456789abcdef") — 1+ bytes from the set. is_not — 1+ bytes NOT in it.
constexpr auto is_a(std::string_view set) {
  return [set](input in) {
    return detail::take_pred(
        in, [set](std::uint8_t b) { return set.find(char(b)) != std::string_view::npos; },
        1, detail::nmax, "is_a: byte from set");
  };
}
constexpr auto is_not(std::string_view set) {
  return [set](input in) {
    return detail::take_pred(
        in, [set](std::uint8_t b) { return set.find(char(b)) == std::string_view::npos; },
        1, detail::nmax, "is_not: byte outside set");
  };
}

// ---------------------------------------------------------------------------
// 6. character parsers (nom::character) — return char / string_view, zero-copy
// ---------------------------------------------------------------------------

/// chr('=') — a single specific character (nom's `char`, renamed: keyword).
constexpr auto chr(char c) {
  return [c](input in) -> result<char> {
    if (in.empty()) return make_incomplete(in, 1);
    if (char(in[0]) != c) return make_err(in, "character");
    return done{c, in.advance(1)};
  };
}
/// satisfy(isupper) — one char passing the predicate.
template <class Pred>
constexpr auto satisfy(Pred pred) {
  return [pred](input in) -> result<char> {
    if (in.empty()) return make_incomplete(in, 1);
    if (!pred(char(in[0]))) return make_err(in, "satisfy");
    return done{char(in[0]), in.advance(1)};
  };
}
/// one_of("+-") / none_of("\r\n") — one char (not) in the set.
constexpr auto one_of(std::string_view set) {
  return [set](input in) -> result<char> {
    if (in.empty()) return make_incomplete(in, 1);
    if (set.find(char(in[0])) == std::string_view::npos) return make_err(in, "one_of");
    return done{char(in[0]), in.advance(1)};
  };
}
constexpr auto none_of(std::string_view set) {
  return [set](input in) -> result<char> {
    if (in.empty()) return make_incomplete(in, 1);
    if (set.find(char(in[0])) != std::string_view::npos) return make_err(in, "none_of");
    return done{char(in[0]), in.advance(1)};
  };
}
/// anychar — any single char.
inline constexpr auto anychar = [](input in) -> result<char> {
  if (in.empty()) return make_incomplete(in, 1);
  return done{char(in[0]), in.advance(1)};
};

namespace detail {
constexpr bool is_alpha(std::uint8_t b) { return (b|32) >= 'a' && (b|32) <= 'z'; }
constexpr bool is_digit(std::uint8_t b) { return b >= '0' && b <= '9'; }
constexpr bool is_hex(std::uint8_t b)   { return is_digit(b) || ((b|32) >= 'a' && (b|32) <= 'f'); }
constexpr bool is_oct(std::uint8_t b)   { return b >= '0' && b <= '7'; }
constexpr bool is_alnum(std::uint8_t b) { return is_alpha(b) || is_digit(b); }
constexpr bool is_space(std::uint8_t b) { return b == ' ' || b == '\t'; }
constexpr bool is_mspace(std::uint8_t b){ return b == ' ' || b == '\t' || b == '\r' || b == '\n'; }

template <auto Pred>
constexpr result<std::string_view> klass(input in, std::size_t min, const char* what) {
  auto r = take_pred(in, Pred, min, nmax, what);
  if (!r) return unexp(r.error());
  return done{as_str(r->value), r->rest};
}
}  // namespace detail

// alpha0/1, digit0/1, … — runs of a character class, as string_view (zero-copy).
inline constexpr auto alpha0        = [](input in) { return detail::klass<detail::is_alpha>(in, 0, ""); };
inline constexpr auto alpha1        = [](input in) { return detail::klass<detail::is_alpha>(in, 1, "alphabetic"); };
inline constexpr auto digit0        = [](input in) { return detail::klass<detail::is_digit>(in, 0, ""); };
inline constexpr auto digit1        = [](input in) { return detail::klass<detail::is_digit>(in, 1, "digit"); };
inline constexpr auto hex_digit0    = [](input in) { return detail::klass<detail::is_hex>(in, 0, ""); };
inline constexpr auto hex_digit1    = [](input in) { return detail::klass<detail::is_hex>(in, 1, "hex digit"); };
inline constexpr auto oct_digit0    = [](input in) { return detail::klass<detail::is_oct>(in, 0, ""); };
inline constexpr auto oct_digit1    = [](input in) { return detail::klass<detail::is_oct>(in, 1, "octal digit"); };
inline constexpr auto alphanumeric0 = [](input in) { return detail::klass<detail::is_alnum>(in, 0, ""); };
inline constexpr auto alphanumeric1 = [](input in) { return detail::klass<detail::is_alnum>(in, 1, "alphanumeric"); };
inline constexpr auto space0        = [](input in) { return detail::klass<detail::is_space>(in, 0, ""); };
inline constexpr auto space1        = [](input in) { return detail::klass<detail::is_space>(in, 1, "space or tab"); };
inline constexpr auto multispace0   = [](input in) { return detail::klass<detail::is_mspace>(in, 0, ""); };
inline constexpr auto multispace1   = [](input in) { return detail::klass<detail::is_mspace>(in, 1, "whitespace"); };

inline constexpr auto newline = [](input in) { return chr('\n')(in); };
inline constexpr auto tab     = [](input in) { return chr('\t')(in); };
inline constexpr auto crlf    = [](input in) -> result<std::string_view> {
  auto r = tag("\r\n")(in);
  if (!r) return unexp(r.error());
  return done{as_str(r->value), r->rest};
};
/// "\n" or "\r\n"
inline constexpr auto line_ending = [](input in) -> result<std::string_view> {
  if (in.empty()) return make_incomplete(in, 1);
  if (char(in[0]) == '\n') return done{std::string_view("\n"), in.advance(1)};
  if (char(in[0]) == '\r') {
    if (in.size() < 2) return make_incomplete(in, 1);
    if (char(in[1]) == '\n') return done{as_str(in.take_span(2)), in.advance(2)};
  }
  return make_err(in, "line ending");
};
inline constexpr auto not_line_ending = [](input in) {
  auto r = detail::take_pred(in, [](std::uint8_t b) { return b != '\r' && b != '\n'; },
                             0, detail::nmax, "");
  return result<std::string_view>{done{as_str(r->value), r->rest}};
};

// ---------------------------------------------------------------------------
// 7. end-of-input & friends
// ---------------------------------------------------------------------------

/// eof — succeeds (with unit) only if all input is consumed.
inline constexpr auto eof = [](input in) -> result<unit> {
  if (!in.empty()) return make_err(in, "end of input");
  return done{unit{}, in};
};
/// rest — all remaining bytes, zero-copy. rest_len — how many are left.
inline constexpr auto rest = [](input in) -> result<bytes> {
  return done{in.span(), in.advance(in.size())};
};
inline constexpr auto rest_len = [](input in) -> result<std::size_t> {
  return done{in.size(), in};
};

// ---------------------------------------------------------------------------
// 8. sequence combinators (nom::sequence)
// ---------------------------------------------------------------------------

namespace detail {
template <class Tup, Parser P, Parser... Ps>
constexpr auto seq_step(Tup&& acc, input in, const P& p, const Ps&... ps)
    -> result<decltype(std::tuple_cat(std::move(acc), std::declval<std::tuple<parsed_t<P>, parsed_t<Ps>...>>()))> {
  auto r = p(in);
  if (!r) return unexp(r.error());
  auto acc2 = std::tuple_cat(std::move(acc), std::make_tuple(std::move(r->value)));
  if constexpr (sizeof...(Ps) == 0)
    return done{std::move(acc2), r->rest};
  else
    return seq_step(std::move(acc2), r->rest, ps...);
}
}  // namespace detail

/// seq(p1, p2, …) — run parsers in order, yield std::tuple of their values.
/// (nom calls this `tuple`; `seq` avoids clashing with std::tuple.)
template <Parser... Ps>
  requires(sizeof...(Ps) >= 1)
constexpr auto seq(Ps... ps) {
  return [ps...](input in) { return detail::seq_step(std::tuple<>{}, in, ps...); };
}

/// pair(a, b) — two values as std::pair.
template <Parser A, Parser B>
constexpr auto pair(A a, B b) {
  return [a, b](input in) -> result<std::pair<parsed_t<A>, parsed_t<B>>> {
    auto ra = a(in);
    if (!ra) return unexp(ra.error());
    auto rb = b(ra->rest);
    if (!rb) return unexp(rb.error());
    return done{std::pair{std::move(ra->value), std::move(rb->value)}, rb->rest};
  };
}
/// separated_pair(a, sep, b) — a and b keeping both, sep discarded.
template <Parser A, Parser S, Parser B>
constexpr auto separated_pair(A a, S sep, B b) {
  return [a, sep, b](input in) -> result<std::pair<parsed_t<A>, parsed_t<B>>> {
    auto ra = a(in);
    if (!ra) return unexp(ra.error());
    auto rs = sep(ra->rest);
    if (!rs) return unexp(rs.error());
    auto rb = b(rs->rest);
    if (!rb) return unexp(rb.error());
    return done{std::pair{std::move(ra->value), std::move(rb->value)}, rb->rest};
  };
}
/// preceded(skip, keep) — discard the first value, keep the second.
template <Parser A, Parser B>
constexpr auto preceded(A skip, B keep) {
  return [skip, keep](input in) -> result<parsed_t<B>> {
    auto ra = skip(in);
    if (!ra) return unexp(ra.error());
    return keep(ra->rest);
  };
}
/// terminated(keep, skip) — keep the first value, discard the second.
template <Parser A, Parser B>
constexpr auto terminated(A keep, B skip) {
  return [keep, skip](input in) -> result<parsed_t<A>> {
    auto ra = keep(in);
    if (!ra) return unexp(ra.error());
    auto rb = skip(ra->rest);
    if (!rb) return unexp(rb.error());
    return done{std::move(ra->value), rb->rest};
  };
}
/// delimited(open, body, close) — keep only the middle value.
template <Parser O, Parser M, Parser C>
constexpr auto delimited(O open, M body, C close) {
  return [open, body, close](input in) -> result<parsed_t<M>> {
    auto ro = open(in);
    if (!ro) return unexp(ro.error());
    auto rm = body(ro->rest);
    if (!rm) return unexp(rm.error());
    auto rc = close(rm->rest);
    if (!rc) return unexp(rc.error());
    return done{std::move(rm->value), rc->rest};
  };
}

// ---------------------------------------------------------------------------
// 9. branch combinators (nom::branch)
// ---------------------------------------------------------------------------

namespace detail {
/// keep whichever error got further into the input — much better alt
/// diagnostics than nom's "last branch wins".
inline const error& better(const error& a, const error& b) {
  return b.offset > a.offset ? b : a;
}

template <class V, Parser P, Parser... Ps>
constexpr result<V> alt_step(input in, const error* best, const P& p, const Ps&... ps) {
  auto r = p(in);
  if (r) return done{V(std::move(r->value)), r->rest};
  if (r.error().kind != errk::err) return unexp(r.error());  // failure/incomplete: stop
  const error& e = best ? better(*best, r.error()) : r.error();
  if constexpr (sizeof...(Ps) == 0) {
    error out = e;
    if (out.expected[0] == '\0') out.expected = "one of the alternatives";
    return unexp(out);
  } else {
    return alt_step<V>(in, &e, ps...);
  }
}
}  // namespace detail

/// alt(p1, p2, …) — first parser that succeeds wins. Backtracks on
/// recoverable errors; a cut() failure aborts the whole alt (nom semantics).
/// All alternatives must yield a common value type.
template <Parser P, Parser... Ps>
constexpr auto alt(P p, Ps... ps) {
  using V = std::common_type_t<parsed_t<P>, parsed_t<Ps>...>;
  return [p, ps...](input in) -> result<V> {
    return detail::alt_step<V>(in, nullptr, p, ps...);
  };
}

/// permutation(p1, p2, …) — all parsers exactly once, in any input order;
/// yields the tuple in declaration order.
template <Parser... Ps>
  requires(sizeof...(Ps) >= 1)
constexpr auto permutation(Ps... ps) {
  return [ps...](input in) -> result<std::tuple<parsed_t<Ps>...>> {
    constexpr std::size_t N = sizeof...(Ps);
    std::tuple<std::optional<parsed_t<Ps>>...> slots;
    auto parsers = std::tie(ps...);
    input cur = in;
    error deepest{};
    for (std::size_t round = 0; round < N; ++round) {
      bool progressed = false;
      expected<input, error> abort_err = cur;  // reused as failure carrier
      auto try_one = [&]<std::size_t I>(std::integral_constant<std::size_t, I>) {
        if (progressed || std::get<I>(slots)) return true;
        auto r = std::get<I>(parsers)(cur);
        if (r) {
          std::get<I>(slots).emplace(std::move(r->value));
          cur = r->rest;
          progressed = true;
        } else if (r.error().kind != errk::err) {
          abort_err = unexp(r.error());
          return false;
        } else {
          deepest = detail::better(deepest, r.error());
        }
        return true;
      };
      bool okrun = [&]<std::size_t... Is>(std::index_sequence<Is...>) {
        return (try_one(std::integral_constant<std::size_t, Is>{}) && ...);
      }(std::make_index_sequence<N>{});
      if (!okrun) return unexp(abort_err.error());
      if (!progressed) {
        error e = deepest;
        if (e.expected[0] == '\0') { e.offset = cur.offset(); e.expected = "permutation alternative"; }
        return unexp(e);
      }
    }
    return done{[&]<std::size_t... Is>(std::index_sequence<Is...>) {
      return std::tuple<parsed_t<Ps>...>{std::move(*std::get<Is>(slots))...};
    }(std::make_index_sequence<N>{}), cur};
  };
}

// ---------------------------------------------------------------------------
// 10. repetition combinators (nom::multi)
// ---------------------------------------------------------------------------

/// many0(p) — zero or more, into std::vector. Errors (like nom) if p succeeds
/// without consuming, to prevent infinite loops.
template <Parser P>
constexpr auto many0(P p) {
  return [p](input in) -> result<std::vector<parsed_t<P>>> {
    std::vector<parsed_t<P>> out;
    input cur = in;
    for (;;) {
      auto r = p(cur);
      if (!r) {
        if (r.error().kind != errk::err) return unexp(r.error());
        return done{std::move(out), cur};
      }
      if (r->rest.first == cur.first) return make_err(cur, "many0: inner parser must consume input");
      out.push_back(std::move(r->value));
      cur = r->rest;
    }
  };
}
/// many1(p) — one or more.
template <Parser P>
constexpr auto many1(P p) {
  return [p](input in) -> result<std::vector<parsed_t<P>>> {
    auto first = p(in);
    if (!first) return unexp(first.error());
    auto more = many0(p)(first->rest);
    if (!more) return unexp(more.error());
    more->value.insert(more->value.begin(), std::move(first->value));
    return done{std::move(more->value), more->rest};
  };
}
/// many_m_n(m, n, p) — between m and n repetitions.
template <Parser P>
constexpr auto many_m_n(std::size_t m, std::size_t n, P p) {
  return [m, n, p](input in) -> result<std::vector<parsed_t<P>>> {
    std::vector<parsed_t<P>> out;
    input cur = in;
    while (out.size() < n) {
      auto r = p(cur);
      if (!r) {
        if (r.error().kind != errk::err) return unexp(r.error());
        break;
      }
      if (r->rest.first == cur.first) return make_err(cur, "many_m_n: inner parser must consume input");
      out.push_back(std::move(r->value));
      cur = r->rest;
    }
    if (out.size() < m) return make_err(cur, "many_m_n: not enough repetitions");
    return done{std::move(out), cur};
  };
}
/// many_till(p, end) — repeat p until end succeeds; yields {vector, end value}.
template <Parser P, Parser E>
constexpr auto many_till(P p, E end) {
  return [p, end](input in) -> result<std::pair<std::vector<parsed_t<P>>, parsed_t<E>>> {
    std::vector<parsed_t<P>> out;
    input cur = in;
    for (;;) {
      if (auto re = end(cur)) return done{std::pair{std::move(out), std::move(re->value)}, re->rest};
      else if (re.error().kind != errk::err) return unexp(re.error());
      auto r = p(cur);
      if (!r) return unexp(r.error());
      if (r->rest.first == cur.first) return make_err(cur, "many_till: inner parser must consume input");
      out.push_back(std::move(r->value));
      cur = r->rest;
    }
  };
}
/// count(p, n) — exactly n repetitions.
template <Parser P>
constexpr auto count(P p, std::size_t n) {
  return [p, n](input in) -> result<std::vector<parsed_t<P>>> {
    std::vector<parsed_t<P>> out;
    out.reserve(n);
    input cur = in;
    for (std::size_t i = 0; i < n; ++i) {
      auto r = p(cur);
      if (!r) return unexp(r.error());
      out.push_back(std::move(r->value));
      cur = r->rest;
    }
    return done{std::move(out), cur};
  };
}

/// separated_list0(sep, p) / separated_list1 — p (sep p)*, seps discarded.
template <Parser S, Parser P>
constexpr auto separated_list0(S sep, P p) {
  return [sep, p](input in) -> result<std::vector<parsed_t<P>>> {
    std::vector<parsed_t<P>> out;
    auto r = p(in);
    if (!r) {
      if (r.error().kind == errk::fail) return unexp(r.error());
      return done{std::move(out), in};
    }
    out.push_back(std::move(r->value));
    input cur = r->rest;
    for (;;) {
      auto rs = sep(cur);
      if (!rs) {
        if (rs.error().kind == errk::fail) return unexp(rs.error());
        return done{std::move(out), cur};
      }
      auto rp = p(rs->rest);
      if (!rp) {
        if (rp.error().kind == errk::fail) return unexp(rp.error());
        return done{std::move(out), cur};
      }
      if (rp->rest.first == cur.first) return make_err(cur, "separated_list0: no progress");
      out.push_back(std::move(rp->value));
      cur = rp->rest;
    }
  };
}
template <Parser S, Parser P>
constexpr auto separated_list1(S sep, P p) {
  return [sep, p](input in) -> result<std::vector<parsed_t<P>>> {
    auto r = separated_list0(sep, p)(in);
    if (!r) return unexp(r.error());
    if (r->value.empty()) return make_err(in, "separated_list1: at least one element");
    return r;
  };
}

/// fold_many0(p, init, f) — like many0 but folds instead of collecting.
/// init is a callable returning the accumulator; f(acc&, value).
template <Parser P, class Init, class F>
constexpr auto fold_many0(P p, Init init, F f) {
  return [p, init, f](input in) -> result<std::decay_t<std::invoke_result_t<const Init&>>> {
    auto acc = init();
    input cur = in;
    for (;;) {
      auto r = p(cur);
      if (!r) {
        if (r.error().kind != errk::err) return unexp(r.error());
        return done{std::move(acc), cur};
      }
      if (r->rest.first == cur.first) return make_err(cur, "fold_many0: inner parser must consume input");
      f(acc, std::move(r->value));
      cur = r->rest;
    }
  };
}
template <Parser P, class Init, class F>
constexpr auto fold_many1(P p, Init init, F f) {
  return [p, init, f](input in) -> result<std::decay_t<std::invoke_result_t<const Init&>>> {
    auto first = p(in);
    if (!first) return unexp(first.error());
    auto acc = init();
    f(acc, std::move(first->value));
    input cur = first->rest;
    for (;;) {
      auto r = p(cur);
      if (!r) {
        if (r.error().kind != errk::err) return unexp(r.error());
        return done{std::move(acc), cur};
      }
      if (r->rest.first == cur.first) return make_err(cur, "fold_many1: inner parser must consume input");
      f(acc, std::move(r->value));
      cur = r->rest;
    }
  };
}
template <Parser P, class Init, class F>
constexpr auto fold_many_m_n(std::size_t m, std::size_t n, P p, Init init, F f) {
  return [m, n, p, init, f](input in) -> result<std::decay_t<std::invoke_result_t<const Init&>>> {
    auto acc = init();
    input cur = in;
    std::size_t got = 0;
    while (got < n) {
      auto r = p(cur);
      if (!r) {
        if (r.error().kind != errk::err) return unexp(r.error());
        break;
      }
      if (r->rest.first == cur.first) return make_err(cur, "fold_many_m_n: inner parser must consume input");
      f(acc, std::move(r->value));
      cur = r->rest;
      ++got;
    }
    if (got < m) return make_err(cur, "fold_many_m_n: not enough repetitions");
    return done{std::move(acc), cur};
  };
}

/// length_data(np) — np yields a length N; then take N raw bytes (zero-copy).
template <Parser N>
constexpr auto length_data(N np) {
  return [np](input in) -> result<bytes> {
    auto rn = np(in);
    if (!rn) return unexp(rn.error());
    return take(std::size_t(rn->value))(rn->rest);
  };
}
/// length_value(np, p) — take a length-prefixed slice, run p on it alone;
/// p must consume the slice's content (errors inside stay localized).
template <Parser N, Parser P>
constexpr auto length_value(N np, P p) {
  return [np, p](input in) -> result<parsed_t<P>> {
    auto rd = length_data(np)(in);
    if (!rd) return unexp(rd.error());
    // sub-input keeps the same base so error offsets remain absolute
    input sub{rd->value.data(), rd->value.data() + rd->value.size(), in.base};
    auto r = p(sub);
    if (!r) {
      error e = r.error();
      if (e.kind == errk::incomplete) { e.kind = errk::err; e.expected = "value fitting its length prefix"; }
      return unexp(e);
    }
    return done{std::move(r->value), rd->rest};
  };
}
/// length_count(np, p) — np yields N; then exactly N repetitions of p.
template <Parser N, Parser P>
constexpr auto length_count(N np, P p) {
  return [np, p](input in) -> result<std::vector<parsed_t<P>>> {
    auto rn = np(in);
    if (!rn) return unexp(rn.error());
    return count(p, std::size_t(rn->value))(rn->rest);
  };
}

// ---------------------------------------------------------------------------
// 11. modifiers (nom::combinator)
// ---------------------------------------------------------------------------

/// map(p, f) — transform the parsed value.
template <Parser P, class F>
constexpr auto map(P p, F f) {
  return [p, f](input in) -> result<std::decay_t<std::invoke_result_t<const F&, parsed_t<P>&&>>> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    return done{f(std::move(r->value)), r->rest};
  };
}
/// map_opt(p, f) — f returns std::optional; empty optional = parse error.
template <Parser P, class F>
constexpr auto map_opt(P p, F f) {
  return [p, f](input in)
             -> result<typename std::decay_t<std::invoke_result_t<const F&, parsed_t<P>&&>>::value_type> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    auto v = f(std::move(r->value));
    if (!v) return make_err(in, "map_opt: conversion");
    return done{std::move(*v), r->rest};
  };
}
/// map_res — alias of map_opt (C++ has no std Result; use optional/expected).
template <Parser P, class F>
constexpr auto map_res(P p, F f) { return map_opt(p, f); }

/// map_parser(p, q) — run q over the bytes produced by p (p must yield bytes
/// or string_view).
template <Parser P, Parser Q>
constexpr auto map_parser(P p, Q q) {
  return [p, q](input in) -> result<parsed_t<Q>> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    auto b = [&]() -> bytes {
      if constexpr (std::is_same_v<parsed_t<P>, std::string_view>)
        return bytes(reinterpret_cast<const std::byte*>(r->value.data()), r->value.size());
      else
        return r->value;
    }();
    input sub{b.data(), b.data() + b.size(), in.base};
    auto rq = q(sub);
    if (!rq) return unexp(rq.error());
    return done{std::move(rq->value), r->rest};
  };
}
/// flat_map(p, f) — f(value) returns the *next parser* (monadic bind).
template <Parser P, class F>
constexpr auto flat_map(P p, F f) {
  return [p, f](input in) {
    using Q = std::decay_t<std::invoke_result_t<const F&, parsed_t<P>&&>>;
    using R = result<parsed_t<Q>>;
    auto r = p(in);
    if (!r) return R{unexp(r.error())};
    return R{f(std::move(r->value))(r->rest)};
  };
}

/// opt(p) — std::optional<V>: engaged on success, nullopt on recoverable
/// error (Failure from cut() still propagates).
template <Parser P>
constexpr auto opt(P p) {
  return [p](input in) -> result<std::optional<parsed_t<P>>> {
    auto r = p(in);
    if (r) return done{std::optional<parsed_t<P>>(std::move(r->value)), r->rest};
    if (r.error().kind == errk::fail) return unexp(r.error());
    return done{std::optional<parsed_t<P>>{}, in};
  };
}
/// cond(b, p) — run p only when b is true (optional value).
template <Parser P>
constexpr auto cond(bool b, P p) {
  return [b, p](input in) -> result<std::optional<parsed_t<P>>> {
    if (!b) return done{std::optional<parsed_t<P>>{}, in};
    auto r = p(in);
    if (!r) return unexp(r.error());
    return done{std::optional<parsed_t<P>>(std::move(r->value)), r->rest};
  };
}
/// peek(p) — parse without consuming.
template <Parser P>
constexpr auto peek(P p) {
  return [p](input in) -> result<parsed_t<P>> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    return done{std::move(r->value), in};
  };
}
/// not_(p) — succeed (consuming nothing) iff p fails. (nom's `not`.)
template <Parser P>
constexpr auto not_(P p) {
  return [p](input in) -> result<unit> {
    auto r = p(in);
    if (r) return make_err(in, "not: inner parser must fail");
    if (r.error().kind == errk::fail) return unexp(r.error());
    return done{unit{}, in};
  };
}
/// recognize(p) — throw away p's value, yield the raw consumed bytes.
template <Parser P>
constexpr auto recognize(P p) {
  return [p](input in) -> result<bytes> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    return done{bytes{in.first, std::size_t(r->rest.first - in.first)}, r->rest};
  };
}
/// consumed(p) — both the raw bytes and the value, as a pair.
template <Parser P>
constexpr auto consumed(P p) {
  return [p](input in) -> result<std::pair<bytes, parsed_t<P>>> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    return done{std::pair{bytes{in.first, std::size_t(r->rest.first - in.first)},
                          std::move(r->value)}, r->rest};
  };
}
/// value(v, p) — run p, discard its result, yield v.
template <class V, Parser P>
constexpr auto value(V v, P p) {
  return [v, p](input in) -> result<V> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    return done{v, r->rest};
  };
}
/// verify(p, pred) — succeed only if pred(value) holds.
template <Parser P, class Pred>
constexpr auto verify(P p, Pred pred) {
  return [p, pred](input in) -> result<parsed_t<P>> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    if (!pred(std::as_const(r->value))) return make_err(in, "verify: predicate");
    return r;
  };
}
/// success(v) — always succeed with v, consuming nothing. fail() — always fail.
template <class V>
constexpr auto success(V v) {
  return [v](input in) -> result<V> { return done{v, in}; };
}
constexpr auto fail(const char* why = "fail") {
  return [why](input in) -> result<unit> { return make_err(in, why); };
}

/// cut(p) — commit: upgrade p's recoverable errors to failures so enclosing
/// alt/opt/many stop backtracking. THE tool for precise error locations.
template <Parser P>
constexpr auto cut(P p) {
  return [p](input in) -> result<parsed_t<P>> {
    auto r = p(in);
    if (!r && r.error().kind == errk::err) {
      error e = r.error();
      e.kind = errk::fail;
      return unexp(e);
    }
    return r;
  };
}
/// complete(p) — whole-buffer mode: Incomplete becomes a plain error.
template <Parser P>
constexpr auto complete(P p) {
  return [p](input in) -> result<parsed_t<P>> {
    auto r = p(in);
    if (!r && r.error().kind == errk::incomplete) {
      error e = r.error();
      e.kind = errk::err;
      return unexp(e);
    }
    return r;
  };
}
/// all_consuming(p) — p must eat every remaining byte.
template <Parser P>
constexpr auto all_consuming(P p) {
  return [p](input in) -> result<parsed_t<P>> {
    auto r = p(in);
    if (!r) return unexp(r.error());
    if (!r->rest.empty()) return make_err(r->rest, "all_consuming: trailing bytes");
    return r;
  };
}
/// into<T>(p) — value converted to T (nom's `into`).
template <class T, Parser P>
constexpr auto into(P p) {
  return map(p, [](parsed_t<P>&& v) { return T(std::move(v)); });
}

/// context("ipv4 header", p) — label a region for error messages; labels
/// stack (innermost first) and appear in error::render().
template <Parser P>
constexpr auto context(const char* label, P p) {
  return [label, p](input in) -> result<parsed_t<P>> {
    auto r = p(in);
    if (!r) {
      error e = r.error();
      e.push_context(label, in.offset());
      return unexp(e);
    }
    return r;
  };
}

// ---------------------------------------------------------------------------
// 12. binary numbers (nom::number) — be_/le_/ne_ × u8..u64, i8..i64, f32, f64
// ---------------------------------------------------------------------------

namespace detail {
template <std::size_t Bytes>
using uint_for_bytes =
    std::conditional_t<Bytes <= 1, std::uint8_t,
    std::conditional_t<Bytes <= 2, std::uint16_t,
    std::conditional_t<Bytes <= 4, std::uint32_t, std::uint64_t>>>;

/// Read Bytes bytes as an unsigned integer with the given byte order.
/// Handles widths that are not a power of two (u24, u48, …) like nom does.
template <std::size_t Bytes>
constexpr result<uint_for_bytes<Bytes>> read_uint(input in, std::endian order) {
  static_assert(Bytes >= 1 && Bytes <= 8);
  if (in.size() < Bytes) return make_incomplete(in, Bytes - in.size());
  using U = uint_for_bytes<Bytes>;
  U v = 0;
  if (order == std::endian::big)
    for (std::size_t i = 0; i < Bytes; ++i) v = U(v << 8) | in[i];
  else
    for (std::size_t i = 0; i < Bytes; ++i) v |= U(U(in[i]) << (8 * i));
  return done{v, in.advance(Bytes)};
}

template <class T> struct signed_of;
template <> struct signed_of<std::uint8_t>  { using type = std::int8_t; };
template <> struct signed_of<std::uint16_t> { using type = std::int16_t; };
template <> struct signed_of<std::uint32_t> { using type = std::int32_t; };
template <> struct signed_of<std::uint64_t> { using type = std::int64_t; };
}  // namespace detail

// --- unsigned, fixed order ---
inline constexpr auto be_u8  = [](input in) { return detail::read_uint<1>(in, std::endian::big); };
inline constexpr auto be_u16 = [](input in) { return detail::read_uint<2>(in, std::endian::big); };
inline constexpr auto be_u24 = [](input in) { return detail::read_uint<3>(in, std::endian::big); };
inline constexpr auto be_u32 = [](input in) { return detail::read_uint<4>(in, std::endian::big); };
inline constexpr auto be_u48 = [](input in) { return detail::read_uint<6>(in, std::endian::big); };
inline constexpr auto be_u64 = [](input in) { return detail::read_uint<8>(in, std::endian::big); };
inline constexpr auto le_u8  = [](input in) { return detail::read_uint<1>(in, std::endian::little); };
inline constexpr auto le_u16 = [](input in) { return detail::read_uint<2>(in, std::endian::little); };
inline constexpr auto le_u24 = [](input in) { return detail::read_uint<3>(in, std::endian::little); };
inline constexpr auto le_u32 = [](input in) { return detail::read_uint<4>(in, std::endian::little); };
inline constexpr auto le_u48 = [](input in) { return detail::read_uint<6>(in, std::endian::little); };
inline constexpr auto le_u64 = [](input in) { return detail::read_uint<8>(in, std::endian::little); };

namespace detail {
template <std::size_t Bytes>
constexpr result<typename signed_of<uint_for_bytes<Bytes>>::type>
read_int(input in, std::endian order) {
  auto r = read_uint<Bytes>(in, order);
  if (!r) return unexp(r.error());
  using S = typename signed_of<uint_for_bytes<Bytes>>::type;
  return done{std::bit_cast<S>(r->value), r->rest};
}
}  // namespace detail

// --- signed, fixed order ---
inline constexpr auto be_i8  = [](input in) { return detail::read_int<1>(in, std::endian::big); };
inline constexpr auto be_i16 = [](input in) { return detail::read_int<2>(in, std::endian::big); };
inline constexpr auto be_i32 = [](input in) { return detail::read_int<4>(in, std::endian::big); };
inline constexpr auto be_i64 = [](input in) { return detail::read_int<8>(in, std::endian::big); };
inline constexpr auto le_i8  = [](input in) { return detail::read_int<1>(in, std::endian::little); };
inline constexpr auto le_i16 = [](input in) { return detail::read_int<2>(in, std::endian::little); };
inline constexpr auto le_i32 = [](input in) { return detail::read_int<4>(in, std::endian::little); };
inline constexpr auto le_i64 = [](input in) { return detail::read_int<8>(in, std::endian::little); };

// --- floats ---
inline constexpr auto be_f32 = [](input in) -> result<float> {
  auto r = detail::read_uint<4>(in, std::endian::big);
  if (!r) return unexp(r.error());
  return done{std::bit_cast<float>(r->value), r->rest};
};
inline constexpr auto be_f64 = [](input in) -> result<double> {
  auto r = detail::read_uint<8>(in, std::endian::big);
  if (!r) return unexp(r.error());
  return done{std::bit_cast<double>(r->value), r->rest};
};
inline constexpr auto le_f32 = [](input in) -> result<float> {
  auto r = detail::read_uint<4>(in, std::endian::little);
  if (!r) return unexp(r.error());
  return done{std::bit_cast<float>(r->value), r->rest};
};
inline constexpr auto le_f64 = [](input in) -> result<double> {
  auto r = detail::read_uint<8>(in, std::endian::little);
  if (!r) return unexp(r.error());
  return done{std::bit_cast<double>(r->value), r->rest};
};

// --- single bytes (nom's u8/i8) ---
inline constexpr auto u8 = be_u8;
inline constexpr auto i8 = [](input in) { return detail::read_int<1>(in, std::endian::big); };

// --- native order + RUNTIME order (for formats like ELF that pick at parse
//     time; nom has no equivalent) ---
inline constexpr auto ne_u16 = [](input in) { return detail::read_uint<2>(in, std::endian::native); };
inline constexpr auto ne_u32 = [](input in) { return detail::read_uint<4>(in, std::endian::native); };
inline constexpr auto ne_u64 = [](input in) { return detail::read_uint<8>(in, std::endian::native); };

/// uint<T>(order) — integer of T's width with an endianness chosen at runtime.
template <class T>
  requires std::integral<T>
constexpr auto uint_(std::endian order) {
  return [order](input in) -> result<T> {
    auto r = detail::read_uint<sizeof(T)>(in, order);
    if (!r) return unexp(r.error());
    return done{T(r->value), r->rest};
  };
}

// ---------------------------------------------------------------------------
// 13. text numbers — decimal / hex / float from ASCII (nom::character +
//     nom::number text parsers)
// ---------------------------------------------------------------------------

/// dec<T>() — decimal integer ("42", "-7" if T is signed), overflow-checked.
template <class T>
  requires std::integral<T>
constexpr auto dec() {
  return [](input in) -> result<T> {
    const char* b = reinterpret_cast<const char*>(in.first);
    const char* e = reinterpret_cast<const char*>(in.last);
    T v{};
    auto [p, ec] = std::from_chars(b, e, v, 10);
    if (ec != std::errc{} || p == b) return make_err(in, "decimal integer");
    return done{v, in.advance(std::size_t(p - b))};
  };
}
/// hex<T>() — hexadecimal integer without prefix ("deadBEEF").
template <class T>
  requires std::unsigned_integral<T>
constexpr auto hex() {
  return [](input in) -> result<T> {
    const char* b = reinterpret_cast<const char*>(in.first);
    const char* e = reinterpret_cast<const char*>(in.last);
    T v{};
    auto [p, ec] = std::from_chars(b, e, v, 16);
    if (ec != std::errc{} || p == b) return make_err(in, "hex integer");
    return done{v, in.advance(std::size_t(p - b))};
  };
}
/// float_ / double_ — text floating point ("3.14", "-1e9"). (nom: float/double)
inline constexpr auto double_ = [](input in) -> result<double> {
  const char* b = reinterpret_cast<const char*>(in.first);
  const char* e = reinterpret_cast<const char*>(in.last);
  double v{};
  // NB: the floating-point from_chars overload takes std::chars_format (default
  // = general), NOT an integer base — passing a base here is ill-formed.
  auto [p, ec] = std::from_chars(b, e, v);
  if (ec != std::errc{} || p == b) return make_err(in, "floating point number");
  return done{v, in.advance(std::size_t(p - b))};
};
inline constexpr auto float_ = [](input in) -> result<float> {
  auto r = double_(in);
  if (!r) return unexp(r.error());
  return done{float(r->value), r->rest};
};

// ---------------------------------------------------------------------------
// 14. bit-level parsing (nom::bits) — with MSB0 *and* LSB0 orders, mixable
// ---------------------------------------------------------------------------

/// Bit numbering within a byte:
///   msb0 — network style, first field occupies the highest bits (nom's only
///          mode; right for IPv4/TCP/VLAN headers)
///   lsb0 — first field occupies the lowest bits (right for many little-endian
///          hardware register layouts, FAT attributes, etc.)
enum class bit_order : std::uint8_t { msb0, lsb0 };

/// Cursor for bit parsers: byte cursor + bit position inside the current byte.
struct bit_input {
  input       in;
  std::size_t bit = 0;  ///< bits already consumed of in.first[0], 0..7
  NANOM_HD constexpr std::size_t bits_left() const { return in.size() * 8 - bit; }
};

template <class T> struct bdone { using type = T; T value; bit_input rest; };
template <class T> bdone(T, bit_input) -> bdone<T>;
template <class T> using bresult = expected<bdone<T>, error>;

namespace detail {
template <class R> struct is_bresult : std::false_type {};
template <class T> struct is_bresult<bresult<T>> : std::true_type {};
}
/// A bit parser: (bit_input) -> bresult<T>.
template <class P>
concept BitParser = std::invocable<const P&, bit_input> &&
                    detail::is_bresult<std::invoke_result_t<const P&, bit_input>>::value;
template <BitParser P>
using bit_parsed_t = typename std::invoke_result_t<const P&, bit_input>::value_type::type;

namespace detail {
/// Consume n bits (n <= 64) in the given order; returns them as the low bits
/// of a std::uint64_t.
NANOM_HD constexpr bresult<std::uint64_t> read_bits(bit_input bi, std::size_t n, bit_order ord) {
  if (bi.bits_left() < n) return make_incomplete(bi.in, (n - bi.bits_left() + 7) / 8);
  std::uint64_t out = 0;
  input cur = bi.in;
  std::size_t bit = bi.bit;
  for (std::size_t got = 0; got < n;) {
    const std::uint8_t byte = cur[0];
    const std::size_t avail = 8 - bit;
    const std::size_t use   = std::min(avail, n - got);
    std::uint64_t piece;
    if (ord == bit_order::msb0) {
      // take `use` bits starting at position (7 - bit) downward
      piece = (byte >> (avail - use)) & ((std::uint64_t(1) << use) - 1);
      out = (out << use) | piece;
    } else {
      // take `use` bits starting at position `bit` upward
      piece = (byte >> bit) & ((std::uint64_t(1) << use) - 1);
      out |= piece << got;
    }
    got += use;
    bit += use;
    if (bit == 8) { bit = 0; cur = cur.advance(1); }
  }
  return bdone{out, bit_input{cur, bit}};
}
}  // namespace detail

/// take_bits<T>(n [, order]) — n bits as a T. Inside bits(...) scope.
template <class T = std::uint64_t>
constexpr auto take_bits(std::size_t n, bit_order ord = bit_order::msb0) {
  return [n, ord](bit_input bi) -> bresult<T> {
    auto r = detail::read_bits(bi, n, ord);
    if (!r) return unexp(r.error());
    return bdone{T(r->value), r->rest};
  };
}
/// tag_bits(pattern, n) — n bits that must equal pattern (nom bits::tag).
constexpr auto tag_bits(std::uint64_t pattern, std::size_t n,
                        bit_order ord = bit_order::msb0) {
  return [pattern, n, ord](bit_input bi) -> bresult<std::uint64_t> {
    auto r = detail::read_bits(bi, n, ord);
    if (!r) return unexp(r.error());
    if (r->value != pattern) return make_err(bi.in, "bit tag");
    return r;
  };
}
/// bool_bit — one bit as bool.
constexpr auto bool_bit(bit_order ord = bit_order::msb0) {
  return [ord](bit_input bi) -> bresult<bool> {
    auto r = detail::read_bits(bi, 1, ord);
    if (!r) return unexp(r.error());
    return bdone{r->value != 0, r->rest};
  };
}

/// bseq(b1, b2, …) — sequence of bit parsers, tuple of values.
namespace detail {
template <class Tup, BitParser P, BitParser... Ps>
constexpr auto bseq_step(Tup&& acc, bit_input bi, const P& p, const Ps&... ps)
    -> bresult<decltype(std::tuple_cat(std::move(acc), std::declval<std::tuple<bit_parsed_t<P>, bit_parsed_t<Ps>...>>()))> {
  auto r = p(bi);
  if (!r) return unexp(r.error());
  auto acc2 = std::tuple_cat(std::move(acc), std::make_tuple(std::move(r->value)));
  if constexpr (sizeof...(Ps) == 0)
    return bdone{std::move(acc2), r->rest};
  else
    return bseq_step(std::move(acc2), r->rest, ps...);
}
}  // namespace detail
template <BitParser... Ps>
  requires(sizeof...(Ps) >= 1)
constexpr auto bseq(Ps... ps) {
  return [ps...](bit_input bi) { return detail::bseq_step(std::tuple<>{}, bi, ps...); };
}

/// bits(bp) — enter bit mode: run a bit parser over the byte stream, then
/// round up to the next byte boundary (nom::bits::bits).
template <BitParser P>
constexpr auto bits(P bp) {
  return [bp](input in) -> result<bit_parsed_t<P>> {
    auto r = bp(bit_input{in, 0});
    if (!r) return unexp(r.error());
    input rest = r->rest.in;
    if (r->rest.bit != 0) rest = rest.advance(1);  // round up, partial byte dropped
    return done{std::move(r->value), rest};
  };
}
/// bytes_(p) — inside a bit parser, drop back to byte mode for p
/// (nom::bits::bytes). Requires the cursor to be byte-aligned.
template <Parser P>
constexpr auto bytes_(P p) {
  return [p](bit_input bi) -> bresult<parsed_t<P>> {
    if (bi.bit != 0) return make_err(bi.in, "bytes(): bit cursor must be byte-aligned");
    auto r = p(bi.in);
    if (!r) return unexp(r.error());
    return bdone{std::move(r->value), bit_input{r->rest, 0}};
  };
}

// ---------------------------------------------------------------------------
// 15. fixed_string — string literals as template parameters (get<"name">())
// ---------------------------------------------------------------------------

template <std::size_t N>
struct fixed_string {
  char data[N]{};
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
}  // namespace detail

// --- preprocessor map machinery (bounded, 32 fields max) -------------------
#define NANOM_PP_NARG(...) NANOM_PP_NARG_(__VA_ARGS__, NANOM_PP_RSEQ())
#define NANOM_PP_NARG_(...) NANOM_PP_ARG_N(__VA_ARGS__)
#define NANOM_PP_ARG_N(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,_21,_22,_23,_24,_25,_26,_27,_28,_29,_30,_31,_32,N,...) N
#define NANOM_PP_RSEQ() 32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1
#define NANOM_PP_CAT(a, b) NANOM_PP_CAT_(a, b)
#define NANOM_PP_CAT_(a, b) a##b
#define NANOM_FLD(T, m) ::nanom::detail::fld<#m, &T::m>{}
#define NANOM_PP_M1(M,T,a) M(T,a)
#define NANOM_PP_M2(M,T,a,...) M(T,a), NANOM_PP_M1(M,T,__VA_ARGS__)
#define NANOM_PP_M3(M,T,a,...) M(T,a), NANOM_PP_M2(M,T,__VA_ARGS__)
#define NANOM_PP_M4(M,T,a,...) M(T,a), NANOM_PP_M3(M,T,__VA_ARGS__)
#define NANOM_PP_M5(M,T,a,...) M(T,a), NANOM_PP_M4(M,T,__VA_ARGS__)
#define NANOM_PP_M6(M,T,a,...) M(T,a), NANOM_PP_M5(M,T,__VA_ARGS__)
#define NANOM_PP_M7(M,T,a,...) M(T,a), NANOM_PP_M6(M,T,__VA_ARGS__)
#define NANOM_PP_M8(M,T,a,...) M(T,a), NANOM_PP_M7(M,T,__VA_ARGS__)
#define NANOM_PP_M9(M,T,a,...) M(T,a), NANOM_PP_M8(M,T,__VA_ARGS__)
#define NANOM_PP_M10(M,T,a,...) M(T,a), NANOM_PP_M9(M,T,__VA_ARGS__)
#define NANOM_PP_M11(M,T,a,...) M(T,a), NANOM_PP_M10(M,T,__VA_ARGS__)
#define NANOM_PP_M12(M,T,a,...) M(T,a), NANOM_PP_M11(M,T,__VA_ARGS__)
#define NANOM_PP_M13(M,T,a,...) M(T,a), NANOM_PP_M12(M,T,__VA_ARGS__)
#define NANOM_PP_M14(M,T,a,...) M(T,a), NANOM_PP_M13(M,T,__VA_ARGS__)
#define NANOM_PP_M15(M,T,a,...) M(T,a), NANOM_PP_M14(M,T,__VA_ARGS__)
#define NANOM_PP_M16(M,T,a,...) M(T,a), NANOM_PP_M15(M,T,__VA_ARGS__)
#define NANOM_PP_M17(M,T,a,...) M(T,a), NANOM_PP_M16(M,T,__VA_ARGS__)
#define NANOM_PP_M18(M,T,a,...) M(T,a), NANOM_PP_M17(M,T,__VA_ARGS__)
#define NANOM_PP_M19(M,T,a,...) M(T,a), NANOM_PP_M18(M,T,__VA_ARGS__)
#define NANOM_PP_M20(M,T,a,...) M(T,a), NANOM_PP_M19(M,T,__VA_ARGS__)
#define NANOM_PP_M21(M,T,a,...) M(T,a), NANOM_PP_M20(M,T,__VA_ARGS__)
#define NANOM_PP_M22(M,T,a,...) M(T,a), NANOM_PP_M21(M,T,__VA_ARGS__)
#define NANOM_PP_M23(M,T,a,...) M(T,a), NANOM_PP_M22(M,T,__VA_ARGS__)
#define NANOM_PP_M24(M,T,a,...) M(T,a), NANOM_PP_M23(M,T,__VA_ARGS__)
#define NANOM_PP_M25(M,T,a,...) M(T,a), NANOM_PP_M24(M,T,__VA_ARGS__)
#define NANOM_PP_M26(M,T,a,...) M(T,a), NANOM_PP_M25(M,T,__VA_ARGS__)
#define NANOM_PP_M27(M,T,a,...) M(T,a), NANOM_PP_M26(M,T,__VA_ARGS__)
#define NANOM_PP_M28(M,T,a,...) M(T,a), NANOM_PP_M27(M,T,__VA_ARGS__)
#define NANOM_PP_M29(M,T,a,...) M(T,a), NANOM_PP_M28(M,T,__VA_ARGS__)
#define NANOM_PP_M30(M,T,a,...) M(T,a), NANOM_PP_M29(M,T,__VA_ARGS__)
#define NANOM_PP_M31(M,T,a,...) M(T,a), NANOM_PP_M30(M,T,__VA_ARGS__)
#define NANOM_PP_M32(M,T,a,...) M(T,a), NANOM_PP_M31(M,T,__VA_ARGS__)
#define NANOM_PP_MAP(M, T, ...) \
  NANOM_PP_CAT(NANOM_PP_M, NANOM_PP_NARG(__VA_ARGS__))(M, T, __VA_ARGS__)

/// NANOM_DESCRIBE(type, field1, field2, …) — register a struct with nanom.
/// Must appear at GLOBAL scope (it specializes nanom::describe). List fields
/// in wire order.
#define NANOM_DESCRIBE(T, ...)                                              \
  template <>                                                               \
  struct nanom::describe<T> {                                               \
    static constexpr const char* name() { return #T; }                      \
    static constexpr auto fields() {                                        \
      return std::make_tuple(NANOM_PP_MAP(NANOM_FLD, T, __VA_ARGS__));      \
    }                                                                       \
  }

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
    std::apply([&](auto... f) {
      ((total += wire<member_t<decltype(f)::mem_ptr>>::bits), ...);
    }, describe<T>::fields());
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
  std::apply([&](auto... f) {
    ((off[i++] = cur, cur += wire<member_t<decltype(f)::mem_ptr>>::bits), ...);
  }, describe<T>::fields());
  return off;
}

/// Layout validity: every non-bit field byte-aligned, total a whole number of
/// bytes. Evaluated at compile time; strct/overlay static_assert on it.
template <Described T>
constexpr bool layout_ok() {
  constexpr auto off = field_bit_offsets<T>();
  bool ok = wire<T>::bits % 8 == 0;
  std::size_t i = 0;
  std::apply([&](auto... f) {
    ((ok = ok && (wire<member_t<decltype(f)::mem_ptr>>::is_bits || off[i] % 8 == 0), ++i), ...);
  }, describe<T>::fields());
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
    std::apply([&](auto... f) {
      ((out.*(decltype(f)::mem_ptr) =
            assign_field<member_t<decltype(f)::mem_ptr>>(p, bitoff + offs[i++], dflt)), ...);
    }, describe<F>::fields());
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
    std::apply([&](auto... f) {
      ((out.*(decltype(f)::mem_ptr) =
            assign_field<member_t<decltype(f)::mem_ptr>>(p, bitoff + offs[i++], dflt)), ...);
    }, describe<F>::fields());
    return out;
  }
}

template <Described T, fixed_string Name>
NANOM_HD constexpr std::size_t field_index() {
  std::size_t idx = std::size_t(-1), i = 0;
  std::apply([&](auto... f) {
    ((decltype(f)::name == Name.sv() ? idx = i : i, ++i), ...);
  }, describe<T>::fields());
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
    std::apply([&](auto... f) {
      ((out.*(decltype(f)::mem_ptr) =
            detail::assign_field<detail::member_t<decltype(f)::mem_ptr>>(
                in.first, offs[i++], dflt)), ...);
    }, describe<T>::fields());
    return done{std::move(out), in.advance(need)};
  };
}

// ---------------------------------------------------------------------------
// 20. view<T> / overlay<T>() — zero-copy lazy access: get<"field">()
// ---------------------------------------------------------------------------

/// A zero-copy overlay of T's wire format over the original buffer. Fields
/// decode on access (endian conversion / bit extraction), nothing is stored.
template <Described T>
struct view {
  const std::byte* p    = nullptr;
  std::endian      dflt = std::endian::native;  ///< order for plain scalars

  /// Decoded value of the named field. Unknown names are a compile error.
  template <fixed_string Name>
  NANOM_HD constexpr auto get() const {
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
  NANOM_HD constexpr bytes raw() const { return {p, wire_size_v<T>}; }
  /// Materialize a full T (same as strct would produce).
  NANOM_HD constexpr T to_struct() const {
    T out{};
    constexpr auto offs = detail::field_bit_offsets<T>();
    std::size_t i = 0;
    std::apply([&](auto... f) {
      ((out.*(decltype(f)::mem_ptr) =
            detail::assign_field<detail::member_t<decltype(f)::mem_ptr>>(p, offs[i++], dflt)), ...);
    }, describe<T>::fields());
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

// ---------------------------------------------------------------------------
// 21. schema — walkable description of a struct, for Arrow / Avro / debug
// ---------------------------------------------------------------------------

enum class dkind : std::uint8_t {
  u8, u16, u32, u64, i8, i16, i32, i64, f32, f64,
  fixed_bin,   ///< fixed-size byte array
  list,        ///< fixed-size list of a scalar element
  record       ///< nested described struct
};

struct schema_node;

struct schema_field {
  std::string_view   name;
  dkind              kind;
  std::uint32_t      bits   = 0;        ///< original wire width in bits
  std::uint32_t      size   = 0;        ///< fixed_bin bytes / list length
  dkind              elem   = dkind::u8;///< list element kind
  const schema_node* nested = nullptr;  ///< record only
};

struct schema_node {
  std::string_view              name;
  std::span<const schema_field> fields;
};

namespace detail {

template <class D>
constexpr dkind scalar_kind() {
  if constexpr (std::is_same_v<D, float>)  return dkind::f32;
  else if constexpr (std::is_same_v<D, double>) return dkind::f64;
  else if constexpr (std::is_signed_v<D>) {
    if constexpr (sizeof(D) == 1) return dkind::i8;
    else if constexpr (sizeof(D) == 2) return dkind::i16;
    else if constexpr (sizeof(D) == 4) return dkind::i32;
    else return dkind::i64;
  } else {
    if constexpr (sizeof(D) == 1) return dkind::u8;
    else if constexpr (sizeof(D) == 2) return dkind::u16;
    else if constexpr (sizeof(D) == 4) return dkind::u32;
    else return dkind::u64;
  }
}

template <Described T> struct schema_holder;

template <class F>
constexpr schema_field field_schema(std::string_view name) {
  schema_field s{};
  s.name = name;
  s.bits = std::uint32_t(wire<F>::bits);
  if constexpr (Described<F>) {
    s.kind = dkind::record;
    s.nested = &schema_holder<F>::node;
  } else if constexpr (is_std_array_v<F>) {
    using E = typename F::value_type;
    using ED = typename wire<E>::decoded;
    s.size = std::uint32_t(std::tuple_size_v<F>);
    if constexpr (sizeof(ED) == 1 && std::is_integral_v<ED>) {
      s.kind = dkind::fixed_bin;             // byte arrays -> fixed binary
    } else {
      s.kind = dkind::list;
      s.elem = scalar_kind<ED>();
    }
  } else {
    s.kind = scalar_kind<typename wire<F>::decoded>();
  }
  return s;
}

template <Described T>
constexpr auto make_schema_fields() {
  std::array<schema_field, field_count_v<T>> out{};
  std::size_t i = 0;
  std::apply([&](auto... f) {
    ((out[i++] = field_schema<member_t<decltype(f)::mem_ptr>>(decltype(f)::name.sv())), ...);
  }, describe<T>::fields());
  return out;
}

template <Described T>
struct schema_holder {
  static constexpr auto fields = make_schema_fields<T>();
  static constexpr schema_node node{describe<T>::name(), fields};
};

}  // namespace detail

/// The schema of a registered struct — a compile-time constant tree.
template <Described T>
constexpr const schema_node& schema_of() { return detail::schema_holder<T>::node; }

// ---------------------------------------------------------------------------
// 22. schema emission — Arrow C data interface, Avro JSON, JSON/CSV debug
// ---------------------------------------------------------------------------

/// Arrow C Data Interface format string for one field ("S"=u16, "w:6"=fixed
/// binary…) — hand these to nanoarrow's ArrowSchemaSetFormat; Lance consumes
/// Arrow schemas directly.
inline std::string arrow_format(const schema_field& f) {
  auto scalar = [](dkind k) -> const char* {
    switch (k) {
      case dkind::u8:  return "C";  case dkind::u16: return "S";
      case dkind::u32: return "I";  case dkind::u64: return "L";
      case dkind::i8:  return "c";  case dkind::i16: return "s";
      case dkind::i32: return "i";  case dkind::i64: return "l";
      case dkind::f32: return "f";  case dkind::f64: return "g";
      default:         return "z";
    }
  };
  switch (f.kind) {
    case dkind::fixed_bin: return "w:" + std::to_string(f.size);
    case dkind::list:      return "+w:" + std::to_string(f.size);  // child: scalar(f.elem)
    case dkind::record:    return "+s";
    default:               return scalar(f.kind);
  }
}

namespace detail {
inline void avro_field_json(const schema_field& f, std::string& out);
inline void avro_record_json(const schema_node& n, std::string& out) {
  out += R"({"type":"record","name":")";
  out += n.name;
  out += R"(","fields":[)";
  bool first = true;
  for (const auto& f : n.fields) {
    if (!first) out += ',';
    first = false;
    out += R"({"name":")";
    out += f.name;
    out += R"(","type":)";
    avro_field_json(f, out);
    out += '}';
  }
  out += "]}";
}
inline void avro_field_json(const schema_field& f, std::string& out) {
  auto scalar = [](dkind k) -> const char* {
    switch (k) {
      case dkind::u8: case dkind::u16: case dkind::i8: case dkind::i16:
      case dkind::i32: return R"("int")";
      // u32 widens to long; u64 is emitted as long (Avro has no unsigned —
      // values above 2^63 wrap; use fixed_bin if that matters)
      case dkind::u32: case dkind::u64: case dkind::i64: return R"("long")";
      case dkind::f32: return R"("float")";
      case dkind::f64: return R"("double")";
      default: return R"("bytes")";
    }
  };
  switch (f.kind) {
    case dkind::fixed_bin:
      out += R"({"type":"fixed","name":")";
      out += f.name;
      out += R"(_fx","size":)" + std::to_string(f.size) + "}";
      break;
    case dkind::list:
      out += R"({"type":"array","items":)";
      out += scalar(f.elem);
      out += '}';
      break;
    case dkind::record: avro_record_json(*f.nested, out); break;
    default: out += scalar(f.kind);
  }
}
}  // namespace detail

/// Avro schema (JSON) for a registered struct.
template <Described T>
std::string avro_schema() {
  std::string out;
  detail::avro_record_json(schema_of<T>(), out);
  return out;
}

// --- JSON / CSV debug dumps -------------------------------------------------

namespace detail {

template <class F>
void json_value(const F& v, std::string& out) {
  if constexpr (Described<F>) {
    out += '{';
    bool first = true;
    std::apply([&](auto... f) {
      ((out += first ? "" : ",", first = false,
        out += '"', out += decltype(f)::name.sv(), out += "\":",
        json_value(v.*(decltype(f)::mem_ptr), out)), ...);
    }, describe<F>::fields());
    out += '}';
  } else if constexpr (is_std_array_v<F>) {
    using E = typename F::value_type;
    using ED = typename wire<E>::decoded;
    if constexpr (sizeof(ED) == 1 && std::is_integral_v<ED>) {
      static constexpr char hexd[] = "0123456789abcdef";  // bytes -> hex string
      out += '"';
      for (auto e : v) {
        auto b = std::uint8_t(typename wire<E>::decoded(e));
        out += hexd[b >> 4]; out += hexd[b & 15];
      }
      out += '"';
    } else {
      out += '[';
      bool first = true;
      for (const auto& e : v) {
        if (!first) out += ',';
        first = false;
        json_value(e, out);
      }
      out += ']';
    }
  } else if constexpr (std::floating_point<F>) {
    char buf[32];
    auto [p, ec] = std::to_chars(buf, buf + sizeof buf, double(v));
    out.append(buf, p);
  } else {  // integral / be / le / ubits / ibits — all convert to a number
    using D = typename wire<F>::decoded;
    D d = D(v);
    if constexpr (std::floating_point<D>) {
      char buf[32];
      auto [pe, ec] = std::to_chars(buf, buf + sizeof buf, double(d));
      (void)ec;
      out.append(buf, pe);
    } else if constexpr (std::is_signed_v<D>) {
      out += std::to_string(std::int64_t(d));
    } else {
      out += std::to_string(std::uint64_t(d));
    }
  }
}

template <class F>
void csv_names(std::string prefix, std::string_view name, std::string& out, bool& first) {
  if constexpr (Described<F>) {
    std::string p2 = prefix + std::string(name) + ".";
    std::apply([&](auto... f) {
      ((csv_names<member_t<decltype(f)::mem_ptr>>(p2, decltype(f)::name.sv(), out, first)), ...);
    }, describe<F>::fields());
  } else {
    if (!first) out += ',';
    first = false;
    out += prefix;
    out += name;
  }
}

template <class F>
void csv_value(const F& v, std::string& out, bool& first) {
  if constexpr (Described<F>) {
    std::apply([&](auto... f) {
      ((csv_value(v.*(decltype(f)::mem_ptr), out, first)), ...);
    }, describe<F>::fields());
  } else {
    if (!first) out += ',';
    first = false;
    json_value(v, out);  // scalar/array rendering is CSV-safe (no commas)
  }
}

}  // namespace detail

/// One-line JSON object for a parsed struct (debug).
template <Described T>
std::string to_json(const T& v) {
  std::string out;
  detail::json_value(v, out);
  return out;
}
/// CSV header ("dst,src,eth_type" — nested fields dotted) and one data row.
template <Described T>
std::string csv_header() {
  std::string out;
  bool first = true;
  std::apply([&](auto... f) {
    ((detail::csv_names<detail::member_t<decltype(f)::mem_ptr>>(
         "", decltype(f)::name.sv(), out, first)), ...);
  }, describe<T>::fields());
  return out;
}
template <Described T>
std::string csv_row(const T& v) {
  std::string out;
  bool first = true;
  std::apply([&](auto... f) {
    ((detail::csv_value(v.*(decltype(f)::mem_ptr), out, first)), ...);
  }, describe<T>::fields());
  return out;
}

// ---------------------------------------------------------------------------
// 23. soa<T> — columnar chunked storage (SoA) for nanoarrow / nanolance
// ---------------------------------------------------------------------------

/// Column-oriented accumulator: push() decomposes each struct into flat,
/// host-order leaf columns; full chunks are sealed at chunk_rows so buffers
/// can be handed to ArrowArray / Lance fragment writers without a transpose.
/// Nested described structs are flattened with dotted names; byte arrays
/// become fixed-size binary columns; bit fields widen to their decoded type.
template <Described T>
class soa {
 public:
  struct column_info {
    std::string  name;        ///< flattened, dotted
    dkind        kind;        ///< scalar kind, or fixed_bin
    std::size_t  elem_bytes;  ///< bytes per row in this column
    std::string  arrow;       ///< Arrow C data interface format string
  };
  struct chunk {
    std::size_t                         rows = 0;
    std::vector<std::vector<std::byte>> cols;   ///< one contiguous buffer per column
    bytes col(std::size_t i) const { return {cols[i].data(), cols[i].size()}; }
    /// Typed access; V must match the column's decoded type.
    template <class V>
    std::span<const V> as(std::size_t i) const {
      return {reinterpret_cast<const V*>(cols[i].data()), rows};
    }
  };

  explicit soa(std::size_t chunk_rows = 65536) : chunk_rows_(chunk_rows) {
    build_columns<T>("");
    open_.cols.resize(columns_.size());
  }

  const std::vector<column_info>& columns() const { return columns_; }
  std::size_t rows() const { return sealed_rows_ + open_.rows; }

  void push(const T& v) {
    std::size_t c = 0;
    push_fields(v, c);
    if (++open_.rows == chunk_rows_) seal();
  }

  /// Visit every chunk (sealed ones, then the open remainder if non-empty).
  template <class F>
  void for_each_chunk(F&& f) const {
    for (const auto& ch : sealed_) f(ch);
    if (open_.rows) f(open_);
  }
  /// Force-seal the open chunk (e.g. before a final flush).
  void seal() {
    if (!open_.rows) return;
    sealed_rows_ += open_.rows;
    sealed_.push_back(std::move(open_));
    open_ = {};
    open_.cols.resize(columns_.size());
  }

 private:
  template <class F>
  void build_columns(std::string prefix, std::string_view name = "") {
    if constexpr (Described<F>) {
      build_nested<F>(name.empty() ? prefix : prefix + std::string(name) + ".");
    } else {
      schema_field s = detail::field_schema<F>(name);
      column_info ci;
      ci.name = prefix + std::string(name);
      if (s.kind == dkind::fixed_bin || s.kind == dkind::list) {
        // store fixed lists as flat fixed-size binary (elem×len bytes per row)
        ci.kind = dkind::fixed_bin;
        ci.elem_bytes = detail::wire<F>::bits / 8;
        schema_field bin = s;
        bin.kind = dkind::fixed_bin;
        bin.size = std::uint32_t(ci.elem_bytes);
        ci.arrow = arrow_format(bin);
      } else {
        ci.kind = s.kind;
        ci.elem_bytes = sizeof(typename detail::wire<F>::decoded);
        ci.arrow = arrow_format(s);
      }
      columns_.push_back(std::move(ci));
    }
  }
  template <class F>
  void build_nested(std::string prefix) {
    std::apply([&](auto... f) {
      ((build_columns<detail::member_t<decltype(f)::mem_ptr>>(prefix, decltype(f)::name.sv())), ...);
    }, describe<F>::fields());
  }

  template <class F>
  void push_one(const F& v, std::size_t& c) {
    if constexpr (Described<F>) {
      push_fields(v, c);
    } else if constexpr (detail::is_std_array_v<F>) {
      auto& col = open_.cols[c++];
      for (const auto& e : v) {
        using ED = typename detail::wire<typename F::value_type>::decoded;
        ED d = ED(e);
        const auto* b = reinterpret_cast<const std::byte*>(&d);
        col.insert(col.end(), b, b + sizeof(ED));
      }
    } else {
      using D = typename detail::wire<F>::decoded;
      D d = D(v);
      auto& col = open_.cols[c++];
      const auto* b = reinterpret_cast<const std::byte*>(&d);
      col.insert(col.end(), b, b + sizeof(D));
    }
  }
  template <class F>
  void push_fields(const F& v, std::size_t& c) {
    std::apply([&](auto... f) {
      ((push_one(v.*(decltype(f)::mem_ptr), c)), ...);
    }, describe<F>::fields());
  }

  std::size_t              chunk_rows_;
  std::vector<column_info> columns_;
  std::vector<chunk>       sealed_;
  chunk                    open_;
  std::size_t              sealed_rows_ = 0;
};

// ---------------------------------------------------------------------------
// sanity pledges (see DESIGN.md §6)
// ---------------------------------------------------------------------------
static_assert(sizeof(error) <= 96, "error must stay POD-small (it taxes the result<T> value path)");
static_assert(std::is_trivially_copyable_v<error>);
static_assert(std::is_trivially_copyable_v<input>);

}  // namespace nanom

#endif  // NANOM_HPP_INCLUDED
