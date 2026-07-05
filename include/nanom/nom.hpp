// SPDX-License-Identifier: Apache-2.0
// nanom/nom.hpp — the pure rust-nom parallel: everything a nom user knows, under the same name.
// input/error/result/Parser, the combinator vocabulary (bytes, character, sequence, branch, multi,
// modifiers), binary numbers (be_/le_/ne_), text numbers (dec/hex/float), and bit-level parsing.
// This layer has NO struct reflection, schema, or columnar storage — those sit on top in
// reflect.hpp / schema.hpp / soa.hpp. Include just this header for the parser-only subset.
#ifndef NANOM_NOM_HPP_INCLUDED
#define NANOM_NOM_HPP_INCLUDED

#include "prelude.hpp"

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
/// Upper bound on error::needed in streaming incomplete errors — avoids OOM when
/// callers pre-allocate from a hostile length prefix. 0 still means unknown.
inline constexpr std::uint32_t max_incomplete_needed = 64 * 1024;

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
    const std::size_t total = whole.base ? std::size_t(whole.last - whole.base) : 0;
    const std::size_t off = std::min<std::size_t>(offset, total);  // clamp bogus offsets
    if (offset > total)
      out += " (offset beyond input, hex window clamped)";
    if (total > 0) {
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
  e.expected = "more input";
  e.needed = std::uint32_t(std::min(needed, std::size_t(max_incomplete_needed)));
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

namespace detail {
inline constexpr std::size_t tag_sbo_cap = 15;
constexpr char lower(char c) { return (c >= 'A' && c <= 'Z') ? char(c + 32) : c; }

/// Owns a tag pattern by value (SBO ≤15 B, else heap string) so parsers outlive
/// ephemeral std::string sources.
struct owned_pattern {
  std::array<char, 16> small{};
  std::string          large;
  std::size_t          len = 0;

  explicit owned_pattern(std::string_view p) : len(p.size()) {
    if (len <= tag_sbo_cap) {
      for (std::size_t i = 0; i < len; ++i) small[static_cast<std::size_t>(i)] = p[i];
    } else {
      large.assign(p);
    }
  }

  const char* data() const noexcept {
    return len <= tag_sbo_cap ? small.data() : large.data();
  }
};

inline auto make_tag_parser(owned_pattern pat) {
  return [pat = std::move(pat)](input in) -> result<bytes> {
    const std::size_t n = pat.len;
    if (in.size() < n) return make_incomplete(in, n - in.size());
    if (std::memcmp(in.first, pat.data(), n) != 0) return make_err(in, "tag");
    return done{in.take_span(n), in.advance(n)};
  };
}

inline auto make_tag_no_case_parser(owned_pattern pat) {
  return [pat = std::move(pat)](input in) -> result<bytes> {
    const std::size_t n = pat.len;
    if (in.size() < n) return make_incomplete(in, n - in.size());
    for (std::size_t i = 0; i < n; ++i)
      if (lower(char(in[i])) != lower(pat.data()[i])) return make_err(in, "tag_no_case");
    return done{in.take_span(n), in.advance(n)};
  };
}
}  // namespace detail

/// tag("GET") / tag(bytes) — match an exact byte sequence, yield it zero-copy.
/// Stores the pattern by value (small-buffer optimized up to 15 bytes).
inline auto tag(std::string_view pattern) {
  return detail::make_tag_parser(detail::owned_pattern(pattern));
}
constexpr auto tag(bytes pattern) {
  return [pattern](input in) -> result<bytes> {
    if (in.size() < pattern.size()) return make_incomplete(in, pattern.size() - in.size());
    if (std::memcmp(in.first, pattern.data(), pattern.size()) != 0)
      return make_err(in, "tag");
    return done{in.take_span(pattern.size()), in.advance(pattern.size())};
  };
}

/// tag_no_case("http") — ASCII case-insensitive tag.
inline auto tag_no_case(std::string_view pattern) {
  return detail::make_tag_no_case_parser(detail::owned_pattern(pattern));
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
namespace detail {
// std::from_chars for *floating point* is, in practice, optional: libc++ (through LLVM 18) ships the
// integer overloads but not the floating-point ones, so `std::from_chars(b, e, double&)` there
// resolves to the deleted bool overload and fails to compile. Detect that and fall back to a
// portable parser. Where the library does provide it (libstdc++, MSVC STL) we keep calling
// std::from_chars unchanged, so its correctly-rounded conversion is preserved.
template <class T>
concept has_fp_from_chars = requires(const char* p, T& v) { std::from_chars(p, p, v); };

// 10^0 .. 10^22 are each exactly representable as double.
inline constexpr double pow10_exact[] = {
    1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,  1e7,  1e8,  1e9,  1e10, 1e11,
    1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22};

// m * 10^e. On the classic fast path (|e| <= 22 and m exact as a double, i.e. <= 15 significant
// digits) this is a single correctly-rounded multiply/divide; with more digits or larger magnitudes
// it scales in 10^22 chunks and can differ from a correctly-rounded conversion by a few ulp (e.g. at
// full-precision DBL_MAX). Only the fallback stdlib (libc++) takes this path; libstdc++/MSVC keep
// std::from_chars. A full Eisel-Lemire/big-integer path is deliberately not carried here.
constexpr double scale10(double m, int e) {
  if (m == 0.0) return 0.0;
  if (e >= 0) {
    while (e > 22) { m *= 1e22; e -= 22; }
    return m * pow10_exact[e];
  }
  int k = -e;
  while (k > 22) { m /= 1e22; k -= 22; }
  return m / pow10_exact[k];
}

// Portable std::from_chars(double) for stdlibs lacking it. Matches from_chars' general-format
// grammar: optional leading '-', at least one decimal digit, optional '.', optional [eE][+-]?digits;
// no leading '+' or whitespace. ptr points one past the last consumed character; result_out_of_range
// on overflow/underflow to inf/0.
constexpr std::from_chars_result from_chars_double(const char* first, const char* last, double& out) {
  const char* p = first;
  bool neg = false;
  if (p != last && *p == '-') { neg = true; ++p; }

  std::uint64_t mant = 0;  // significand; digits capped so it can never overflow
  int  digits = 0;
  int  exp10  = 0;
  bool any    = false;
  auto eat = [&](bool fractional) {
    for (; p != last && *p >= '0' && *p <= '9'; ++p) {
      any = true;
      if (digits < 18) { mant = mant * 10 + std::uint64_t(*p - '0'); ++digits; if (fractional) --exp10; }
      else if (!fractional) ++exp10;  // extra integer digits scale up; extra fraction digits drop
    }
  };
  eat(false);
  if (p != last && *p == '.') { ++p; eat(true); }
  if (!any) return {first, std::errc::invalid_argument};  // from_chars needs at least one digit

  if (p != last && (*p == 'e' || *p == 'E')) {
    const char* ep = p + 1;
    bool eneg = false;
    if (ep != last && (*ep == '+' || *ep == '-')) { eneg = (*ep == '-'); ++ep; }
    if (ep != last && *ep >= '0' && *ep <= '9') {
      int e = 0;
      for (; ep != last && *ep >= '0' && *ep <= '9'; ++ep) e = e < 100000 ? e * 10 + (*ep - '0') : e;
      exp10 += eneg ? -e : e;
      p = ep;
    }
    // else: a bare 'e' with no exponent digits is not part of the number; leave p pointing at it.
  }

  double v = scale10(double(mant), exp10);
  const bool overflow  = (v != 0.0 && v * 2.0 == v);  // v == +inf
  const bool underflow = (v == 0.0 && mant != 0);
  if (overflow || underflow) return {p, std::errc::result_out_of_range};
  out = neg ? -v : v;
  return {p, std::errc{}};
}

// Dispatch to the real from_chars where available (exact), the portable parser otherwise. Two
// constrained overloads (rather than `if constexpr`) so the std::from_chars call lives in a
// template body that is *only instantiated* when the overload is chosen — in a non-template
// function even a discarded `if constexpr` branch is still type-checked, which re-triggers the
// libc++ deleted-overload error. Fp is deduced as double; it only makes the from_chars call
// dependent so it isn't checked at definition on stdlibs that lack it.
template <class Fp>
  requires has_fp_from_chars<Fp>
std::from_chars_result parse_double(const char* first, const char* last, Fp& out) {
  return std::from_chars(first, last, out);
}
template <class Fp>
  requires (!has_fp_from_chars<Fp>)
std::from_chars_result parse_double(const char* first, const char* last, Fp& out) {
  return from_chars_double(first, last, out);
}
}  // namespace detail

/// float_ / double_ — text floating point ("3.14", "-1e9"). (nom: float/double)
inline constexpr auto double_ = [](input in) -> result<double> {
  const char* b = reinterpret_cast<const char*>(in.first);
  const char* e = reinterpret_cast<const char*>(in.last);
  double v{};
  // std::from_chars(double) where the stdlib provides it (correct rounding), else a portable
  // general-format fallback — libc++ through LLVM 18 ships no floating-point from_chars.
  auto [p, ec] = detail::parse_double(b, e, v);
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
// sanity pledges (see DESIGN.md §6)
// ---------------------------------------------------------------------------
static_assert(sizeof(error) <= 96, "error must stay POD-small (it taxes the result<T> value path)");
static_assert(std::is_trivially_copyable_v<error>);
static_assert(std::is_trivially_copyable_v<input>);

}  // namespace nanom

#endif  // NANOM_NOM_HPP_INCLUDED
