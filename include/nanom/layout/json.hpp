// SPDX-License-Identifier: Apache-2.0
// nanom/layout/json.hpp — a small JSON reader built from nanom's own combinators.
//
// The layout description (JSON Lines) and the enum file are JSON written by other tools, so they are
// UNTRUSTED text: this reader bounds nesting depth, rejects control characters and bad escapes, and
// remembers the byte offset of every value so callers can say "line 12, column 40: bit_width must
// be 1..64" instead of "bad input". It is a DOM reader (the documents are small: a few MB at most);
// the binary hot path never touches it.
//
// It doubles as a showcase: strings, numbers, literals, arrays and objects are nom-style parsers
// composed with chr/alt/delimited/separated_list0/fold_many0/recognize/cut — the same vocabulary a
// Rust nom user would reach for.
#ifndef NANOM_LAYOUT_JSON_HPP_INCLUDED
#define NANOM_LAYOUT_JSON_HPP_INCLUDED

#include "../nom.hpp"

namespace nanom::layout {

struct json_member;

/// One JSON value. `offset` is the byte offset of the value's first character in the parsed text.
struct json {
  enum class type : std::uint8_t { null, boolean, integer, real, string, array, object };
  type t = type::null;
  bool b = false;
  std::int64_t i = 0;  ///< type::integer (exact; integers outside int64 become type::real)
  double d = 0;        ///< type::real, and the value of type::integer as a double
  std::string s;       ///< type::string (UTF-8, escapes resolved)
  std::vector<json> items;            ///< type::array
  std::vector<json_member> members;   ///< type::object, in document order
  std::size_t offset = 0;

  bool is_object() const { return t == type::object; }
  bool is_string() const { return t == type::string; }
  bool is_int() const { return t == type::integer; }
  /// First member named `key` (objects only), or nullptr.
  inline const json* find(std::string_view key) const;
  inline static const char* type_name(type t);
};

struct json_member {
  std::string key;
  std::size_t key_offset = 0;
  json value;
};

inline const json* json::find(std::string_view key) const {
  for (const auto& m : members)
    if (m.key == key) return &m.value;
  return nullptr;
}
inline const char* json::type_name(type t) {
  switch (t) {
    case type::null: return "null";
    case type::boolean: return "a boolean";
    case type::integer: return "an integer";
    case type::real: return "a number";
    case type::string: return "a string";
    case type::array: return "an array";
    case type::object: return "an object";
  }
  return "?";
}

/// A located parse failure (offset into the parsed text + what was expected there).
struct json_error {
  std::size_t offset = 0;
  std::string what;
};

/// 1-based line and column of a byte offset in `text`.
inline std::pair<std::size_t, std::size_t> line_col(std::string_view text, std::size_t offset) {
  offset = std::min(offset, text.size());
  std::size_t line = 1, col = 1;
  for (std::size_t i = 0; i < offset; ++i) {
    if (text[i] == '\n') { ++line; col = 1; } else ++col;
  }
  return {line, col};
}

namespace json_detail {

inline constexpr unsigned max_depth = 64;

// Every failure names what was expected, in words a person editing the file understands.
template <char C>
inline constexpr char quoted[] = {'\'', C, '\'', '\0'};
/// lit<'{'> — one punctuation character; on mismatch the error says "'{'".
template <char C>
inline constexpr auto lit = [](input in) -> result<char> {
  if (in.empty() || char(in[0]) != C) return make_err(in, quoted<C>);
  return done{C, in.advance(1)};
};
/// tok(p) — p after optional JSON whitespace.
template <class P>
constexpr auto tok(P p) { return preceded(multispace0, p); }

constexpr bool is_hex(std::uint8_t c) {
  return (c >= '0' && c <= '9') || ((c | 32) >= 'a' && (c | 32) <= 'f');
}
constexpr std::uint32_t hex_val(char c) {
  return c <= '9' ? std::uint32_t(c - '0') : std::uint32_t((c | 32) - 'a' + 10);
}

/// A string is a run of plain bytes and escapes; each piece is either text or one code point.
struct piece {
  std::string_view text;
  std::uint32_t cp = 0;
};

inline constexpr auto plain_run = map(
    take_while1([](std::uint8_t c) { return c != '"' && c != '\\' && c >= 0x20; }),
    [](auto b) { return piece{as_str(b), 0}; });

inline constexpr auto hex4 = map(
    take_while_m_n(4, 4, is_hex), [](auto b) {
      std::uint32_t v = 0;
      for (char c : as_str(b)) v = v * 16 + hex_val(c);
      return v;
    });

inline constexpr auto simple_escape = map(one_of("\"\\/bfnrt"), [](char c) -> std::uint32_t {
  switch (c) {
    case 'b': return '\b';
    case 'f': return '\f';
    case 'n': return '\n';
    case 'r': return '\r';
    case 't': return '\t';
    default: return std::uint32_t(c);
  }
});

/// '\' then cut(one of "\"\\/bfnrt" | 'u' XXXX): after a backslash there is no alternative left.
inline constexpr auto escape = map(
    preceded(lit<'\\'>, cut(alt(simple_escape, preceded(lit<'u'>, hex4)))),
    [](std::uint32_t cp) { return piece{{}, cp}; });

inline void put_utf8(std::string& s, std::uint32_t cp) {
  if (cp < 0x80) s += char(cp);
  else if (cp < 0x800) { s += char(0xC0 | (cp >> 6)); s += char(0x80 | (cp & 63)); }
  else if (cp < 0x10000) {
    s += char(0xE0 | (cp >> 12)); s += char(0x80 | ((cp >> 6) & 63)); s += char(0x80 | (cp & 63));
  } else {
    s += char(0xF0 | (cp >> 18)); s += char(0x80 | ((cp >> 12) & 63));
    s += char(0x80 | ((cp >> 6) & 63)); s += char(0x80 | (cp & 63));
  }
}

struct string_acc {
  std::string s;
  std::uint32_t hi = 0;  ///< pending high surrogate
  void flush_hi() { if (hi) { put_utf8(s, 0xFFFD); hi = 0; } }
};

/// '"' (plain_run | escape)* '"' — UTF-16 surrogate pairs from \u escapes are joined; a lone
/// surrogate becomes U+FFFD (lossy but never invalid UTF-8).
inline constexpr auto string_lit = delimited(
    lit<'"'>,
    fold_many0(alt(plain_run, escape), [] { return string_acc{}; },
               [](string_acc& a, piece p) {
                 if (!p.text.empty()) { a.flush_hi(); a.s += p.text; return; }
                 if (p.cp >= 0xD800 && p.cp < 0xDC00) { a.flush_hi(); a.hi = p.cp; return; }
                 if (p.cp >= 0xDC00 && p.cp < 0xE000) {
                   if (a.hi) {
                     put_utf8(a.s, 0x10000 + ((a.hi - 0xD800) << 10) + (p.cp - 0xDC00));
                     a.hi = 0;
                   } else put_utf8(a.s, 0xFFFD);
                   return;
                 }
                 a.flush_hi();
                 put_utf8(a.s, p.cp);
               }),
    cut(lit<'"'>));

inline constexpr auto digits = take_while1([](std::uint8_t c) { return c >= '0' && c <= '9'; });

/// -?digits(.digits)?([eE][+-]?digits)? — recognized as text, then converted exactly.
inline constexpr auto number_text = recognize(seq(
    opt(lit<'-'>), digits, opt(preceded(lit<'.'>, cut(digits))),
    opt(seq(one_of("eE"), opt(one_of("+-")), cut(digits)))));

inline json make_number(std::string_view t) {
  json j;
  const bool integral = t.find_first_of(".eE") == std::string_view::npos;
  if (integral) {
    std::int64_t v = 0;
    auto [p, ec] = std::from_chars(t.data(), t.data() + t.size(), v);
    if (ec == std::errc{} && p == t.data() + t.size()) {
      j.t = json::type::integer; j.i = v; j.d = double(v);
      return j;
    }
  }
  j.t = json::type::real;
  j.d = std::strtod(std::string(t).c_str(), nullptr);  // locale-free enough for [-0-9.eE+]
  return j;
}

inline constexpr auto keyword = [](input in) -> result<json> {
  const auto s = as_str(in.span());
  json j;
  std::size_t n = 0;
  if (s.starts_with("true")) { j.t = json::type::boolean; j.b = true; n = 4; }
  else if (s.starts_with("false")) { j.t = json::type::boolean; n = 5; }
  else if (s.starts_with("null")) { n = 4; }
  else return make_err(in, "a JSON value (string, number, object, array, true, false, null)");
  return done{std::move(j), in.advance(n)};
};

/// The recursive value parser. Depth travels by value: every nested array/object parses its
/// children with value_p{depth + 1}, and depth past max_depth is a hard (cut) failure.
struct value_p {
  unsigned depth = 0;
  inline result<json> operator()(input in) const;
};

inline result<json> value_p::operator()(input in) const {
  const std::size_t at = in.offset();
  auto located = [at](json j) { j.offset = at; return j; };
  if (in.empty()) return make_err(in, "a JSON value (string, number, object, array, true, false, null)");
  const char c = char(in[0]);
  if (c == '"')
    return map(string_lit, [&](string_acc a) {
      a.flush_hi();
      json j; j.t = json::type::string; j.s = std::move(a.s);
      return located(std::move(j));
    })(in);
  if (c == '-' || (c >= '0' && c <= '9'))
    return map(number_text, [&](auto b) { return located(make_number(as_str(b))); })(in);
  if (c != '[' && c != '{') return map(keyword, located)(in);

  if (depth >= max_depth) {
    error e = make_err(in, "nesting no deeper than 64 levels").error();
    e.kind = errk::fail;  // no alternative can fix this: stop here
    return unexp(e);
  }
  const value_p inner{depth + 1};
  if (c == '[') {
    return map(delimited(lit<'['>, separated_list0(tok(lit<','>), tok(inner)),
                         cut(tok(lit<']'>))),
               [&](std::vector<json> v) {
                 json j; j.t = json::type::array; j.items = std::move(v);
                 return located(std::move(j));
               })(in);
  }
  // member: "key" ':' value  — once the key is read, a missing ':' or value is final (cut)
  auto key = [](input i) -> result<std::pair<std::string, std::size_t>> {
    const std::size_t off = i.offset();
    return map(string_lit, [off](string_acc a) { a.flush_hi(); return std::pair{std::move(a.s), off}; })(i);
  };
  auto member = map(separated_pair(tok(key), cut(tok(lit<':'>)), cut(tok(inner))),
                    [](auto kv) {
                      return json_member{std::move(kv.first.first), kv.first.second,
                                         std::move(kv.second)};
                    });
  return map(delimited(lit<'{'>, separated_list0(tok(lit<','>), member), cut(tok(lit<'}'>))),
             [&](std::vector<json_member> m) {
               json j; j.t = json::type::object; j.members = std::move(m);
               return located(std::move(j));
             })(in);
}

/// ws value ws EOF
inline constexpr auto document = terminated(tok(value_p{}), tok(eof));

}  // namespace json_detail

/// Parse one complete JSON document (surrounding whitespace allowed). Offsets in the result and in
/// the error are relative to `text`.
inline expected<json, json_error> parse_json(std::string_view text) {
  const input in = from(text);
  auto r = json_detail::document(in);
  if (r) return std::move(r->value);
  const error& e = r.error();
  std::string what = "expected ";
  what += e.expected;
  if (std::string_view(e.expected) == "end of input") what = "unexpected text after the JSON value";
  return unexpected<json_error>(json_error{e.offset, std::move(what)});
}

/// Append `s` as a JSON string literal (quotes included) — used by the exporters too.
inline void append_json_string(std::string& out, std::string_view s) {
  out += '"';
  for (char ch : s) {
    const auto c = std::uint8_t(ch);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          static constexpr char hx[] = "0123456789abcdef";
          out += "\\u00"; out += hx[c >> 4]; out += hx[c & 15];
        } else out += ch;
    }
  }
  out += '"';
}

}  // namespace nanom::layout

#endif
