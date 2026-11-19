// SPDX-License-Identifier: Apache-2.0
// nanom/layout/desc.hpp — the layout DESCRIPTION: JSON Lines of scalars + the optional enum file.
//
//   {"raw_file":"/dev/x/gfi.raw","scalar_name":"GFI.grab_index","bit_offset":0,"bit_width":32,"type":"UInt"}
//
// load_description() reads every line (whitespace, key order and extra keys tolerated; blank lines
// and lines starting with '#' or '//' skipped), validates it, and classifies the type string into a
// family (unsigned / signed / float / bool / pointer / enum) plus the declared storage size the
// name implies (UChar=1, Short=2, UInt=4, ULongLong=8, Real*8=8, Logical*4=4 ...). Every error
// carries source:line:column. Nothing here knows about record bytes: that is plan.hpp.
#ifndef NANOM_LAYOUT_DESC_HPP_INCLUDED
#define NANOM_LAYOUT_DESC_HPP_INCLUDED

#include <fstream>
#include <map>
#include <sstream>

#include "json.hpp"

namespace nanom::layout {

/// Every layout failure: where (source:line:column, 0 = unknown) and what.
struct layout_error {
  std::string source;
  std::size_t line = 0, column = 0;
  std::string message;

  std::string str() const {
    std::string s = source.empty() ? std::string("layout") : source;
    if (line) {
      s += ':' + std::to_string(line);
      if (column) s += ':' + std::to_string(column);
    }
    return s + ": " + message;
  }
};
template <class T>
using lresult = expected<T, layout_error>;
inline unexpected<layout_error> lfail(std::string source, std::size_t line, std::size_t col,
                                      std::string msg) {
  return unexpected<layout_error>(layout_error{std::move(source), line, col, std::move(msg)});
}

// ---------------------------------------------------------------------------
// type strings
// ---------------------------------------------------------------------------

enum class family : std::uint8_t {
  unsigned_int,  ///< UInt, UChar, UShort, ULong, ULongLong, Unsigned*, UInteger*N, Byte
  signed_int,    ///< Int, Char, Short, Long, LongLong, Integer*N, SChar
  floating,      ///< Float, Double, Real*4, Real*8 (bit_width 32 or 64)
  boolean,       ///< Logical*N, Bool, Boolean — nonzero is true
  pointer,       ///< *Void, *Anything, Foo* — unsigned, printed as hex
  enumeration,   ///< "Enum ref = N" — signed storage, names from the enum file
  raw            ///< unknown type in lenient mode — unsigned bits
};

inline const char* family_name(family f) {
  switch (f) {
    case family::unsigned_int: return "unsigned";
    case family::signed_int: return "signed";
    case family::floating: return "float";
    case family::boolean: return "bool";
    case family::pointer: return "pointer";
    case family::enumeration: return "enum";
    case family::raw: return "raw";
  }
  return "?";
}

struct type_info {
  family fam = family::raw;
  std::uint8_t size = 0;      ///< declared storage bytes the type name implies (0 = unknown)
  std::int64_t enum_ref = 0;  ///< enumeration only
};

namespace desc_detail {
inline std::string squash(std::string_view s) {  // lower-case, no blanks/underscores
  std::string o;
  for (char c : s) {
    if (c == ' ' || c == '\t' || c == '_') continue;
    o += (c >= 'A' && c <= 'Z') ? char(c + 32) : c;
  }
  return o;
}
inline std::optional<std::int64_t> parse_int(std::string_view s) {
  if (s.empty()) return std::nullopt;
  bool neg = false;
  if (s[0] == '-' || s[0] == '+') { neg = s[0] == '-'; s.remove_prefix(1); }
  int base = 10;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s.remove_prefix(2); }
  std::uint64_t v = 0;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
  if (ec != std::errc{} || p != s.data() + s.size() || s.empty()) return std::nullopt;
  if (neg) {
    if (v > std::uint64_t(1) << 63) return std::nullopt;
    return std::int64_t(0 - v);
  }
  if (v > std::uint64_t(std::numeric_limits<std::int64_t>::max())) return std::nullopt;
  return std::int64_t(v);
}
/// "*4" suffix of Logical*4 / Integer*2 / Real*8 (1..8), or nullopt.
inline std::optional<std::uint8_t> star_size(std::string_view rest) {
  if (rest.size() < 2 || rest[0] != '*') return std::nullopt;
  auto n = parse_int(rest.substr(1));
  if (!n || *n < 1 || *n > 16) return std::nullopt;
  return std::uint8_t(*n);
}
/// int family base names (after an optional u/unsigned/signed prefix) -> storage bytes.
inline std::optional<std::uint8_t> int_base(std::string_view s) {
  static constexpr std::pair<std::string_view, std::uint8_t> names[] = {
      {"char", 1},     {"short", 2},   {"shortint", 2},   {"int", 4},       {"integer", 4},
      {"long", 8},     {"longint", 8}, {"longlong", 8},   {"longlongint", 8}, {"int8", 1},
      {"int16", 2},    {"int32", 4},   {"int64", 8},      {"int8t", 1},     {"int16t", 2},
      {"int32t", 4},   {"int64t", 8},  {"wchar", 4},      {"wchart", 4},    {"char16", 2},
      {"char32", 4},   {"size", 8},    {"sizet", 8},      {"ptrdiff", 8},   {"ptrdifft", 8}};
  for (auto [n, sz] : names)
    if (s == n) return sz;
  if (s.starts_with("integer")) return star_size(s.substr(7));
  return std::nullopt;
}
}  // namespace desc_detail

/// Classify a type string. nullopt = unknown (strict mode rejects it, lenient decodes raw bits).
/// Matching ignores case, blanks and underscores, so "unsigned int", "UInt" and "uint" agree.
inline std::optional<type_info> classify_type(std::string_view type) {
  using namespace desc_detail;
  const std::string t = squash(type);
  if (t.empty()) return std::nullopt;
  type_info ti;
  if (t.starts_with("enumref=") || t.starts_with("enumref:")) {
    auto n = parse_int(t.substr(8));
    if (!n) return std::nullopt;
    ti.fam = family::enumeration; ti.size = 0; ti.enum_ref = *n;
    return ti;
  }
  if (t == "enum") { ti.fam = family::enumeration; ti.enum_ref = std::numeric_limits<std::int64_t>::min(); return ti; }
  if (t.front() == '*' || t.back() == '*') { ti.fam = family::pointer; return ti; }
  if (t.starts_with("logical")) {
    if (t.size() == 7) { ti.fam = family::boolean; ti.size = 4; return ti; }
    auto n = star_size(t.substr(7));
    if (!n) return std::nullopt;
    ti.fam = family::boolean; ti.size = *n; return ti;
  }
  if (t == "bool" || t == "boolean" || t == "bool8" || t == "cbool") { ti.fam = family::boolean; ti.size = 1; return ti; }
  if (t == "float" || t == "float32" || t == "single") { ti.fam = family::floating; ti.size = 4; return ti; }
  if (t == "double" || t == "float64") { ti.fam = family::floating; ti.size = 8; return ti; }
  if (t == "real") { ti.fam = family::floating; ti.size = 0; return ti; }
  if (t.starts_with("real")) {
    auto n = star_size(t.substr(4));
    if (!n || (*n != 4 && *n != 8)) return std::nullopt;
    ti.fam = family::floating; ti.size = *n; return ti;
  }
  if (t == "byte" || t == "ubyte") { ti.fam = family::unsigned_int; ti.size = 1; return ti; }
  if (t == "unsigned") { ti.fam = family::unsigned_int; ti.size = 4; return ti; }
  if (t == "signed") { ti.fam = family::signed_int; ti.size = 4; return ti; }
  if (t == "schar" || t == "signedchar") { ti.fam = family::signed_int; ti.size = 1; return ti; }
  if (auto n = int_base(t)) { ti.fam = family::signed_int; ti.size = *n; return ti; }
  for (std::string_view pre : {"unsigned", "u"})
    if (t.starts_with(pre))
      if (auto n = int_base(t.substr(pre.size()))) { ti.fam = family::unsigned_int; ti.size = *n; return ti; }
  if (t.starts_with("signed"))
    if (auto n = int_base(t.substr(6))) { ti.fam = family::signed_int; ti.size = *n; return ti; }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// the description
// ---------------------------------------------------------------------------

/// One line of the description.
struct scalar_desc {
  std::string raw_file;
  std::string name;   ///< scalar_name, verbatim
  std::string type;   ///< type string, verbatim
  std::uint64_t bit_offset = 0;
  std::uint32_t bit_width = 0;
  type_info ti;
  bool known_type = true;  ///< false: lenient mode decoded an unknown type as raw bits
  std::size_t line = 0;    ///< 1-based line in the description
};

struct description {
  std::string source;
  std::vector<scalar_desc> scalars;     ///< file order
  std::vector<std::string> raw_files;   ///< distinct raw_file values, first-appearance order
  std::vector<std::string> warnings;    ///< lenient mode: what was tolerated
  /// Scalars of one raw_file, in file order.
  std::vector<const scalar_desc*> of(std::string_view raw_file) const {
    std::vector<const scalar_desc*> v;
    for (const auto& s : scalars)
      if (s.raw_file == raw_file) v.push_back(&s);
    return v;
  }
};

struct load_options {
  bool strict = true;  ///< unknown types / inconsistent widths are errors (else: warnings)
  std::uint64_t max_record_bytes = std::uint64_t(1) << 30;  ///< reject offsets past this ("absurd")
  std::string source = "<layout>";  ///< file name used in error messages
};

namespace desc_detail {

inline lresult<std::string> get_string(const json& obj, std::string_view key, const load_options& o,
                                       std::size_t line) {
  const json* v = obj.find(key);
  if (!v)
    return lfail(o.source, line, obj.offset + 1, "missing key \"" + std::string(key) + "\"");
  if (!v->is_string())
    return lfail(o.source, line, v->offset + 1,
                 "\"" + std::string(key) + "\" must be a string, got " + json::type_name(v->t));
  return v->s;
}
inline lresult<std::uint64_t> get_uint(const json& obj, std::string_view key, const load_options& o,
                                       std::size_t line) {
  const json* v = obj.find(key);
  if (!v)
    return lfail(o.source, line, obj.offset + 1, "missing key \"" + std::string(key) + "\"");
  if (v->is_int() && v->i >= 0) return std::uint64_t(v->i);
  if (v->t == json::type::real && v->d >= 0 && v->d < 9.0e15 && v->d == double(std::uint64_t(v->d)))
    return std::uint64_t(v->d);  // 32.0 is still 32
  if (v->is_string())            // "32" is tolerated: some exporters quote everything
    if (auto n = parse_int(v->s); n && *n >= 0) return std::uint64_t(*n);
  return lfail(o.source, line, v->offset + 1,
               "\"" + std::string(key) + "\" must be a non-negative integer, got " +
                   (v->is_int() ? std::to_string(v->i) : std::string(json::type_name(v->t))));
}

/// Validate one parsed line into a scalar_desc.
inline lresult<scalar_desc> make_scalar(const json& obj, std::size_t line, const load_options& o,
                                        std::vector<std::string>& warnings) {
  if (!obj.is_object())
    return lfail(o.source, line, obj.offset + 1,
                 std::string("each line must be a JSON object, got ") + json::type_name(obj.t));
  scalar_desc s;
  s.line = line;
  auto rf = get_string(obj, "raw_file", o, line);
  if (!rf) return unexpected<layout_error>(rf.error());
  auto nm = get_string(obj, "scalar_name", o, line);
  if (!nm) return unexpected<layout_error>(nm.error());
  auto ty = get_string(obj, "type", o, line);
  if (!ty) return unexpected<layout_error>(ty.error());
  auto off = get_uint(obj, "bit_offset", o, line);
  if (!off) return unexpected<layout_error>(off.error());
  auto wid = get_uint(obj, "bit_width", o, line);
  if (!wid) return unexpected<layout_error>(wid.error());
  s.raw_file = std::move(*rf);
  s.name = std::move(*nm);
  s.type = std::move(*ty);
  const auto col_of = [&](std::string_view key) { const json* v = obj.find(key); return v ? v->offset + 1 : 0; };
  if (s.raw_file.empty()) return lfail(o.source, line, col_of("raw_file"), "raw_file is empty");
  if (s.name.empty()) return lfail(o.source, line, col_of("scalar_name"), "scalar_name is empty");
  if (s.name.size() > 4096) return lfail(o.source, line, col_of("scalar_name"), "scalar_name longer than 4096 bytes");
  if (*wid == 0 || *wid > 64)
    return lfail(o.source, line, col_of("bit_width"),
                 "bit_width must be 1..64, got " + std::to_string(*wid));
  const std::uint64_t max_bits = o.max_record_bytes * 8;
  if (*off >= max_bits || *off + *wid > max_bits)
    return lfail(o.source, line, col_of("bit_offset"),
                 "bit_offset " + std::to_string(*off) + " is beyond the record size limit (" +
                     std::to_string(o.max_record_bytes) + " bytes)");
  s.bit_offset = *off;
  s.bit_width = std::uint32_t(*wid);

  const auto warn_or_fail = [&](std::string msg) -> std::optional<layout_error> {
    if (o.strict) return layout_error{o.source, line, col_of("type"), std::move(msg)};
    warnings.push_back(o.source + ':' + std::to_string(line) + ": " + msg);
    return std::nullopt;
  };
  if (auto ti = classify_type(s.type)) {
    s.ti = *ti;
  } else {
    if (auto e = warn_or_fail("unknown type \"" + s.type + "\" (decoded as raw unsigned bits)"))
      return unexpected<layout_error>(*e);
    s.ti = type_info{family::raw, 0, 0};
    s.known_type = false;
  }
  const unsigned w = s.bit_width;
  if (s.ti.fam == family::floating) {
    if ((s.ti.size && w != 8u * s.ti.size) || (w != 32 && w != 64))
      return lfail(o.source, line, col_of("bit_width"),
                   "float type \"" + s.type + "\" needs bit_width " +
                       (s.ti.size ? std::to_string(8 * s.ti.size) : std::string("32 or 64")) +
                       ", got " + std::to_string(w));
    s.ti.size = std::uint8_t(w / 8);
  } else if (s.ti.size && w > 8u * s.ti.size) {
    if (auto e = warn_or_fail("type \"" + s.type + "\" holds " + std::to_string(8 * s.ti.size) +
                              " bits but bit_width is " + std::to_string(w)))
      return unexpected<layout_error>(*e);
    s.ti.size = 0;  // trust the width
  }
  return s;
}

}  // namespace desc_detail

/// Parse a JSON Lines description. A JSON array of the same objects is accepted too.
inline lresult<description> parse_description(std::string_view text, const load_options& o = {}) {
  description d;
  d.source = o.source;
  std::map<std::string, std::size_t, std::less<>> seen_files;
  std::map<std::tuple<std::string, std::string, std::uint64_t>, std::size_t> seen_fields;

  auto add = [&](const json& obj, std::size_t line) -> std::optional<layout_error> {
    auto s = desc_detail::make_scalar(obj, line, o, d.warnings);
    if (!s) return s.error();
    auto key = std::tuple{s->raw_file, s->name, s->bit_offset};
    if (auto it = seen_fields.find(key); it != seen_fields.end()) {
      std::string msg = "duplicate scalar \"" + s->name + "\" at bit_offset " +
                        std::to_string(s->bit_offset) + " (first on line " +
                        std::to_string(it->second) + ")";
      if (o.strict) return layout_error{o.source, line, 1, msg};
      d.warnings.push_back(o.source + ':' + std::to_string(line) + ": " + msg + " — skipped");
      return std::nullopt;
    }
    seen_fields.emplace(std::move(key), line);
    if (seen_files.emplace(s->raw_file, d.raw_files.size()).second) d.raw_files.push_back(s->raw_file);
    d.scalars.push_back(std::move(*s));
    return std::nullopt;
  };

  // Whole-document JSON array form.
  const auto first = text.find_first_not_of(" \t\r\n");
  if (first != std::string_view::npos && text[first] == '[') {
    auto doc = parse_json(text);
    if (!doc) {
      auto [l, c] = line_col(text, doc.error().offset);
      return lfail(o.source, l, c, doc.error().what);
    }
    for (const auto& item : doc->items) {
      auto [l, c] = line_col(text, item.offset);
      json shifted = item;
      // make_scalar reports offset+1 as the column: re-base offsets onto the item's line
      std::size_t line_start = item.offset - (c - 1);
      struct rebase { static void go(json& j, std::size_t base) {
        j.offset -= base; for (auto& m : j.members) { m.key_offset -= base; go(m.value, base); }
        for (auto& i : j.items) go(i, base); } };
      rebase::go(shifted, line_start);
      if (auto e = add(shifted, l)) return unexpected<layout_error>(*e);
    }
    return d;
  }

  std::size_t line = 0, pos = 0;
  while (pos <= text.size()) {
    std::size_t nl = text.find('\n', pos);
    if (nl == std::string_view::npos) nl = text.size();
    std::string_view ln = text.substr(pos, nl - pos);
    ++line;
    pos = nl + 1;
    if (!ln.empty() && ln.back() == '\r') ln.remove_suffix(1);
    const auto nb = ln.find_first_not_of(" \t");
    if (nb == std::string_view::npos || ln[nb] == '#' || ln.substr(nb).starts_with("//")) {
      if (nl == text.size()) break;
      continue;
    }
    auto j = parse_json(ln);
    if (!j) return lfail(o.source, line, j.error().offset + 1, j.error().what);
    if (auto e = add(*j, line)) return unexpected<layout_error>(*e);
    if (nl == text.size()) break;
  }
  return d;
}

inline lresult<std::string> read_text_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return lfail(path, 0, 0, "cannot open file");
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

/// Read and parse a description file.
inline lresult<description> load_description(const std::string& path, load_options o = {}) {
  auto t = read_text_file(path);
  if (!t) return unexpected<layout_error>(t.error());
  o.source = path;
  return parse_description(*t, o);
}

// ---------------------------------------------------------------------------
// enum definitions: { raw_file: { "Enum ref = N": { "value": "NAME", ... } } }
// ---------------------------------------------------------------------------

/// value -> name for one enum. Dense ranges use a direct table; sparse ones binary search.
class enum_table {
 public:
  void add(std::int64_t v, std::string name) { entries_.emplace_back(v, std::move(name)); }
  void seal() {
    std::stable_sort(entries_.begin(), entries_.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    // last definition of a value wins
    std::vector<std::pair<std::int64_t, std::string>> u;
    for (auto& e : entries_) {
      if (!u.empty() && u.back().first == e.first) u.back().second = std::move(e.second);
      else u.push_back(std::move(e));
    }
    entries_ = std::move(u);
    dense_.clear();
    if (!entries_.empty()) {
      lo_ = entries_.front().first;
      const auto hi = entries_.back().first;
      if (hi - lo_ < 4096) {
        dense_.assign(std::size_t(hi - lo_ + 1), -1);
        for (std::size_t i = 0; i < entries_.size(); ++i)
          dense_[std::size_t(entries_[i].first - lo_)] = std::int32_t(i);
      }
    }
  }
  /// Name of `v`, or nullptr when the value has no name.
  const std::string* name(std::int64_t v) const {
    if (!dense_.empty()) {
      if (v < lo_ || std::uint64_t(v - lo_) >= dense_.size()) return nullptr;
      const auto i = dense_[std::size_t(v - lo_)];
      return i < 0 ? nullptr : &entries_[std::size_t(i)].second;
    }
    auto it = std::lower_bound(entries_.begin(), entries_.end(), v,
                               [](const auto& e, std::int64_t x) { return e.first < x; });
    return it != entries_.end() && it->first == v ? &it->second : nullptr;
  }
  bool has_negative() const { return !entries_.empty() && entries_.front().first < 0; }
  std::size_t size() const { return entries_.size(); }
  const auto& entries() const { return entries_; }

 private:
  std::vector<std::pair<std::int64_t, std::string>> entries_;
  std::vector<std::int32_t> dense_;
  std::int64_t lo_ = 0;
};

class enum_catalog {
 public:
  /// The enum `ref` of `raw_file`, or nullptr.
  std::shared_ptr<const enum_table> find(std::string_view raw_file, std::int64_t ref) const {
    auto f = files_.find(raw_file);
    if (f == files_.end()) return nullptr;
    auto e = f->second.find(ref);
    return e == f->second.end() ? nullptr : e->second;
  }
  std::size_t size() const {
    std::size_t n = 0;
    for (const auto& [_, m] : files_) n += m.size();
    return n;
  }
  std::map<std::string, std::map<std::int64_t, std::shared_ptr<const enum_table>>, std::less<>> files_;
};

/// Parse the enum file. Enum keys may be "Enum ref = N" or just "N"; value keys are decimal (or
/// 0x hex) integers, possibly negative; names must be strings.
inline lresult<enum_catalog> parse_enums(std::string_view text, std::string source = "<enums>") {
  auto doc = parse_json(text);
  auto fail_at = [&](std::size_t off, std::string msg) {
    auto [l, c] = line_col(text, off);
    return lfail(source, l, c, std::move(msg));
  };
  if (!doc) return fail_at(doc.error().offset, doc.error().what);
  if (!doc->is_object()) return fail_at(doc->offset, "the enum file must be a JSON object keyed by raw_file");
  enum_catalog cat;
  for (const auto& file : doc->members) {
    if (!file.value.is_object())
      return fail_at(file.value.offset, "enums of \"" + file.key + "\" must be an object keyed by \"Enum ref = N\"");
    auto& per_file = cat.files_[file.key];
    for (const auto& en : file.value.members) {
      std::string_view k = en.key;
      std::string sq = desc_detail::squash(k);
      if (sq.starts_with("enumref=")) sq = sq.substr(8);
      auto ref = desc_detail::parse_int(sq);
      if (!ref) return fail_at(en.key_offset, "enum key \"" + en.key + "\" is not \"Enum ref = <integer>\"");
      if (!en.value.is_object())
        return fail_at(en.value.offset, "enum \"" + en.key + "\" must be an object of \"value\": \"NAME\"");
      auto t = std::make_shared<enum_table>();
      for (const auto& kv : en.value.members) {
        auto v = desc_detail::parse_int(kv.key);
        if (!v) return fail_at(kv.key_offset, "enum value \"" + kv.key + "\" is not an integer");
        if (!kv.value.is_string())
          return fail_at(kv.value.offset, std::string("enum name must be a string, got ") +
                                              json::type_name(kv.value.t));
        t->add(*v, kv.value.s);
      }
      t->seal();
      per_file[*ref] = std::move(t);
    }
  }
  return cat;
}

inline lresult<enum_catalog> load_enums(const std::string& path) {
  auto t = read_text_file(path);
  if (!t) return unexpected<layout_error>(t.error());
  return parse_enums(*t, path);
}

}  // namespace nanom::layout

#endif
