// SPDX-License-Identifier: Apache-2.0
// nanom/layout/export.hpp — JSON Lines and CSV out of records (or of decoded tables).
//
// JSON: one object per record, nested along the plan's name tree; array_item_N and repeated names
// become arrays, enums print their name (number when unnamed), pointers print as "0x..." strings,
// booleans as true/false, non-finite floats as null, floats in shortest round-trip form.
// The writer precompiles the tree into "literal, value, literal, value, ..., literal": per record
// it only appends pre-escaped key text and formats numbers — no tree walk, no string building.
#ifndef NANOM_LAYOUT_EXPORT_HPP_INCLUDED
#define NANOM_LAYOUT_EXPORT_HPP_INCLUDED

#include "decode.hpp"

namespace nanom::layout {

namespace detail {
inline void append_u64(std::string& out, std::uint64_t v) {
  char b[24];
  auto r = std::to_chars(b, b + sizeof b, v);
  out.append(b, r.ptr);
}
inline void append_i64(std::string& out, std::int64_t v) {
  char b[24];
  auto r = std::to_chars(b, b + sizeof b, v);
  out.append(b, r.ptr);
}
inline void append_hex(std::string& out, std::uint64_t v) {
  char b[24];
  auto r = std::to_chars(b, b + sizeof b, v, 16);
  out += "0x";
  out.append(b, r.ptr);
}
/// Shortest round-trip text; false (nothing appended) when not finite.
inline bool append_float(std::string& out, const scalar& v) {
  char b[40];
  std::to_chars_result r;
  if (v.st == storage::f32) {
    const float f = std::bit_cast<float>(std::uint32_t(v.bits));
    if (!std::isfinite(f)) return false;
    r = std::to_chars(b, b + sizeof b, f);
  } else {
    const double d = std::bit_cast<double>(v.bits);
    if (!std::isfinite(d)) return false;
    r = std::to_chars(b, b + sizeof b, d);
  }
  // keep floats recognizable as floats: 1.0 not 1, -0.0 not -0 (which parses as integer 0)
  const bool bare = std::find_if(b, r.ptr, [](char c) { return c == '.' || c == 'e' || c == 'n' || c == 'i'; }) == r.ptr;
  out.append(b, r.ptr);
  if (bare) out += ".0";
  return true;
}
inline void append_int(std::string& out, const scalar& v) {
  if (storage_signed(v.st)) append_i64(out, v.i64());
  else append_u64(out, v.u64());
}
}  // namespace detail

/// One value as JSON.
inline void append_json_value(std::string& out, const scalar& v) {
  switch (v.fam) {
    case family::boolean: out += v.bits ? "true" : "false"; return;
    case family::floating:
      if (!detail::append_float(out, v)) out += "null";
      return;
    case family::pointer: out += '"'; detail::append_hex(out, v.bits); out += '"'; return;
    case family::enumeration:
      if (const std::string* n = v.enum_name()) { append_json_string(out, *n); return; }
      detail::append_int(out, v);
      return;
    default: detail::append_int(out, v); return;
  }
}

inline void append_csv_text(std::string& out, std::string_view s) {
  if (s.find_first_of(",\"\r\n") == std::string_view::npos) { out += s; return; }
  out += '"';
  for (char c : s) { if (c == '"') out += '"'; out += c; }
  out += '"';
}

/// One value as a CSV cell.
inline void append_csv_value(std::string& out, const scalar& v) {
  switch (v.fam) {
    case family::boolean: out += v.bits ? "true" : "false"; return;
    case family::floating:
      if (!detail::append_float(out, v)) {
        const double d = v.f64();
        out += std::isnan(d) ? "nan" : d > 0 ? "inf" : "-inf";
      }
      return;
    case family::pointer: detail::append_hex(out, v.bits); return;
    case family::enumeration:
      if (const std::string* n = v.enum_name()) { append_csv_text(out, *n); return; }
      detail::append_int(out, v);
      return;
    default: detail::append_int(out, v); return;
  }
}

/// Precompiled JSON Lines writer for one selection.
class jsonl_writer {
 public:
  explicit jsonl_writer(const plan& p) : jsonl_writer(p, p.all()) {}
  jsonl_writer(const plan& p, const selection& s) {
    const auto tree = p.tree();
    std::vector<char> sel(p.size(), 0), has(tree.size(), 0);
    for (auto i : s.fields) sel[i] = 1;
    for (std::size_t n = tree.size(); n-- > 0;) {  // children have larger ids than parents
      const tree_node& t = tree[n];
      if (t.k == tree_node::kind::leaf) has[n] = sel[t.field];
      for (auto c : t.children) has[n] |= has[c];
    }
    std::string lit;
    struct gen {
      const plan& p;
      std::span<const tree_node> tree;
      const std::vector<char>& has;
      std::string& lit;
      jsonl_writer& w;
      void go(std::uint32_t n) {
        const tree_node& t = tree[n];
        switch (t.k) {
          case tree_node::kind::leaf:
            w.lits_.push_back(std::move(lit));
            lit.clear();
            w.handles_.push_back(p.handle(t.field));
            return;
          case tree_node::kind::null: lit += "null"; return;
          case tree_node::kind::object: {
            lit += '{';
            bool first = true;
            for (auto c : t.children) {
              if (!has[c]) continue;
              if (!first) lit += ',';
              first = false;
              append_json_string(lit, tree[c].key);
              lit += ':';
              go(c);
            }
            lit += '}';
            return;
          }
          case tree_node::kind::array: {
            lit += '[';
            std::size_t last = 0;
            for (std::size_t i = 0; i < t.children.size(); ++i)
              if (has[t.children[i]]) last = i + 1;
            for (std::size_t i = 0; i < last; ++i) {
              if (i) lit += ',';
              if (has[t.children[i]]) go(t.children[i]);
              else lit += "null";
            }
            lit += ']';
            return;
          }
        }
      }
    } g{p, tree, has, lit, *this};
    g.go(0);
    lit += '\n';
    lits_.push_back(std::move(lit));
  }

  /// Append one record as one line.
  void write(std::string& out, const record& r) const {
    emit(out, [&](std::size_t i) { return r.value(handles_[i]); });
  }
  /// Table columns feeding this writer (call once per table).
  std::vector<std::size_t> bind(const table& t) const {
    std::vector<std::size_t> col_of(t.source().size(), std::size_t(-1));
    for (std::size_t c = 0; c < t.columns(); ++c) col_of[t.field_index(c)] = c;
    std::vector<std::size_t> cols(handles_.size());
    for (std::size_t i = 0; i < handles_.size(); ++i) cols[i] = col_of[handles_[i].index];
    return cols;
  }
  /// Append row `row` of a decoded table (cols from bind(); the table must hold the selection).
  void write(std::string& out, const table& t, std::size_t row, std::span<const std::size_t> cols) const {
    emit(out, [&](std::size_t i) { return t.cell(row, cols[i]); });
  }
  std::size_t values() const { return handles_.size(); }

 private:
  template <class Get>
  void emit(std::string& out, Get&& get) const {
    for (std::size_t i = 0; i < handles_.size(); ++i) {
      out += lits_[i];
      append_json_value(out, get(i));
    }
    out += lits_.back();
  }
  std::vector<std::string> lits_;
  std::vector<field_handle> handles_;
};

/// CSV writer: a header of column names, then one row per record.
class csv_writer {
 public:
  explicit csv_writer(const plan& p) : csv_writer(p, p.all()) {}
  csv_writer(const plan& p, const selection& s) {
    for (auto i : s.fields) {
      handles_.push_back(p.handle(i));
      if (!header_.empty()) header_ += ',';
      append_csv_text(header_, p.fields()[i].column);
    }
    header_ += '\n';
  }
  const std::string& header() const { return header_; }
  void write(std::string& out, const record& r) const {
    for (std::size_t i = 0; i < handles_.size(); ++i) {
      if (i) out += ',';
      append_csv_value(out, r.value(handles_[i]));
    }
    out += '\n';
  }

 private:
  std::string header_;
  std::vector<field_handle> handles_;
};

/// Stream records [o.first, o.first + o.count) as JSON Lines into sink(std::string_view), in
/// chunks of ~1 MiB. Returns the number of records written.
template <class Sink>
lresult<std::size_t> export_jsonl(const plan& p, std::span<const std::byte> data, Sink&& sink,
                                  const selection& s, const decode_options& o = {}) {
  auto rr = resolve_range(p, data, o);
  if (!rr) return unexpected<layout_error>(rr.error());
  const jsonl_writer w(p, s);
  const auto recs = p.records(data);
  std::string buf;
  buf.reserve(std::size_t(1) << 21);
  for (std::size_t i = rr->first; i < rr->first + rr->count; ++i) {
    w.write(buf, recs[i]);
    if (buf.size() >= (std::size_t(1) << 20)) { sink(std::string_view(buf)); buf.clear(); }
  }
  if (!buf.empty()) sink(std::string_view(buf));
  return rr->count;
}

/// Same, CSV (header first).
template <class Sink>
lresult<std::size_t> export_csv(const plan& p, std::span<const std::byte> data, Sink&& sink,
                                const selection& s, const decode_options& o = {}) {
  auto rr = resolve_range(p, data, o);
  if (!rr) return unexpected<layout_error>(rr.error());
  const csv_writer w(p, s);
  const auto recs = p.records(data);
  std::string buf = w.header();
  for (std::size_t i = rr->first; i < rr->first + rr->count; ++i) {
    w.write(buf, recs[i]);
    if (buf.size() >= (std::size_t(1) << 20)) { sink(std::string_view(buf)); buf.clear(); }
  }
  if (!buf.empty()) sink(std::string_view(buf));
  return rr->count;
}

}  // namespace nanom::layout

#endif
