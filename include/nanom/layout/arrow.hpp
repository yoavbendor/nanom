// SPDX-License-Identifier: Apache-2.0
// nanom/layout/arrow.hpp — hand a decoded table to Arrow through the C Data Interface.
//
// export_arrow(std::move(table), &schema, &array[, options]) produces a struct array ("+s") with one
// child per column, named by column name with '.' replaced by arrow_options::separator ("/"). Integer / float columns are exported zero-copy (the
// table's 64-byte aligned buffers become the Arrow data buffers); boolean columns are bit-packed
// into Arrow's LSB-first bitmap.
//
// Enum columns that have an enum table become dictionary<intN, utf8> columns by default, so the
// names travel with the data (into Lance, Parquet, ...): the dictionary is the table's names in
// raw-value order, followed by the decimal text of every raw value that occurs in the data but is
// missing from the table (ascending), and the field metadata maps dictionary index -> raw value
// ("nanom.enum.values"). The table keeps the plain integer column; the translation is one cheap
// pass at export time (encode_enum). arrow_options::enums picks dictionary / integer / both.
// The table stays alive until the consumer has released the struct and every child it moved out.
#ifndef NANOM_LAYOUT_ARROW_HPP_INCLUDED
#define NANOM_LAYOUT_ARROW_HPP_INCLUDED

#include "decode.hpp"

#ifndef ARROW_C_DATA_INTERFACE
#define ARROW_C_DATA_INTERFACE
#define ARROW_FLAG_DICTIONARY_ORDERED 1
#define ARROW_FLAG_NULLABLE 2
#define ARROW_FLAG_MAP_KEYS_SORTED 4
extern "C" {
struct ArrowSchema {
  const char* format;
  const char* name;
  const char* metadata;
  int64_t flags;
  int64_t n_children;
  struct ArrowSchema** children;
  struct ArrowSchema* dictionary;
  void (*release)(struct ArrowSchema*);
  void* private_data;
};
struct ArrowArray {
  int64_t length;
  int64_t null_count;
  int64_t offset;
  int64_t n_buffers;
  int64_t n_children;
  const void** buffers;
  struct ArrowArray** children;
  struct ArrowArray* dictionary;
  void (*release)(struct ArrowArray*);
  void* private_data;
};
}
#endif

namespace nanom::layout {

/// Arrow C Data format string of a column type.
inline const char* arrow_format(storage s) {
  switch (s) {
    case storage::u8: return "C";
    case storage::u16: return "S";
    case storage::u32: return "I";
    case storage::u64: return "L";
    case storage::i8: return "c";
    case storage::i16: return "s";
    case storage::i32: return "i";
    case storage::i64: return "l";
    case storage::f32: return "f";
    case storage::f64: return "g";
    case storage::boolean: return "b";
  }
  return "C";
}

// ---------------------------------------------------------------------------
// enum column -> dictionary
// ---------------------------------------------------------------------------

/// A dictionary-encoded enum column: Arrow dictionary<index, utf8> in ready-to-export buffers.
struct enum_dictionary {
  storage index = storage::i8;          ///< i8 / i16 / i32 / i64: the smallest that holds size()
  bool unsigned_values = false;         ///< the raw column is unsigned (values print as uint64)
  std::vector<std::int64_t> values;     ///< raw value of dictionary entry i (unsigned: the bits)
  std::size_t named = 0;                ///< entries [0, named) are the enum table, in value order;
                                        ///< [named, size()) raw values seen in the data, no name
  std::vector<std::int32_t> offsets{0}; ///< Arrow utf8 offsets (size() + 1)
  std::string chars;                    ///< Arrow utf8 data
  std::size_t rows = 0;

  std::size_t size() const { return values.size(); }
  std::string_view name(std::size_t i) const {
    return std::string_view(chars).substr(std::size_t(offsets[i]), std::size_t(offsets[i + 1] - offsets[i]));
  }
  const void* index_data() const { return idx_.get(); }
  /// Dictionary index of every row. I must match `index` (int8_t for i8 ...); else empty.
  template <class I> std::span<const I> codes() const {
    if (storage_of<I>() != index) return {};
    return std::span<const I>(reinterpret_cast<const I*>(idx_.get()), rows);
  }
  /// Raw value of entry i as JSON number text (signed or unsigned per the column).
  std::string value_text(std::size_t i) const {
    return unsigned_values ? std::to_string(std::uint64_t(values[i])) : std::to_string(values[i]);
  }

  // internal
  struct aligned_delete {
    void operator()(std::byte* p) const { ::operator delete(p, std::align_val_t(64)); }
  };
  std::unique_ptr<std::byte, aligned_delete> idx_;
  void add(std::int64_t v, std::string_view n) {
    values.push_back(v);
    chars += n;
    offsets.push_back(std::int32_t(chars.size()));
  }
};

namespace arrow_detail {

/// Modular (sign-extending) widening: differences of widened values are distances in column order.
template <class T> constexpr std::uint64_t widen(T x) { return std::uint64_t(x); }
/// The table key of a column value (enum_table keys are int64; unsigned columns reinterpret).
template <class T> constexpr std::int64_t key(T x) {
  if constexpr (std::is_signed_v<T>) return std::int64_t(x);
  else return std::int64_t(std::uint64_t(x));
}

inline storage index_storage(std::size_t n) {
  return n <= 128 ? storage::i8 : n <= 32768 ? storage::i16
       : n <= (std::size_t(1) << 31) ? storage::i32 : storage::i64;
}

template <class I, class Src, class Map>
void write_codes(enum_dictionary& d, const Src* src, std::size_t n, Map&& map) {
  I* out = reinterpret_cast<I*>(d.idx_.get());
  for (std::size_t r = 0; r < n; ++r) out[r] = I(map(src[r]));
}
template <class Src, class Map>
void write_codes_any(enum_dictionary& d, const Src* src, std::size_t n, Map&& map) {
  d.index = index_storage(d.size());
  d.idx_.reset(static_cast<std::byte*>(
      ::operator new(std::max<std::size_t>(n * storage_size(d.index), 64), std::align_val_t(64))));
  switch (d.index) {
    case storage::i8: write_codes<std::int8_t>(d, src, n, map); break;
    case storage::i16: write_codes<std::int16_t>(d, src, n, map); break;
    case storage::i32: write_codes<std::int32_t>(d, src, n, map); break;
    default: write_codes<std::int64_t>(d, src, n, map); break;
  }
}

template <class T>
void encode_enum_typed(enum_dictionary& d, const enum_table& tab, const T* src, std::size_t n) {
  using U = std::uint64_t;
  for (const auto& [v, name] : tab.entries()) d.add(v, name);
  d.named = d.size();
  auto unnamed_text = [&](T x) { return std::is_signed_v<T> ? std::to_string(std::int64_t(x)) : std::to_string(std::uint64_t(x)); };
  if (n == 0) { write_codes_any(d, src, 0, [](T) { return 0; }); return; }
  T lo = src[0], hi = src[0];
  for (std::size_t r = 1; r < n; ++r) { lo = std::min(lo, src[r]); hi = std::max(hi, src[r]); }
  const U base = widen(lo), span = widen(hi) - base;  // values occupy [lo, lo + span]
  const U dense_limit = std::min<U>(std::max<U>(U(1) << 16, n), U(1) << 24);
  if (span < dense_limit) {
    // dense: lut[x - lo] = dictionary index; -1 = not in the table; -2 = not in the table, seen
    std::vector<std::int32_t> lut(std::size_t(span) + 1, -1);
    std::size_t hits = 0;
    for (std::size_t i = 0; i < d.named; ++i) {
      const U slot = U(d.values[i]) - base;  // unsigned columns: a negative key lands > span
      if (slot <= span && lut[std::size_t(slot)] < 0) { lut[std::size_t(slot)] = std::int32_t(i); ++hits; }
    }
    if (hits != lut.size()) {  // holes: find the raw values that need an unnamed entry
      for (std::size_t r = 0; r < n; ++r) {
        auto& e = lut[std::size_t(widen(src[r]) - base)];
        if (e == -1) e = -2;
      }
      for (std::size_t s = 0; s < lut.size(); ++s)
        if (lut[s] == -2) {
          const T x = T(base + s);  // modular: s <= span
          lut[s] = std::int32_t(d.size());
          d.add(key(x), unnamed_text(x));
        }
    }
    const std::int32_t* L = lut.data();
    write_codes_any(d, src, n, [L, base](T x) { return L[std::size_t(widen(x) - base)]; });
    return;
  }
  // sparse: the distinct values of the column (sorted copy), each given its dictionary index once;
  // then one binary search per row over that contiguous array
  std::vector<std::pair<T, std::int64_t>> tabk;  // table keys a T can hold, in column order
  tabk.reserve(d.named);
  for (std::size_t i = 0; i < d.named; ++i) {
    const std::int64_t v = d.values[i];
    if constexpr (std::is_unsigned_v<T>)  // keys a T can never hold (negative, too wide) never match
      if (sizeof(T) < 8 && std::uint64_t(v) > std::numeric_limits<T>::max()) continue;
    if constexpr (std::is_signed_v<T>)
      if (v < std::numeric_limits<T>::min() || v > std::numeric_limits<T>::max()) continue;
    tabk.emplace_back(T(v), std::int64_t(i));
  }
  std::sort(tabk.begin(), tabk.end());  // table keys are unique (enum_table::seal)
  std::vector<T> distinct(src, src + n);
  std::sort(distinct.begin(), distinct.end());
  distinct.erase(std::unique(distinct.begin(), distinct.end()), distinct.end());
  std::vector<std::int64_t> code(distinct.size());
  std::size_t ti = 0;
  for (std::size_t i = 0; i < distinct.size(); ++i) {  // merge: both ascending
    const T x = distinct[i];
    while (ti < tabk.size() && tabk[ti].first < x) ++ti;
    if (ti < tabk.size() && tabk[ti].first == x) code[i] = tabk[ti].second;
    else { code[i] = std::int64_t(d.size()); d.add(key(x), unnamed_text(x)); }
  }
  const T* D = distinct.data();
  const std::int64_t* C = code.data();
  const std::size_t nd = distinct.size();
  write_codes_any(d, src, n, [D, C, nd](T x) { return C[std::lower_bound(D, D + nd, x) - D]; });
}

}  // namespace arrow_detail

/// Dictionary-encode an integer enum column (`bytes` holds `rows` elements of `st`) with `tab`.
/// Dense value ranges use a lookup table (two passes: min/max, then gather; a third only when the
/// data has values outside the table); sparse ones sort a copy of the column once and binary-search
/// each row in its distinct values.
inline enum_dictionary encode_enum(const enum_table& tab, storage st, std::span<const std::byte> bytes,
                                   std::size_t rows) {
  enum_dictionary d;
  d.rows = rows;
  d.unsigned_values = !storage_signed(st);
  auto go = [&]<class T>(T) {
    arrow_detail::encode_enum_typed<T>(d, tab, reinterpret_cast<const T*>(bytes.data()), rows);
  };
  switch (st) {
    case storage::i8: go(std::int8_t{}); break;
    case storage::i16: go(std::int16_t{}); break;
    case storage::i32: go(std::int32_t{}); break;
    case storage::i64: go(std::int64_t{}); break;
    case storage::u8: case storage::boolean: go(std::uint8_t{}); break;
    case storage::u16: go(std::uint16_t{}); break;
    case storage::u32: go(std::uint32_t{}); break;
    default: go(std::uint64_t{}); break;
  }
  return d;
}
/// Dictionary-encode column c of a table (an enum column whose field has an enum table).
inline enum_dictionary encode_enum(const table& t, std::size_t c) {
  const field& f = t.column_field(c);
  static const enum_table empty;
  return encode_enum(f.enums ? *f.enums : empty, f.st, t.bytes(c), t.rows());
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

/// How enum columns with an enum table are exported (enum columns without one, or with an empty
/// one, are always plain integers).
enum class enum_mode : std::uint8_t {
  dictionary,  ///< dictionary<intN, utf8> under the column name (default)
  integer,     ///< the raw integer codes; the table travels as metadata "nanom.enum.names"
  both         ///< the dictionary column under the column name, then the integer codes as a
               ///< sibling named column + raw_suffix
};
/// How AUTOSAR signals with factor/offset are exported.
enum class signal_mode : std::uint8_t {
  automatic,  ///< both when the table has physical columns (decode_options::physical), else raw
  raw,        ///< the raw integer column only (factor/offset/unit as metadata)
  physical,   ///< the physical float64 column only, under the column name
  both        ///< physical float64 under the column name, then the raw integers as column + raw_suffix
};
struct arrow_options {
  enum_mode enums = enum_mode::dictionary;
  signal_mode signals = signal_mode::automatic;
  std::string raw_suffix = "#raw";  ///< enum_mode::both: name of the integer sibling = column + this
  /// Flat Arrow column names: the '.' between name components is replaced by this (Lance and
  /// several engines refuse '.' in top-level field names). "GFI[1].grab_index" -> "GFI[1]/grab_index".
  /// "." keeps the canonical names. Components never contain '.', so the mapping is reversible as
  /// long as the separator does not occur inside a component ('/' never does in C++ names).
  std::string separator = "/";
};

/// The Arrow column name export_arrow gives a column/scalar name under `separator`.
inline std::string arrow_column_name(std::string_view column, std::string_view separator = "/") {
  if (separator == ".") return std::string(column);
  std::string out;
  out.reserve(column.size() + 8);
  for (char ch : column) {
    if (ch == '.') out += separator;
    else out += ch;
  }
  return out;
}

namespace arrow_detail {
struct column {
  std::string name, metadata;
  std::int64_t nulls = 0;
  std::array<const void*, 2> buffers{nullptr, nullptr};
  std::array<const void*, 3> dict_buffers{nullptr, nullptr, nullptr};
  ArrowSchema schema{}, dict_schema{};
  ArrowArray array{}, dict_array{};
  std::vector<std::uint8_t> bitmap;
  std::vector<std::uint8_t> validity;  ///< Arrow validity bitmap (nullable signal columns)
  std::unique_ptr<enum_dictionary> dict;  ///< dictionary columns
};
struct state {
  table t;
  std::vector<column> cols;  ///< sized once; addresses stay put
  std::vector<ArrowSchema*> child_schema_ptr;
  std::vector<ArrowArray*> child_array_ptr;
  std::array<const void*, 1> struct_buffers{nullptr};
};
using holder = std::shared_ptr<state>;

inline void release_leaf_schema(ArrowSchema* s) {
  delete static_cast<holder*>(s->private_data);
  s->release = nullptr;
}
inline void release_leaf_array(ArrowArray* a) {
  delete static_cast<holder*>(a->private_data);
  a->release = nullptr;
}
inline void release_child_schema(ArrowSchema* s) {
  if (s->dictionary && s->dictionary->release) s->dictionary->release(s->dictionary);
  release_leaf_schema(s);
}
inline void release_child_array(ArrowArray* a) {
  if (a->dictionary && a->dictionary->release) a->dictionary->release(a->dictionary);
  release_leaf_array(a);
}
inline void release_schema(ArrowSchema* s) {
  for (int64_t i = 0; i < s->n_children; ++i)
    if (s->children[i]->release) s->children[i]->release(s->children[i]);
  release_leaf_schema(s);
}
inline void release_array(ArrowArray* a) {
  for (int64_t i = 0; i < a->n_children; ++i)
    if (a->children[i]->release) a->children[i]->release(a->children[i]);
  release_leaf_array(a);
}

/// Arrow C metadata: int32 count, then (int32 length, bytes) for each key and value.
inline std::string encode_metadata(std::span<const std::pair<std::string, std::string>> kv) {
  std::string m;
  auto put = [&](std::size_t n) { const auto v = std::int32_t(n); m.append(reinterpret_cast<const char*>(&v), 4); };
  put(kv.size());
  for (const auto& [k, v] : kv) { put(k.size()); m += k; put(v.size()); m += v; }
  return m;
}
inline std::vector<std::pair<std::string, std::string>> enum_metadata(const field& f) {
  return {{"nanom.layout.type", f.type}, {"nanom.enum.ref", std::to_string(f.enum_ref)},
          {"nanom.layout.storage", storage_name(f.st)}};
}
inline std::string md_num(double v) {
  char b[40];
  auto r = std::to_chars(b, b + sizeof b, v);
  return std::string(b, r.ptr);
}
/// AUTOSAR signal metadata (fields that use any signal key).
inline void signal_metadata(const plan& p, const field& f, std::vector<std::pair<std::string, std::string>>& md,
                            const char* role) {
  const field_signal& g = f.sig;
  if (!g.any) return;
  md.emplace_back("nanom.signal.role", role);  // raw / physical
  md.emplace_back("nanom.signal.factor", md_num(g.factor));
  md.emplace_back("nanom.signal.offset", md_num(g.offset));
  if (!g.unit.empty()) md.emplace_back("nanom.signal.unit", g.unit);
  if (g.min) md.emplace_back("nanom.signal.min", md_num(*g.min));
  if (g.max) md.emplace_back("nanom.signal.max", md_num(*g.max));
  md.emplace_back("nanom.signal.byte_order", g.order == byte_order::motorola ? "motorola"
                                             : g.order == byte_order::intel  ? "intel"
                                             : p.order() == std::endian::big ? "big" : "little");
  md.emplace_back("nanom.signal.start_bit", std::to_string(f.bit_offset));
  md.emplace_back("nanom.signal.bit_width", std::to_string(f.bit_width));
  md.emplace_back("nanom.signal.raw_storage", storage_name(f.st));
  if (g.multiplexor) md.emplace_back("nanom.signal.multiplexor", "true");
  if (g.mux != field_signal::none) {
    md.emplace_back("nanom.signal.mux_signal", p.fields()[g.mux].column);
    std::string v = "[";
    for (std::size_t i = 0; i < g.mux_values.size(); ++i) v += (i ? "," : "") + std::to_string(g.mux_values[i]);
    md.emplace_back("nanom.signal.mux_values", v + "]");
  }
  if (g.update_bit) md.emplace_back("nanom.signal.update_bit", std::to_string(*g.update_bit));
}
}  // namespace arrow_detail

/// Decode Arrow C metadata (the format encode_metadata writes) back into pairs; for tests/tools.
inline std::vector<std::pair<std::string, std::string>> arrow_metadata(const char* md) {
  std::vector<std::pair<std::string, std::string>> out;
  if (!md) return out;
  auto get = [&md]() { std::int32_t v; std::memcpy(&v, md, 4); md += 4; return std::size_t(v); };
  const std::size_t n = get();
  for (std::size_t i = 0; i < n; ++i) {
    const std::size_t kl = get();
    std::string k(md, kl);
    md += kl;
    const std::size_t vl = get();
    out.emplace_back(std::move(k), std::string(md, vl));
    md += vl;
  }
  return out;
}

/// Move `t` into Arrow C Data structs (out params are overwritten; release them when done).
inline void export_arrow(table&& t, ArrowSchema* out_schema, ArrowArray* out_array,
                         const arrow_options& o = {}) {
  using namespace arrow_detail;
  auto st = std::make_shared<state>();
  st->t = std::move(t);
  const table& tb = st->t;
  const auto rows = std::int64_t(tb.rows());
  auto is_dict = [&](std::size_t c) {
    const field& f = tb.column_field(c);
    return o.enums != enum_mode::integer && f.fam == family::enumeration && f.enums && f.enums->size();
  };
  // signals: 0 = raw only, 1 = physical only, 2 = physical + raw sibling
  auto sig_mode = [&](std::size_t c) {
    if (tb.physical(c).empty() || o.signals == signal_mode::raw) return 0;
    return o.signals == signal_mode::physical ? 1 : 2;
  };
  std::size_t n = 0;
  for (std::size_t c = 0; c < tb.columns(); ++c)
    n += sig_mode(c) ? std::size_t(sig_mode(c) == 2 ? 2 : 1) : 1 + (is_dict(c) && o.enums == enum_mode::both);
  st->cols.resize(n);
  std::size_t k = 0;
  std::size_t cur = 0;  // table column being exported (validity)
  auto leaf = [&](column& col, const char* format) {
    const auto v = tb.validity(cur);
    std::int64_t flags = 0;
    if (!v.empty()) {  // multiplexed / update-bit signal: nullable, Arrow validity bitmap
      col.nulls = std::int64_t(tb.null_count(cur));
      flags = ARROW_FLAG_NULLABLE;
      if (col.nulls) {
        col.validity.assign((v.size() + 7) / 8, 0);
        for (std::size_t r = 0; r < v.size(); ++r)
          if (v[r]) col.validity[r / 8] |= std::uint8_t(1u << (r % 8));
        col.buffers[0] = col.validity.data();
      }
    }
    col.schema = ArrowSchema{format, col.name.c_str(), col.metadata.empty() ? nullptr : col.metadata.c_str(),
                             flags, 0, nullptr, nullptr, &release_child_schema, new holder(st)};
    col.array = ArrowArray{rows, col.nulls, 0, 2, 0, col.buffers.data(), nullptr, nullptr, &release_child_array,
                           new holder(st)};
  };
  auto physical = [&](std::size_t c, std::string name) {
    column& col = st->cols[k++];
    const field& f = tb.column_field(c);
    col.name = std::move(name);
    std::vector<std::pair<std::string, std::string>> md;
    signal_metadata(tb.source(), f, md, "physical");
    col.metadata = encode_metadata(md);
    col.buffers = {nullptr, tb.physical(c).data()};
    leaf(col, "g");
  };
  auto plain = [&](std::size_t c, std::string name, bool with_names) {
    column& col = st->cols[k++];
    const field& f = tb.column_field(c);
    const storage s = f.st;
    col.name = std::move(name);
    const void* data = tb.bytes(c).data();
    if (s == storage::boolean) {
      col.bitmap.assign((tb.rows() + 7) / 8, 0);
      const auto v = tb.column<bool>(c);
      for (std::size_t r = 0; r < v.size(); ++r)
        if (v[r]) col.bitmap[r / 8] |= std::uint8_t(1u << (r % 8));
      data = col.bitmap.data();
    }
    if (f.fam == family::enumeration) {
      auto md = enum_metadata(f);
      if (with_names && f.enums && f.enums->size()) {
        std::string j = "{";
        for (const auto& [v, nm] : f.enums->entries()) {
          if (j.size() > 1) j += ',';
          append_json_string(j, std::to_string(v));
          j += ':';
          append_json_string(j, nm);
        }
        md.emplace_back("nanom.enum.names", j + "}");
      }
      signal_metadata(tb.source(), f, md, "raw");
      col.metadata = encode_metadata(md);
    } else if (f.sig.any) {
      std::vector<std::pair<std::string, std::string>> md{{"nanom.layout.type", f.type},
                                                          {"nanom.layout.storage", storage_name(f.st)}};
      signal_metadata(tb.source(), f, md, "raw");
      col.metadata = encode_metadata(md);
    }
    col.buffers = {nullptr, data};
    leaf(col, arrow_format(s));
  };
  auto dictionary = [&](std::size_t c, std::string name) {
    column& col = st->cols[k++];
    const field& f = tb.column_field(c);
    col.name = std::move(name);
    col.dict = std::make_unique<enum_dictionary>(encode_enum(tb, c));
    const enum_dictionary& d = *col.dict;
    auto md = enum_metadata(f);
    std::string vals = "[";
    for (std::size_t i = 0; i < d.size(); ++i) {
      if (i) vals += ',';
      vals += d.value_text(i);
    }
    md.emplace_back("nanom.enum.values", vals + "]");
    md.emplace_back("nanom.enum.named", std::to_string(d.named));
    signal_metadata(tb.source(), f, md, "raw");
    col.metadata = encode_metadata(md);
    col.buffers = {nullptr, d.index_data()};
    col.dict_buffers = {nullptr, d.offsets.data(), d.chars.data()};
    leaf(col, arrow_format(d.index));
    col.dict_schema = ArrowSchema{"u", "", nullptr, 0, 0, nullptr, nullptr, &release_leaf_schema, new holder(st)};
    col.dict_array = ArrowArray{std::int64_t(d.size()), 0, 0, 3, 0, col.dict_buffers.data(), nullptr,
                                nullptr, &release_leaf_array, new holder(st)};
    col.schema.dictionary = &col.dict_schema;
    col.array.dictionary = &col.dict_array;
  };
  for (std::size_t c = 0; c < tb.columns(); ++c) {
    cur = c;
    const std::string name = arrow_column_name(tb.column_field(c).column, o.separator);
    if (const int sm = sig_mode(c)) {
      physical(c, name);
      if (sm == 2) plain(c, name + o.raw_suffix, false);
      continue;
    }
    if (!is_dict(c)) { plain(c, name, o.enums == enum_mode::integer); continue; }
    dictionary(c, name);
    if (o.enums == enum_mode::both) plain(c, name + o.raw_suffix, false);
  }
  for (auto& col : st->cols) {
    st->child_schema_ptr.push_back(&col.schema);
    st->child_array_ptr.push_back(&col.array);
  }
  *out_schema = ArrowSchema{"+s", "", nullptr, 0, std::int64_t(n), st->child_schema_ptr.data(),
                            nullptr, &release_schema, new holder(st)};
  *out_array = ArrowArray{rows, 0, 0, 1, std::int64_t(n), st->struct_buffers.data(),
                          st->child_array_ptr.data(), nullptr, &release_array, new holder(st)};
}

}  // namespace nanom::layout

#endif
