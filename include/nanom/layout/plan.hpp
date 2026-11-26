// SPDX-License-Identifier: Apache-2.0
// nanom/layout/plan.hpp — compile the description of ONE raw_file into a decode plan.
//
// A plan is the description with every question answered once, up front:
//   * record stride (C struct rule, or the caller's override) — validated against every field;
//   * per field: the byte offset of one fixed-size load, the shift, the width, sign extension, the
//     storage type of its column, its enum table — an `access` the hot loops run without checks;
//   * the NAME TREE from the dotted scalar names: `::` stays inside a component, `array_item_N`
//     siblings become JSON arrays, and a name that repeats at several offsets becomes an implicit
//     array placed at the highest component whose whole subtree repeats the same number of times
//     (GFI.* x2 -> "GFI":[{...},{...}]).
// SAFETY: the description is untrusted. compile() proves that every load of every field stays
// inside [0, stride); a record_set only ever hands out records with `stride` readable bytes. So
// record::get and the column kernels read without bounds checks and still never leave the buffer.
#ifndef NANOM_LAYOUT_PLAN_HPP_INCLUDED
#define NANOM_LAYOUT_PLAN_HPP_INCLUDED

#include <cmath>
#include <unordered_map>

#include "desc.hpp"

namespace nanom::layout {

/// Column element type of a field.
enum class storage : std::uint8_t { u8, u16, u32, u64, i8, i16, i32, i64, f32, f64, boolean };

constexpr std::size_t storage_size(storage s) {
  switch (s) {
    case storage::u8: case storage::i8: case storage::boolean: return 1;
    case storage::u16: case storage::i16: return 2;
    case storage::u32: case storage::i32: case storage::f32: return 4;
    default: return 8;
  }
}
constexpr bool storage_signed(storage s) {
  return s == storage::i8 || s == storage::i16 || s == storage::i32 || s == storage::i64;
}
inline const char* storage_name(storage s) {
  static constexpr const char* n[] = {"u8", "u16", "u32", "u64", "i8", "i16",
                                      "i32", "i64", "f32", "f64", "bool"};
  return n[std::size_t(s)];
}
/// storage<T>: the storage tag of a C++ column element type (for typed column access).
template <class T> constexpr std::optional<storage> storage_of() {
  if constexpr (std::is_same_v<T, bool>) return storage::boolean;
  else if constexpr (std::is_same_v<T, float>) return storage::f32;
  else if constexpr (std::is_same_v<T, double>) return storage::f64;
  else if constexpr (std::is_integral_v<T> && std::is_signed_v<T>)
    return sizeof(T) == 1 ? storage::i8 : sizeof(T) == 2 ? storage::i16 : sizeof(T) == 4 ? storage::i32 : storage::i64;
  else if constexpr (std::is_integral_v<T>)
    return sizeof(T) == 1 ? storage::u8 : sizeof(T) == 2 ? storage::u16 : sizeof(T) == 4 ? storage::u32 : storage::u64;
  else return std::nullopt;
}

namespace detail {

/// How a field is loaded. Natural modes are one aligned-size load at a byte offset; bit modes load
/// one 64-bit word (or 64 + 8 bits when a field straddles 9 bytes) and shift; `small` is for
/// records shorter than 8 bytes, where no 8-byte window fits.
enum class mode : std::uint8_t { n8, n16, n32, n64, bits64, bits72, small };

struct access {
  std::uint32_t off = 0;   ///< byte offset of the load inside the record
  mode m = mode::n8;
  std::uint8_t sh = 0;     ///< bit shift: from the LSB of the load (little) / the MSB (big)
  std::uint8_t width = 0;  ///< 1..64
  std::uint8_t span = 0;   ///< small mode: bytes loaded
  bool sign = false;       ///< sign-extend from `width`
  bool be = false;         ///< big-endian storage / MSB-first bit numbering
  constexpr std::size_t load_bytes() const {
    switch (m) {
      case mode::n8: return 1;
      case mode::n16: return 2;
      case mode::n32: return 4;
      case mode::n64: case mode::bits64: return 8;
      case mode::bits72: return 9;
      case mode::small: return span;
    }
    return 0;
  }
};

template <class U, bool BE>
inline U load(const std::byte* p) {
  U v;
  std::memcpy(&v, p, sizeof v);
  if constexpr ((std::endian::native == std::endian::big) != BE)
    if constexpr (sizeof(U) > 1) v = std::byteswap(v);
  return v;
}

/// The value bits of field `a` in record `rec`: zero-extended, or sign-extended when a.sign.
/// M / BE / Sign are template parameters so the column kernels are straight-line code; the
/// runtime extract() below dispatches once.
template <mode M, bool BE, bool Sign>
inline std::uint64_t extract_t(const std::byte* rec, const access& a) {
  const std::byte* p = rec + a.off;
  if constexpr (M == mode::n8) return Sign ? std::uint64_t(std::int64_t(std::int8_t(load<std::uint8_t, BE>(p)))) : load<std::uint8_t, BE>(p);
  else if constexpr (M == mode::n16) return Sign ? std::uint64_t(std::int64_t(std::int16_t(load<std::uint16_t, BE>(p)))) : load<std::uint16_t, BE>(p);
  else if constexpr (M == mode::n32) return Sign ? std::uint64_t(std::int64_t(std::int32_t(load<std::uint32_t, BE>(p)))) : load<std::uint32_t, BE>(p);
  else if constexpr (M == mode::n64) return load<std::uint64_t, BE>(p);
  else {
    std::uint64_t t;  // field moved to the top bits
    if constexpr (M == mode::bits64) {
      const std::uint64_t v = load<std::uint64_t, BE>(p);
      t = BE ? v << a.sh : (v >> a.sh) << (64 - a.width);
    } else if constexpr (M == mode::bits72) {
      const std::uint64_t lo = load<std::uint64_t, BE>(p);
      const std::uint64_t hi = std::uint8_t(p[8]);  // a.sh is 1..7 here
      t = BE ? (lo << a.sh) | (hi >> (8 - a.sh))
             : ((lo >> a.sh) | (hi << (64 - a.sh))) << (64 - a.width);
    } else {  // small: 1..7 bytes
      std::uint64_t v = 0;
      if constexpr (BE) {
        for (unsigned i = 0; i < a.span; ++i) v = (v << 8) | std::uint8_t(p[i]);
        t = (v << (64 - 8 * a.span)) << a.sh;
      } else {
        for (unsigned i = 0; i < a.span; ++i) v |= std::uint64_t(std::uint8_t(p[i])) << (8 * i);
        t = (v >> a.sh) << (64 - a.width);
      }
    }
    if constexpr (Sign) return std::uint64_t(std::int64_t(t) >> (64 - a.width));
    else return t >> (64 - a.width);
  }
}

template <class F>
inline decltype(auto) dispatch_access(const access& a, F&& f) {
  auto with_be = [&](auto M) -> decltype(auto) {
    auto with_sign = [&](auto B) -> decltype(auto) {
      if (a.sign) return f(M, B, std::true_type{});
      return f(M, B, std::false_type{});
    };
    if (a.be) return with_sign(std::true_type{});
    return with_sign(std::false_type{});
  };
  using enum mode;
  switch (a.m) {
    case n8: return with_be(std::integral_constant<mode, n8>{});
    case n16: return with_be(std::integral_constant<mode, n16>{});
    case n32: return with_be(std::integral_constant<mode, n32>{});
    case n64: return with_be(std::integral_constant<mode, n64>{});
    case bits64: return with_be(std::integral_constant<mode, bits64>{});
    case bits72: return with_be(std::integral_constant<mode, bits72>{});
    default: return with_be(std::integral_constant<mode, small>{});
  }
}

inline std::uint64_t extract(const std::byte* rec, const access& a) {
  return dispatch_access(a, [&](auto M, auto B, auto S) {
    return extract_t<decltype(M)::value, decltype(B)::value, decltype(S)::value>(rec, a);
  });
}

template <class U, bool BE>
inline void store(std::byte* p, U v) {
  if constexpr ((std::endian::native == std::endian::big) != BE)
    if constexpr (sizeof(U) > 1) v = std::byteswap(v);
  std::memcpy(p, &v, sizeof v);
}

/// The inverse of extract(): write the low `a.width` bits of `v` into field `a` of record `rec`,
/// preserving every other bit (read-modify-write of the same window extract() reads).
template <bool BE>
inline void insert_t(std::byte* rec, const access& a, std::uint64_t v) {
  std::byte* p = rec + a.off;
  const unsigned w = a.width;
  const std::uint64_t mask = w >= 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << w) - 1;
  v &= mask;
  switch (a.m) {
    case mode::n8: store<std::uint8_t, BE>(p, std::uint8_t(v)); return;
    case mode::n16: store<std::uint16_t, BE>(p, std::uint16_t(v)); return;
    case mode::n32: store<std::uint32_t, BE>(p, std::uint32_t(v)); return;
    case mode::n64: store<std::uint64_t, BE>(p, v); return;
    case mode::bits64: {
      const unsigned pos = BE ? 64 - a.sh - w : a.sh;
      const std::uint64_t x = load<std::uint64_t, BE>(p);
      store<std::uint64_t, BE>(p, (x & ~(mask << pos)) | (v << pos));
      return;
    }
    case mode::bits72: {  // a.sh in 1..7, a.sh + w in 65..72
      const std::uint64_t lo = load<std::uint64_t, BE>(p);
      const std::uint8_t hi = std::uint8_t(p[8]);
      const unsigned lo_bits = 64 - a.sh, hi_bits = w - lo_bits;  // hi_bits in 1..8
      const std::uint64_t lo_mask = ~std::uint64_t(0) >> a.sh;    // low lo_bits ones
      const unsigned hmask = (1u << hi_bits) - 1;
      if constexpr (BE) {  // the field's high lo_bits bits end the 64-bit word, the rest top byte 8
        store<std::uint64_t, BE>(p, (lo & ~lo_mask) | (v >> hi_bits));
        const unsigned sh8 = 8 - hi_bits;
        p[8] = std::byte((hi & ~(hmask << sh8)) | ((unsigned(v) & hmask) << sh8));
      } else {  // the field's low lo_bits bits are the top of the word, the rest bottom of byte 8
        store<std::uint64_t, BE>(p, (lo & ~(lo_mask << a.sh)) | (v << a.sh));
        p[8] = std::byte((hi & ~hmask) | (unsigned(v >> lo_bits) & hmask));
      }
      return;
    }
    case mode::small: {
      std::uint64_t x = 0;
      const unsigned n = a.span;
      if constexpr (BE) for (unsigned i = 0; i < n; ++i) x = (x << 8) | std::uint8_t(p[i]);
      else for (unsigned i = 0; i < n; ++i) x |= std::uint64_t(std::uint8_t(p[i])) << (8 * i);
      const unsigned pos = BE ? 8 * n - a.sh - w : a.sh;
      x = (x & ~(mask << pos)) | (v << pos);
      if constexpr (BE) for (unsigned i = 0; i < n; ++i) p[i] = std::byte(x >> (8 * (n - 1 - i)));
      else for (unsigned i = 0; i < n; ++i) p[i] = std::byte(x >> (8 * i));
      return;
    }
  }
}
inline void insert(std::byte* rec, const access& a, std::uint64_t v) {
  if (a.be) insert_t<true>(rec, a, v);
  else insert_t<false>(rec, a, v);
}

/// The narrowest single load for a field of `w` bits at linear bit `lin` in a record of `stride`
/// bytes (bit numbering per byte order: LSB-first little-endian / MSB-first big-endian).
inline access make_access(std::uint64_t lin, unsigned w, bool be, std::size_t stride) {
  access a;
  a.width = std::uint8_t(w);
  a.be = be;
  const std::uint64_t byte = lin / 8;
  const unsigned sh0 = unsigned(lin % 8);
  const unsigned span = (sh0 + w + 7) / 8;
  if (sh0 == 0 && (w == 8 || w == 16 || w == 32 || w == 64)) {
    a.m = w == 8 ? mode::n8 : w == 16 ? mode::n16 : w == 32 ? mode::n32 : mode::n64;
    a.off = std::uint32_t(byte);
  } else if (stride >= 8 && span <= 8) {
    const std::uint64_t off = std::min<std::uint64_t>(byte, stride - 8);
    a.m = mode::bits64;
    a.off = std::uint32_t(off);
    a.sh = std::uint8_t(sh0 + 8 * (byte - off));
  } else if (span == 9) {
    a.m = mode::bits72;
    a.off = std::uint32_t(byte);
    a.sh = std::uint8_t(sh0);
  } else {
    a.m = mode::small;
    a.off = std::uint32_t(byte);
    a.sh = std::uint8_t(sh0);
    a.span = std::uint8_t(span);
  }
  return a;
}

inline bool is_array_item(std::string_view c, std::uint64_t* n = nullptr) {
  constexpr std::string_view pre = "array_item_";
  if (!c.starts_with(pre) || c.size() == pre.size() || c.size() > pre.size() + 9) return false;
  std::uint64_t v = 0;
  for (char ch : c.substr(pre.size())) {
    if (ch < '0' || ch > '9') return false;
    v = v * 10 + std::uint64_t(ch - '0');
  }
  if (n) *n = v;
  return true;
}

}  // namespace detail

/// Split a scalar name into components on '.' only: "MEIO::X._a.long>._M_i" ->
/// ["MEIO::X", "_a", "long>", "_M_i"]. Empty components (a..b, leading/trailing '.') are kept as
/// "" so callers can reject them.
inline std::vector<std::string_view> split_name(std::string_view name) {
  std::vector<std::string_view> out;
  std::size_t pos = 0;
  for (;;) {
    const auto dot = name.find('.', pos);
    out.push_back(name.substr(pos, dot == std::string_view::npos ? std::string_view::npos : dot - pos));
    if (dot == std::string_view::npos) break;
    pos = dot + 1;
  }
  return out;
}

/// The decoded bits of one field plus what is needed to interpret them.
struct scalar {
  std::uint64_t bits = 0;  ///< sign-extended for signed storage; IEEE bits for floats
  storage st = storage::u64;
  family fam = family::raw;
  std::uint8_t width = 64;
  const enum_table* enums = nullptr;

  std::int64_t i64() const { return std::int64_t(bits); }
  std::uint64_t u64() const { return bits; }
  double f64() const {
    if (st == storage::f32) return double(std::bit_cast<float>(std::uint32_t(bits)));
    if (st == storage::f64) return std::bit_cast<double>(bits);
    return storage_signed(st) ? double(i64()) : double(bits);
  }
  /// The value converted to T (static_cast semantics; bool: nonzero).
  template <class T> T as() const {
    if constexpr (std::is_same_v<T, bool>) return st == storage::f32 || st == storage::f64 ? f64() != 0 : bits != 0;
    else if (st == storage::f32 || st == storage::f64) return T(f64());
    else if (st == storage::boolean) return T(bits != 0);
    else if (storage_signed(st)) return T(i64());
    else return T(bits);
  }
  /// Enum name, or nullptr.
  const std::string* enum_name() const { return enums ? enums->name(i64()) : nullptr; }
};

/// A precomputed field handle: everything record::get needs, no string work, no plan lookup.
struct field_handle {
  std::uint32_t index = 0;
  detail::access acc;
  storage st = storage::u64;
  family fam = family::raw;
  const enum_table* enums = nullptr;
  double factor = 1, offset = 0;  ///< physical = raw * factor + offset (1 / 0 unless scaled)
};

/// One record: `stride` readable bytes (guaranteed by whoever made it).
class record {
 public:
  /// The field's value converted to T. ~3 ns: one load, shift, sign-extend, convert.
  template <class T> T get(const field_handle& h) const { return value(h).template as<T>(); }
  scalar value(const field_handle& h) const {
    return scalar{detail::extract(p_, h.acc), h.st, h.fam, h.acc.width, h.enums};
  }
  scalar operator[](const field_handle& h) const { return value(h); }
  /// Physical value: raw * factor + offset (the raw value itself for unscaled fields).
  double physical(const field_handle& h) const { return value(h).f64() * h.factor + h.offset; }
  std::span<const std::byte> bytes() const { return std::span<const std::byte>(p_, n_); }

 private:
  friend class record_set;
  friend class plan;
  record(const std::byte* p, std::size_t n) : p_(p), n_(n) {}
  const std::byte* p_;
  std::size_t n_;
};

/// The whole records of a byte span (zero-copy). A trailing partial record is reported via
/// tail_bytes() and never handed out.
class record_set {
 public:
  record_set() = default;
  record_set(std::span<const std::byte> data, std::size_t stride)
      : data_(data), stride_(stride), count_(stride ? data.size() / stride : 0),
        tail_(stride ? data.size() % stride : data.size()) {}
  std::size_t size() const { return count_; }
  std::size_t tail_bytes() const { return tail_; }
  std::size_t stride() const { return stride_; }
  /// Unchecked (i < size() is the caller's job); at() checks.
  record operator[](std::size_t i) const { return record(data_.data() + i * stride_, stride_); }
  std::optional<record> at(std::size_t i) const {
    if (i >= count_) return std::nullopt;
    return (*this)[i];
  }
  std::span<const std::byte> data() const { return data_.first(count_ * stride_); }

  struct iterator {
    const record_set* s; std::size_t i;
    record operator*() const { return (*s)[i]; }
    iterator& operator++() { ++i; return *this; }
    bool operator==(const iterator& o) const { return i == o.i; }
  };
  iterator begin() const { return {this, 0}; }
  iterator end() const { return {this, count_}; }

 private:
  std::span<const std::byte> data_;
  std::size_t stride_ = 0, count_ = 0, tail_ = 0;
};

/// AUTOSAR signal attributes of a field (all defaults for plain layout scalars).
struct field_signal {
  static constexpr std::uint32_t none = std::uint32_t(-1);
  byte_order order = byte_order::plan;  ///< as described (plan = the plan's order)
  double factor = 1, offset = 0;
  bool scaled = false;                  ///< factor/offset given: a physical column is produced
  std::string unit;
  std::optional<double> min, max;
  bool multiplexor = false;
  std::uint32_t mux = none;             ///< field index of the multiplexor (multiplexed signals)
  std::vector<std::int64_t> mux_values;
  std::string mux_signal;               ///< as described ("" = the PDU's only multiplexor)
  std::optional<std::uint64_t> update_bit;
  detail::access update;                ///< 1-bit Intel access of the update bit
  bool any = false;                     ///< any signal key given
  bool conditional() const { return mux != none || update_bit.has_value(); }
};

/// One field of a plan.
struct field {
  std::string name;    ///< scalar_name as written
  std::string column;  ///< unique column name: name, with [k] at the implicit-array component
  std::string type;    ///< type string as written
  std::uint64_t bit_offset = 0;
  std::uint32_t bit_width = 0;
  family fam = family::raw;
  storage st = storage::u64;
  std::uint8_t align = 1;      ///< natural alignment used by the stride rule
  std::int64_t enum_ref = 0;
  const enum_table* enums = nullptr;
  std::size_t line = 0;        ///< description line
  std::uint32_t occurrence = 0, occurrences = 1;  ///< k-th of n fields with this name (offset order)
  detail::access acc;
  std::uint64_t linear_offset = 0;  ///< offset in the access numbering (Motorola: MSB-first linear)
  field_signal sig;

  bool bitfield() const { return acc.m >= detail::mode::bits64; }
};

/// Node of the output tree (JSON nesting).
struct tree_node {
  enum class kind : std::uint8_t { object, array, leaf, null };
  kind k = kind::object;
  std::string key;                     ///< key in the parent object ("" for array elements)
  std::vector<std::uint32_t> children; ///< node ids
  std::uint32_t field = 0;             ///< leaf: field index
};

/// A subset of a plan's fields (indices in plan order).
struct selection {
  std::vector<std::uint32_t> fields;
};

struct compile_options {
  std::optional<std::uint64_t> stride{};  ///< record size in bytes for every raw_file
  std::map<std::string, std::uint64_t, std::less<>> stride_by_file{};  ///< per-raw_file override
  std::endian order = std::endian::little;
  bool strict = true;  ///< name conflicts are errors (lenient: warnings)
  std::uint64_t max_record_bytes = std::uint64_t(1) << 30;
};

/// True when `s` matches selection pattern `p`: glob (* and ?) when it has wildcards; otherwise
/// exact, or a prefix ending at a component boundary ("A.b" selects "A.b.c" and "A.b[1].c",
/// "A.b." and "A::" are plain prefixes).
inline bool name_matches(std::string_view p, std::string_view s) {
  if (p.find_first_of("*?") != std::string_view::npos) {
    std::size_t pi = 0, si = 0, star = std::string_view::npos, mark = 0;
    while (si < s.size()) {
      if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) { ++pi; ++si; }
      else if (pi < p.size() && p[pi] == '*') { star = pi++; mark = si; }
      else if (star != std::string_view::npos) { pi = star + 1; si = ++mark; }
      else return false;
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
  }
  if (s == p) return true;
  if (!s.starts_with(p) || p.empty()) return false;
  const char last = p.back();
  if (last == '.' || last == ':' || last == '[') return true;
  return s[p.size()] == '.' || s[p.size()] == '[';
}

class plan {
 public:
  /// Compile the scalars of `raw_file`. `enums` may be null.
  static lresult<plan> compile(const description& d, std::string_view raw_file,
                               const enum_catalog* enums = nullptr, const compile_options& o = {});

  const std::string& raw_file() const { return raw_file_; }
  std::span<const field> fields() const { return fields_; }
  std::size_t size() const { return fields_.size(); }
  std::size_t stride() const { return stride_; }
  /// Bytes the fields actually cover: ceil(max(bit_offset + bit_width) / 8).
  std::size_t used_bytes() const { return used_bytes_; }
  /// Largest field alignment (the stride rule's rounding unit).
  std::size_t alignment() const { return align_; }
  std::endian order() const { return order_; }
  const std::vector<std::string>& warnings() const { return warnings_; }

  /// Handle by column name ("GFI[1].grab_index") or scalar name (first occurrence).
  std::optional<field_handle> find(std::string_view name) const {
    auto it = by_name_.find(std::string(name));
    if (it == by_name_.end()) return std::nullopt;
    return handle(it->second);
  }
  field_handle handle(std::uint32_t i) const {
    const field& f = fields_[i];
    return field_handle{i, f.acc, f.st, f.fam, f.enums, f.sig.factor, f.sig.offset};
  }

  // ---- AUTOSAR signals -------------------------------------------------------------------
  /// Some field uses the signal keys (byte_order, factor, multiplexing, update bits, ...).
  bool has_signals() const { return has_signals_; }
  /// Some field is multiplexed or has an update bit (decode yields nullable columns).
  bool conditional() const { return conditional_; }
  /// Some field has factor/offset (decode can add physical columns).
  bool scaled() const { return scaled_; }
  /// Field i holds a value in `r`: its multiplexor selects it and its update bit (if any) is set.
  /// Always true for unconditional fields.
  bool valid(const record& r, std::uint32_t i) const {
    const field_signal& g = fields_[i].sig;
    if (g.update_bit && detail::extract(r.p_, g.update) == 0) return false;
    if (g.mux == field_signal::none) return true;
    const std::int64_t sel = std::int64_t(detail::extract(r.p_, fields_[g.mux].acc));
    for (auto v : g.mux_values)
      if (v == sel) return true;
    return false;
  }
  bool valid(const record& r, const field_handle& h) const { return valid(r, h.index); }

  // ---- encode (the inverse of decode): write signals into a PDU buffer --------------------
  /// Write raw bits (masked to the width) into `pdu` without any check except nothing: the
  /// caller guarantees pdu.size() >= stride(). Other bits are preserved. The fastest path.
  void set_bits_unchecked(const field_handle& h, std::span<std::byte> pdu, std::uint64_t bits) const {
    detail::insert(pdu.data(), h.acc, bits);
    const field_signal& g = fields_[h.index].sig;
    if (g.update_bit) detail::insert(pdu.data(), g.update, 1);
  }
  /// Write a raw (integer) value. Errors: buffer shorter than stride(), value outside the
  /// field's raw range ([0, 2^w-1] unsigned, [-2^(w-1), 2^(w-1)-1] signed). Floats: use set().
  lresult<bool> set_raw(const field_handle& h, std::span<std::byte> pdu, std::int64_t raw) const;
  lresult<bool> set_raw_unsigned(const field_handle& h, std::span<std::byte> pdu, std::uint64_t raw) const;
  /// Write a physical value: raw = round((physical - offset) / factor), ties away from zero
  /// (std::llround); IEEE float signals store (physical - offset) / factor as float/double.
  /// Errors: not finite, outside [min, max] (when given), raw outside the raw range.
  /// Sets the field's update bit, if it has one.
  lresult<bool> set(const field_handle& h, std::span<std::byte> pdu, double physical) const;
  /// The raw value set() would write for `physical` (validated), without writing. A negative
  /// signed signal comes back sign-extended to 64 bits; set() masks it to the field width.
  lresult<std::uint64_t> to_raw(const field_handle& h, double physical) const;
  /// The raw bits set_raw() would write for `raw` (validated).
  lresult<std::uint64_t> raw_bits(const field_handle& h, std::int64_t raw) const;

  /// One value for encode(): physical (default) or raw.
  struct signal_value {
    field_handle h;
    double value = 0;
    bool raw = false;  ///< value is the raw integer (exact up to 2^53)
  };
  /// Validate every value first (ranges; a multiplexed signal needs its multiplexor -- given in
  /// `values` or already in `pdu` -- to select it), then write them all; on error `pdu` is unchanged.
  lresult<bool> encode(std::span<const signal_value> values, std::span<std::byte> pdu) const;
  lresult<bool> encode(std::initializer_list<signal_value> values, std::span<std::byte> pdu) const {
    return encode(std::span<const signal_value>(values.begin(), values.size()), pdu);
  }

  /// Every field.
  selection all() const {
    selection s;
    s.fields.resize(fields_.size());
    for (std::uint32_t i = 0; i < s.fields.size(); ++i) s.fields[i] = i;
    return s;
  }
  /// Fields whose scalar name or column name matches any pattern (see name_matches), in plan
  /// order. A pattern that matches nothing is an error (typos should not silently select nothing).
  lresult<selection> select(std::span<const std::string> patterns) const {
    selection s;
    std::vector<bool> hit(patterns.size());
    for (std::uint32_t i = 0; i < fields_.size(); ++i) {
      bool any = false;
      for (std::size_t p = 0; p < patterns.size(); ++p)
        if (name_matches(patterns[p], fields_[i].name) || name_matches(patterns[p], fields_[i].column)) {
          any = true;
          hit[p] = true;
        }
      if (any) s.fields.push_back(i);
    }
    for (std::size_t p = 0; p < patterns.size(); ++p)
      if (!hit[p]) return lfail(raw_file_, 0, 0, "selection \"" + patterns[p] + "\" matches no scalar");
    return s;
  }
  lresult<selection> select(std::initializer_list<std::string> patterns) const {
    std::vector<std::string> v(patterns);
    return select(std::span<const std::string>(v));
  }

  /// The whole records in `data` (zero-copy).
  record_set records(std::span<const std::byte> data) const { return record_set(data, stride_); }
  /// One record viewed over `bytes` (nullopt unless it holds at least stride() bytes).
  std::optional<record> view(std::span<const std::byte> bytes) const {
    if (bytes.size() < stride_) return std::nullopt;
    return record(bytes.data(), stride_);
  }

  /// The output tree: node 0 is the root object.
  std::span<const tree_node> tree() const { return tree_; }

 private:
  std::string raw_file_;
  std::vector<field> fields_;
  std::size_t stride_ = 0, used_bytes_ = 0, align_ = 1;
  std::endian order_ = std::endian::little;
  std::vector<tree_node> tree_;
  std::unordered_map<std::string, std::uint32_t> by_name_;
  std::vector<std::shared_ptr<const enum_table>> keep_;  ///< owns the enum tables fields point at
  std::vector<std::string> warnings_;
  bool has_signals_ = false, conditional_ = false, scaled_ = false;

  lresult<bool> build_tree(bool strict);
  lresult<bool> link_signals(const description& d);
  layout_error enc_error(const field_handle& h, std::string msg) const {
    return layout_error{raw_file_, fields_[h.index].line, 0, fields_[h.index].column + ": " + std::move(msg)};
  }
};

// ---------------------------------------------------------------------------
// compile
// ---------------------------------------------------------------------------

namespace detail {
constexpr std::uint8_t pow2_bytes(unsigned bits) {
  const unsigned b = (bits + 7) / 8;
  return b <= 1 ? 1 : b <= 2 ? 2 : b <= 4 ? 4 : 8;
}
}  // namespace detail

inline lresult<plan> plan::compile(const description& d, std::string_view raw_file,
                                   const enum_catalog* enums, const compile_options& o) {
  plan p;
  p.raw_file_ = std::string(raw_file);
  p.order_ = o.order;
  const auto scalars = d.of(raw_file);
  if (scalars.empty()) {
    std::string known;
    for (const auto& f : d.raw_files) known += "\n  " + f;
    return lfail(d.source, 0, 0, "no scalars for raw_file \"" + std::string(raw_file) +
                                     "\"; the description has:" + known);
  }
  std::uint64_t end_bits = 0;
  std::optional<std::uint64_t> pdu_length;
  for (const scalar_desc* s : scalars) {
    field f;
    f.name = s->name;
    f.type = s->type;
    f.bit_offset = s->bit_offset;
    f.bit_width = s->bit_width;
    f.fam = s->ti.fam;
    f.line = s->line;
    f.enum_ref = s->ti.enum_ref;
    const unsigned w = s->bit_width;
    f.linear_offset = s->linear_offset();
    const bool natural = f.linear_offset % 8 == 0 && (w == 8 || w == 16 || w == 32 || w == 64);
    // C rule: a plain member aligns to its own size; a bit-field to its declared type's size.
    // An enum bit-field's declared type is the enum's underlying int (4 bytes with GCC).
    f.align = natural ? std::uint8_t(w / 8)
              : s->ti.size ? std::uint8_t(std::min<unsigned>(s->ti.size, 8))
              : f.fam == family::enumeration ? std::uint8_t(4) : detail::pow2_bytes(w);
    if (f.align != 1 && f.align != 2 && f.align != 4 && f.align != 8) f.align = detail::pow2_bytes(8u * f.align);
    const std::uint8_t sz = detail::pow2_bytes(w);
    bool sign = false;
    if (f.fam == family::enumeration && enums) {
      if (auto t = enums->find(raw_file, f.enum_ref)) {
        f.enums = t.get();
        p.keep_.push_back(std::move(t));
      }
    }
    switch (f.fam) {
      case family::floating: f.st = w == 32 ? storage::f32 : storage::f64; break;
      case family::boolean: f.st = storage::boolean; break;
      case family::signed_int: sign = true; break;
      // enums are signed (-1 = UNDEF is common); an enum BIT-FIELD is signed only if the enum has
      // a negative value — GCC gives an enum without negatives an unsigned underlying type.
      case family::enumeration:
        sign = s->sig.is_signed ? *s->sig.is_signed : natural || (f.enums && f.enums->has_negative());
        break;
      default: break;
    }
    if (f.fam != family::floating && f.fam != family::boolean) {
      static constexpr storage us[] = {storage::u8, storage::u16, storage::u32, storage::u64};
      static constexpr storage ss[] = {storage::i8, storage::i16, storage::i32, storage::i64};
      const int k = sz == 1 ? 0 : sz == 2 ? 1 : sz == 4 ? 2 : 3;
      f.st = sign ? ss[k] : us[k];
    }
    f.acc.sign = sign;
    f.acc.width = std::uint8_t(w);
    f.acc.be = s->sig.order == byte_order::motorola ? true
               : s->sig.order == byte_order::intel  ? false
                                                    : o.order == std::endian::big;
    end_bits = std::max(end_bits, f.linear_offset + w);
    if (s->sig.update_bit) end_bits = std::max(end_bits, *s->sig.update_bit + 1);
    if (s->sig.pdu_length) {
      if (pdu_length && *pdu_length != *s->sig.pdu_length)
        return lfail(d.source, s->line, 0, "pdu_length " + std::to_string(*s->sig.pdu_length) +
                                               " disagrees with pdu_length " + std::to_string(*pdu_length) +
                                               " given earlier for \"" + p.raw_file_ + "\"");
      pdu_length = s->sig.pdu_length;
    }
    p.align_ = std::max<std::size_t>(p.align_, f.align);
    p.fields_.push_back(std::move(f));
  }
  p.used_bytes_ = std::size_t((end_bits + 7) / 8);
  std::uint64_t stride = pdu_length ? *pdu_length : (p.used_bytes_ + p.align_ - 1) / p.align_ * p.align_;
  if (auto it = o.stride_by_file.find(raw_file); it != o.stride_by_file.end()) stride = it->second;
  else if (o.stride) stride = *o.stride;
  if (stride < p.used_bytes_)
    return lfail(d.source, 0, 0, "stride " + std::to_string(stride) + " for \"" + p.raw_file_ +
                                     "\" is smaller than the " + std::to_string(p.used_bytes_) +
                                     " bytes its fields cover");
  if (stride > o.max_record_bytes)
    return lfail(d.source, 0, 0, "stride " + std::to_string(stride) + " exceeds the record size limit");
  p.stride_ = std::size_t(stride);

  // Per-field load: the narrowest single load that the stride allows.
  const auto proven = [&](const detail::access& a) {  // the invariant every unchecked read relies on
    return std::uint64_t(a.off) + a.load_bytes() <= p.stride_ &&
           a.sh + (a.m == detail::mode::bits64 ? a.width : 0) <= 64;
  };
  for (field& f : p.fields_) {
    const bool sign = f.acc.sign, be = f.acc.be;
    f.acc = detail::make_access(f.linear_offset, f.bit_width, be, p.stride_);
    f.acc.sign = sign;
    if (!proven(f.acc))
      return lfail(d.source, f.line, 0, "internal: field \"" + f.name + "\" load leaves the record");
  }
  for (std::size_t i = 0; i < scalars.size(); ++i) {
    const signal_desc& g = scalars[i]->sig;
    field_signal& fs = p.fields_[i].sig;
    fs.order = g.order;
    fs.factor = g.factor;
    fs.offset = g.offset;
    fs.scaled = g.scaled;
    fs.unit = g.unit;
    fs.min = g.min;
    fs.max = g.max;
    fs.multiplexor = g.multiplexor;
    fs.mux_values = g.mux_values;
    fs.mux_signal = g.mux_signal;
    fs.update_bit = g.update_bit;
    fs.any = g.any;
    if (g.update_bit) {
      fs.update = detail::make_access(*g.update_bit, 1, false, p.stride_);
      if (!proven(fs.update))
        return lfail(d.source, p.fields_[i].line, 0, "internal: update bit load leaves the record");
    }
    p.has_signals_ |= g.any;
    p.scaled_ |= g.scaled;
  }

  // Occurrences of repeated names, in (bit_offset, line) order.
  {
    std::unordered_map<std::string_view, std::vector<std::uint32_t>> groups;
    for (std::uint32_t i = 0; i < p.fields_.size(); ++i) groups[p.fields_[i].name].push_back(i);
    for (auto& [_, g] : groups) {
      std::sort(g.begin(), g.end(), [&](auto a, auto b) {
        const auto& fa = p.fields_[a]; const auto& fb = p.fields_[b];
        return fa.bit_offset != fb.bit_offset ? fa.bit_offset < fb.bit_offset : fa.line < fb.line;
      });
      for (std::uint32_t k = 0; k < g.size(); ++k) {
        p.fields_[g[k]].occurrence = k;
        p.fields_[g[k]].occurrences = std::uint32_t(g.size());
      }
    }
  }
  auto t = p.build_tree(o.strict);
  if (!t) return unexpected<layout_error>(t.error());
  if (p.has_signals_) {
    auto l = p.link_signals(d);
    if (!l) return unexpected<layout_error>(l.error());
  }
  for (std::uint32_t i = 0; i < p.fields_.size(); ++i) {
    p.by_name_.emplace(p.fields_[i].column, i);
    if (p.fields_[i].occurrence == 0) p.by_name_.emplace(p.fields_[i].name, i);
  }
  return p;
}

// Multiplexed signals -> their multiplexor's field index.
inline lresult<bool> plan::link_signals(const description& d) {
  std::vector<std::uint32_t> muxes;
  for (std::uint32_t i = 0; i < fields_.size(); ++i)
    if (fields_[i].sig.multiplexor) muxes.push_back(i);
  for (field& f : fields_) {
    field_signal& g = f.sig;
    if (g.mux_values.empty()) continue;
    const std::string& want = g.mux_signal;
    std::uint32_t m = field_signal::none;
    if (want.empty()) {
      if (muxes.size() != 1)
        return lfail(d.source, f.line, 0,
                     "multiplexed signal \"" + f.name + "\" needs \"mux_signal\": \"" + raw_file_ + "\" has " +
                         std::to_string(muxes.size()) + " multiplexor signals");
      m = muxes[0];
    } else {
      for (std::uint32_t i = 0; i < fields_.size(); ++i)
        if (fields_[i].name == want || fields_[i].column == want) { m = i; break; }
      if (m == field_signal::none)
        return lfail(d.source, f.line, 0, "mux_signal \"" + want + "\" is not a signal of \"" + raw_file_ + "\"");
      if (!fields_[m].sig.mux_values.empty())
        return lfail(d.source, f.line, 0, "mux_signal \"" + want + "\" is itself multiplexed (nested multiplexing is not supported)");
      if (fields_[m].fam == family::floating)
        return lfail(d.source, f.line, 0, "mux_signal \"" + want + "\" is a float");
      fields_[m].sig.multiplexor = true;
    }
    g.mux = m;
  }
  for (const field& f : fields_) conditional_ |= f.sig.conditional();
  return true;
}

namespace detail {
/// [lo, hi] of a field's raw integer values.
inline std::pair<std::int64_t, std::uint64_t> raw_range(const field& f, bool& is_signed) {
  const unsigned w = f.bit_width;
  is_signed = f.acc.sign;
  if (is_signed) {
    const std::int64_t lo = w >= 64 ? std::numeric_limits<std::int64_t>::min() : -(std::int64_t(1) << (w - 1));
    return {lo, w >= 64 ? std::uint64_t(std::numeric_limits<std::int64_t>::max()) : (std::uint64_t(1) << (w - 1)) - 1};
  }
  return {0, w >= 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << w) - 1};
}
inline std::string num_text(double v) {
  char b[40];
  auto r = std::to_chars(b, b + sizeof b, v);
  return std::string(b, r.ptr);
}
}  // namespace detail

inline lresult<std::uint64_t> plan::raw_bits(const field_handle& h, std::int64_t raw) const {
  const field& f = fields_[h.index];
  if (f.fam == family::floating) return unexpected<layout_error>(enc_error(h, "float signal: use set() with a value"));
  bool sg = false;
  const auto [lo, hi] = detail::raw_range(f, sg);
  const bool bad = sg ? (raw < lo || (raw > 0 && std::uint64_t(raw) > hi)) : (raw < 0 || std::uint64_t(raw) > hi);
  if (bad)
    return unexpected<layout_error>(enc_error(h, "raw value " + std::to_string(raw) + " outside [" +
                                                     std::to_string(lo) + ", " + std::to_string(hi) + "]"));
  return std::uint64_t(raw);
}

inline lresult<bool> plan::set_raw(const field_handle& h, std::span<std::byte> pdu, std::int64_t raw) const {
  if (pdu.size() < stride_)
    return unexpected<layout_error>(enc_error(h, "PDU buffer of " + std::to_string(pdu.size()) +
                                                     " bytes is shorter than " + std::to_string(stride_)));
  auto b = raw_bits(h, raw);
  if (!b) return unexpected<layout_error>(b.error());
  set_bits_unchecked(h, pdu, *b);
  return true;
}

inline lresult<bool> plan::set_raw_unsigned(const field_handle& h, std::span<std::byte> pdu, std::uint64_t raw) const {
  const field& f = fields_[h.index];
  if (f.acc.sign || f.fam == family::floating) {
    if (raw > std::uint64_t(std::numeric_limits<std::int64_t>::max()))
      return unexpected<layout_error>(enc_error(h, "raw value " + std::to_string(raw) + " out of range"));
    return set_raw(h, pdu, std::int64_t(raw));
  }
  if (pdu.size() < stride_)
    return unexpected<layout_error>(enc_error(h, "PDU buffer shorter than the stride"));
  bool sg = false;
  const auto hi = detail::raw_range(f, sg).second;
  if (raw > hi)
    return unexpected<layout_error>(enc_error(h, "raw value " + std::to_string(raw) + " outside [0, " + std::to_string(hi) + "]"));
  set_bits_unchecked(h, pdu, raw);
  return true;
}

inline lresult<std::uint64_t> plan::to_raw(const field_handle& h, double physical) const {
  const field& f = fields_[h.index];
  const field_signal& g = f.sig;
  if (!std::isfinite(physical)) return unexpected<layout_error>(enc_error(h, "value is not finite"));
  if ((g.min && physical < *g.min) || (g.max && physical > *g.max))
    return unexpected<layout_error>(enc_error(h, "physical value " + detail::num_text(physical) + " outside [" +
                                                     detail::num_text(g.min.value_or(-INFINITY)) + ", " +
                                                     detail::num_text(g.max.value_or(INFINITY)) + "]"));
  const double r = (physical - g.offset) / g.factor;
  if (f.fam == family::floating) {
    if (f.bit_width == 32) {
      if (std::isfinite(r) && std::abs(r) > double(std::numeric_limits<float>::max()))
        return unexpected<layout_error>(enc_error(h, "value overflows float"));
      return std::uint64_t(std::bit_cast<std::uint32_t>(float(r)));
    }
    return std::bit_cast<std::uint64_t>(r);
  }
  // round half away from zero, then range-check the integer
  bool sg = false;
  const auto [lo, hi] = detail::raw_range(f, sg);
  const double rr = std::round(r);
  const bool bad = !std::isfinite(rr) || (sg ? (rr < double(lo) || rr > double(hi)) : (rr < 0 || rr > double(hi)));
  if (bad)
    return unexpected<layout_error>(enc_error(h, "physical value " + detail::num_text(physical) + " -> raw " +
                                                     detail::num_text(rr) + " outside [" + std::to_string(lo) +
                                                     ", " + std::to_string(hi) + "]"));
  // double(hi) may round up to 2^w: re-check exactly in the integer domain
  if (sg) {
    if (rr >= 9.2233720368547758e18) return unexpected<layout_error>(enc_error(h, "raw value out of range"));
    const auto v = std::int64_t(rr);
    if (v < lo || (v > 0 && std::uint64_t(v) > hi)) return unexpected<layout_error>(enc_error(h, "raw value out of range"));
    return std::uint64_t(v);
  }
  if (rr >= 1.8446744073709552e19) return unexpected<layout_error>(enc_error(h, "raw value out of range"));
  const auto v = std::uint64_t(rr);
  if (v > hi) return unexpected<layout_error>(enc_error(h, "raw value out of range"));
  return v;
}

inline lresult<bool> plan::set(const field_handle& h, std::span<std::byte> pdu, double physical) const {
  if (pdu.size() < stride_)
    return unexpected<layout_error>(enc_error(h, "PDU buffer of " + std::to_string(pdu.size()) +
                                                     " bytes is shorter than " + std::to_string(stride_)));
  auto b = to_raw(h, physical);
  if (!b) return unexpected<layout_error>(b.error());
  set_bits_unchecked(h, pdu, *b);
  return true;
}

inline lresult<bool> plan::encode(std::span<const signal_value> values, std::span<std::byte> pdu) const {
  if (pdu.size() < stride_)
    return lfail(raw_file_, 0, 0, "encode: PDU buffer of " + std::to_string(pdu.size()) +
                                      " bytes is shorter than " + std::to_string(stride_));
  constexpr std::size_t kInline = 32;
  std::uint64_t small[kInline];
  std::vector<std::uint64_t> big;
  std::uint64_t* bits = small;
  if (values.size() > kInline) { big.resize(values.size()); bits = big.data(); }
  for (std::size_t i = 0; i < values.size(); ++i) {
    const signal_value& v = values[i];
    if (v.h.index >= fields_.size()) return lfail(raw_file_, 0, 0, "encode: handle of another plan");
    lresult<std::uint64_t> b = std::uint64_t(0);
    if (v.raw) {
      if (!(v.value == std::floor(v.value)) || std::abs(v.value) > 9.0e18)
        return unexpected<layout_error>(enc_error(v.h, "raw value " + detail::num_text(v.value) + " is not an integer"));
      b = fields_[v.h.index].fam == family::floating ? to_raw(v.h, v.value * fields_[v.h.index].sig.factor + fields_[v.h.index].sig.offset)
                                                     : raw_bits(v.h, std::int64_t(v.value));
    } else {
      b = to_raw(v.h, v.value);
    }
    if (!b) return unexpected<layout_error>(b.error());
    bits[i] = *b;
  }
  if (conditional_)
    for (std::size_t i = 0; i < values.size(); ++i) {
      const field_signal& g = fields_[values[i].h.index].sig;
      if (g.mux == field_signal::none) continue;
      std::optional<std::int64_t> sel;
      for (std::size_t j = 0; j < values.size(); ++j)  // the multiplexor among the values (last wins)
        if (values[j].h.index == g.mux) {
          const field& m = fields_[g.mux];
          const std::uint64_t x = bits[j];
          sel = m.acc.sign && m.bit_width < 64 ? std::int64_t(x << (64 - m.bit_width)) >> (64 - m.bit_width)
                                               : std::int64_t(x);
        }
      if (!sel) sel = std::int64_t(detail::extract(pdu.data(), fields_[g.mux].acc));
      if (std::find(g.mux_values.begin(), g.mux_values.end(), *sel) == g.mux_values.end())
        return unexpected<layout_error>(enc_error(values[i].h, "multiplexor \"" + fields_[g.mux].column +
                                                                   "\" = " + std::to_string(*sel) +
                                                                   " selects another signal group"));
    }
  for (std::size_t i = 0; i < values.size(); ++i) set_bits_unchecked(values[i].h, pdu, bits[i]);
  return true;
}

// Name tree: first a trie over the distinct names, then the output tree with implicit arrays
// (repeated names) and array_item_N arrays expanded.
inline lresult<bool> plan::build_tree(bool strict) {
  struct tnode {
    std::string comp;
    std::uint32_t parent = 0, depth = 0;
    std::vector<std::uint32_t> kids;
    std::unordered_map<std::string, std::uint32_t> by;
    std::vector<std::uint32_t> inst;  // field indices by occurrence
    std::uint32_t uniform = 0;
    bool rep = false;
  };
  std::vector<tnode> t(1);
  std::vector<std::uint32_t> leaf_of(fields_.size());
  for (std::uint32_t i = 0; i < fields_.size(); ++i) {
    const field& f = fields_[i];
    std::uint32_t cur = 0;
    for (auto c : split_name(f.name)) {
      if (c.empty()) {
        if (strict) return lfail(raw_file_, f.line, 0, "scalar_name \"" + f.name + "\" has an empty component");
      }
      auto it = t[cur].by.find(std::string(c));
      if (it == t[cur].by.end()) {
        tnode n;
        n.comp = std::string(c);
        n.parent = cur;
        n.depth = t[cur].depth + 1;
        t.push_back(std::move(n));
        const auto id = std::uint32_t(t.size() - 1);
        t[cur].kids.push_back(id);
        t[cur].by.emplace(t[id].comp, id);
        cur = id;
      } else cur = it->second;
    }
    leaf_of[i] = cur;
    auto& inst = t[cur].inst;
    if (inst.size() <= f.occurrence) inst.resize(f.occurrence + 1);
    inst[f.occurrence] = i;
  }
  for (std::uint32_t n = 1; n < t.size(); ++n)
    if (!t[n].inst.empty() && !t[n].kids.empty()) {
      const field& f = fields_[t[n].inst[0]];
      std::string msg = "\"" + f.name + "\" is both a scalar and the parent of other scalars";
      if (strict) return lfail(raw_file_, f.line, 0, msg + " (lenient mode emits it as \"_value\")");
      warnings_.push_back(msg);
    }
  // uniform repeat count of each subtree (0 = mixed), children before parents (ids grow downward)
  for (std::uint32_t n = std::uint32_t(t.size()); n-- > 1;) {
    std::uint32_t u = t[n].inst.empty() ? 0 : std::uint32_t(t[n].inst.size());
    bool first = t[n].inst.empty();
    for (auto k : t[n].kids) {
      if (first) { u = t[k].uniform; first = false; }
      else if (t[k].uniform != u) u = 0;
    }
    t[n].uniform = u;
  }
  for (std::uint32_t n = 1; n < t.size(); ++n)
    t[n].rep = t[n].uniform > 1 && (t[n].parent == 0 || t[t[n].parent].uniform != t[n].uniform);

  // column names: [k] after the implicit-array component
  for (std::uint32_t i = 0; i < fields_.size(); ++i) {
    field& f = fields_[i];
    if (f.occurrences == 1) { f.column = f.name; continue; }
    std::uint32_t n = leaf_of[i], rep_depth = 0;
    for (std::uint32_t c = n; c != 0; c = t[c].parent)
      if (t[c].rep) rep_depth = t[c].depth;
    std::string col;
    std::uint32_t depth = 0;
    for (auto c : split_name(f.name)) {
      if (depth) col += '.';
      col += c;
      if (++depth == rep_depth) col += '[' + std::to_string(f.occurrence) + ']';
    }
    if (rep_depth == 0) col += '[' + std::to_string(f.occurrence) + ']';  // (unreachable guard)
    f.column = std::move(col);
  }

  // expand
  tree_.clear();
  tree_.push_back(tree_node{});  // root object
  auto add = [&](tree_node n) { tree_.push_back(std::move(n)); return std::uint32_t(tree_.size() - 1); };
  // (recursive lambdas via a local struct)
  struct ex {
    std::vector<tnode>& t;
    std::vector<tree_node>& out;
    decltype(add)& mk;
    std::uint32_t node(std::uint32_t n, int inst) {
      if (t[n].rep && inst < 0) {
        const auto arr = mk(tree_node{tree_node::kind::array, {}, {}, 0});
        for (std::uint32_t k = 0; k < t[n].uniform; ++k) {
          const auto c = body(n, int(k));
          out[arr].children.push_back(c);
        }
        return arr;
      }
      return body(n, inst);
    }
    std::uint32_t body(std::uint32_t n, int inst) {
      const tnode& tn = t[n];
      if (tn.kids.empty()) {
        const std::size_t k = inst < 0 ? 0 : std::size_t(inst);
        return mk(tree_node{tree_node::kind::leaf, {}, {}, tn.inst[std::min(k, tn.inst.size() - 1)]});
      }
      bool all_items = tn.inst.empty();
      std::vector<std::pair<std::uint64_t, std::uint32_t>> items;
      for (auto k : tn.kids) {
        std::uint64_t idx;
        if (!detail::is_array_item(t[k].comp, &idx)) { all_items = false; break; }
        items.emplace_back(idx, k);
      }
      if (all_items) {
        std::sort(items.begin(), items.end());
        const auto arr = mk(tree_node{tree_node::kind::array, {}, {}, 0});
        std::uint64_t next = items.front().first;
        for (auto [idx, k] : items) {
          for (; next < idx; ++next) {  // gap: null
            const auto z = mk(tree_node{tree_node::kind::null, {}, {}, 0});
            out[arr].children.push_back(z);
          }
          const auto c = node(k, inst);
          out[arr].children.push_back(c);
          next = idx + 1;
        }
        return arr;
      }
      const auto obj = mk(tree_node{tree_node::kind::object, {}, {}, 0});
      if (!tn.inst.empty()) {  // lenient: scalar that is also a parent
        const std::size_t k = inst < 0 ? 0 : std::size_t(inst);
        const auto v = mk(tree_node{tree_node::kind::leaf, "_value", {}, tn.inst[std::min(k, tn.inst.size() - 1)]});
        out[obj].children.push_back(v);
      }
      for (auto k : tn.kids) {
        const auto c = node(k, inst);
        out[c].key = t[k].comp;
        out[obj].children.push_back(c);
      }
      return obj;
    }
  } e{t, tree_, add};
  for (auto k : t[0].kids) {
    const auto c = e.node(k, -1);
    tree_[c].key = t[k].comp;
    tree_[0].children.push_back(c);
  }
  return true;
}

}  // namespace nanom::layout

#endif
