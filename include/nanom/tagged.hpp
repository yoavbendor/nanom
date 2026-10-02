// SPDX-License-Identifier: Apache-2.0
// nanom/tagged.hpp — reflected TAGGED messages: self-describing, field-numbered wire formats
// (Thrift compact today; protobuf rides the same model next). An "extra", layered on reflect.hpp.
//
// reflect.hpp describes FIXED-LAYOUT structs: every field at a compile-time bit offset. Columnar file
// formats keep their metadata in TAGGED encodings instead — Parquet's footer and page headers are
// Thrift compact, Lance's manifests and page layouts are protobuf: each value is preceded by a field
// id + wire type, fields may be absent, repeated or unknown, and strings/lists are length-prefixed.
// This header gives those formats the same "the struct IS the schema" treatment:
//
//   struct KeyValue {
//     nm::field<1, std::string_view>                 key;     // required (absent = error)
//     nm::field<2, std::optional<std::string_view>>  value;   // optional (absent = nullopt)
//   };
//   NANOM_DESCRIBE(KeyValue, key, value);   // C++23; under C++26 reflection no registration at all
//
//   auto r = nm::thrift_compact<KeyValue>()(in);          // an ordinary nanom parser
//
// This header only READS. Writing the same model back (nm::thrift_compact_encode) lives in
// nanom/tagged_encode.hpp, which a reader never needs to include.
//
// The field id lives in the TYPE (field<Id, T>), exactly as endianness lives in be<>/le<> — so both
// describe<T> providers (the NANOM_DESCRIBE macro and C++26 P2996 reflection) work unchanged, and
// everything the codec needs is known at compile time:
//
//   * a field-id -> member dispatch table (dense array for ids < 256), built by consteval code;
//   * the expected wire type of every member: a field whose wire type does not match is never
//     reinterpreted — it is skipped like an unknown field (Apache Thrift's own semantics, which
//     real files rely on: old writers reused field ids with other types), and if the member is
//     required the message then fails the required-field check;
//   * the required-field bitmask, checked once when the struct's STOP byte arrives;
//   * id uniqueness / ascending order / ≤ 64 fields — static_asserts, not runtime surprises.
//
// Zero-copy: std::string_view and nm::bytes members point into the input buffer (same lifetime
// contract as every other nanom view; prefer nm::bytes under NANOM_GENERATION — it carries the
// attestation, a string_view cannot). nm::list<E> is a LAZY list (the validated element bytes +
// count; decode on iteration, no allocation) and nm::lazy<M> a lazily decoded nested struct — reading
// one row group out of a 10,000-row-group Parquet footer touches nothing else. std::vector<E> and
// std::string are accepted too when an owning copy is what you want.
//
// Hostile-input posture (all bounded, nothing allocates from a wire count before checking it):
//   * every list count is checked against the remaining bytes (count_fits) before any reserve;
//   * every length prefix is checked against the remaining bytes before any span is formed;
//   * nesting depth (struct-in-list-in-struct…) is capped at max_tagged_depth, for decode and skip;
//   * integers are range-checked into the member's width (an i64 on the wire into an int32_t member
//     is an error, never a silent truncation);
//   * unknown fields are skipped structurally (forward compatibility) under the same limits.
#ifndef NANOM_TAGGED_HPP_INCLUDED
#define NANOM_TAGGED_HPP_INCLUDED

#include "reflect.hpp"

namespace nanom {

// ---------------------------------------------------------------------------
// 24. the tagged-message model (codec-independent)
// ---------------------------------------------------------------------------

/// Nesting cap for tagged decoding and skipping (Thrift's own reference implementation uses 64).
#ifndef NANOM_TAGGED_MAX_DEPTH
#define NANOM_TAGGED_MAX_DEPTH 64
#endif
inline constexpr int max_tagged_depth = NANOM_TAGGED_MAX_DEPTH;

/// What happens when a field does not appear on the wire.
///   required  — the message is rejected (Thrift `required`, and the safe default)
///   defaulted — the member keeps its value-initialized default (Thrift default-requiredness,
///               proto3 implicit presence)
/// A field whose type is std::optional<T> is always optional (absent = nullopt), whatever P says.
enum class presence : std::uint8_t { required, defaulted };

/// One field of a tagged message: the wire field id + the value type, in the type.
template <std::uint16_t Id, class T, presence P = presence::required>
struct field {
  static_assert(Id >= 1 && Id <= 32767, "nanom::field: ids are 1..32767 (Thrift i16, positive)");
  using value_type = T;
  static constexpr std::uint16_t id = Id;
  static constexpr presence      pres = P;

  T v{};

  constexpr field() = default;
  constexpr field(T x) : v(std::move(x)) {}
  /// Anything T is constructible from (so `f.opt_int = 3;` and `f.name = "x"sv;` read naturally).
  template <class U>
    requires(!std::is_same_v<std::remove_cvref_t<U>, field> && !std::is_same_v<std::remove_cvref_t<U>, T> &&
             std::is_constructible_v<T, U &&>)
  constexpr field(U&& u) : v(std::forward<U>(u)) {}
  constexpr T&       operator*()        { return v; }
  constexpr const T& operator*()  const { return v; }
  constexpr T*       operator->()       { return &v; }
  constexpr const T* operator->() const { return &v; }
  constexpr const T& get()        const { return v; }
  constexpr operator const T&()   const { return v; }
};

/// Thrift `struct Foo {}` (Parquet's StringType, DateType, MilliSeconds, …): no members to reflect.
/// Decoding validates (and skips) whatever fields a newer writer put inside.
struct empty_struct {
  constexpr bool operator==(const empty_struct&) const = default;
};

enum class tagged_wire : std::uint8_t { thrift_compact };

template <class E> class list;
template <class M> class lazy;

namespace detail {
template <class T> struct is_field_t : std::false_type {};
template <std::uint16_t I, class T, presence P> struct is_field_t<field<I, T, P>> : std::true_type {};
template <class T> struct is_optional_t : std::false_type {};
template <class T> struct is_optional_t<std::optional<T>> : std::true_type {};
template <class T> struct unwrap_optional { using type = T; };
template <class T> struct unwrap_optional<std::optional<T>> { using type = T; };
template <class T> using unwrap_optional_t = typename unwrap_optional<T>::type;
template <class T> struct is_vector_t : std::false_type {};
template <class T, class A> struct is_vector_t<std::vector<T, A>> : std::true_type {};
template <class T> struct is_list_t : std::false_type {};
template <class T> struct is_list_t<list<T>> : std::true_type {};
template <class T> struct is_lazy_t : std::false_type {};
template <class T> struct is_lazy_t<lazy<T>> : std::true_type {};

template <class T>
consteval bool all_members_are_fields() {
  bool ok = true;
  for_each_field<T>([&](auto f) { ok = ok && is_field_t<member_t<decltype(f)::mem_ptr>>::value; });
  return ok;
}
}  // namespace detail

/// A tagged message: a described struct whose every member is a nanom::field<>.
template <class T>
concept Message = Described<T> && detail::all_members_are_fields<std::remove_cv_t<T>>();

namespace detail {
template <class M>
using fields_tuple_t = decltype(describe<M>::fields());
template <class M, std::size_t I>
using field_at_t = member_t<std::tuple_element_t<I, fields_tuple_t<M>>::mem_ptr>;

/// Compile-time facts about a message, computed once per type.
template <class M>
struct message_info {
  static constexpr std::size_t n = std::tuple_size_v<fields_tuple_t<M>>;
  static_assert(n <= 64, "nanom: a tagged message may have at most 64 fields");

  static consteval std::array<std::uint16_t, n> make_ids() {
    std::array<std::uint16_t, n> a{};
    std::size_t i = 0;
    for_each_field<M>([&](auto f) { a[i++] = member_t<decltype(f)::mem_ptr>::id; });
    return a;
  }
  static constexpr std::array<std::uint16_t, n> ids = make_ids();

  static consteval bool ascending() {
    for (std::size_t i = 1; i < n; ++i)
      if (ids[i] <= ids[i - 1]) return false;
    return true;
  }
  static_assert(ascending(),
                "nanom: tagged message fields must be declared (and registered) with strictly "
                "ascending, unique ids");

  static consteval std::uint64_t make_required_mask() {
    std::uint64_t m = 0;
    std::size_t i = 0;
    for_each_field<M>([&](auto f) {
      using F = member_t<decltype(f)::mem_ptr>;
      if (F::pres == presence::required && !is_optional_t<typename F::value_type>::value)
        m |= std::uint64_t(1) << i;
      ++i;
    });
    return m;
  }
  static constexpr std::uint64_t required_mask = make_required_mask();

  static constexpr std::uint16_t max_id = n ? ids[n - 1] : 0;
  static constexpr bool dense = max_id < 256;
  static constexpr std::uint8_t no_slot = 0xff;
  static consteval auto make_slots() {
    std::array<std::uint8_t, dense ? std::size_t(max_id) + 1 : 1> s{};
    for (auto& x : s) x = no_slot;
    if constexpr (dense)
      for (std::size_t i = 0; i < n; ++i) s[ids[i]] = std::uint8_t(i);
    return s;
  }
  static constexpr auto slots = make_slots();

  /// Member index for a wire id, or no_slot (unknown field -> skipped).
  static constexpr std::uint8_t slot_of(std::int32_t id) {
    if (id < 0) return no_slot;
    if constexpr (dense) {
      return std::size_t(id) < slots.size() ? slots[std::size_t(id)] : no_slot;
    } else {
      for (std::size_t i = 0; i < n; ++i)  // sorted ids: binary search is no faster at n <= 64
        if (ids[i] == id) return std::uint8_t(i);
      return no_slot;
    }
  }
};

/// Call f(std::integral_constant<std::size_t, I>) for the I == idx; returns f's bool result
/// (false when idx is out of range). One runtime switch into fully specialized per-field code.
template <class M, class F>
constexpr bool with_field_index(std::size_t idx, F&& f) {
  return [&]<std::size_t... I>(std::index_sequence<I...>) {
    bool ok = false;
    (void)((idx == I ? (ok = f(std::integral_constant<std::size_t, I>{}), true) : false) || ...);
    return ok;
  }(std::make_index_sequence<message_info<M>::n>{});
}
}  // namespace detail

/// A lazily decoded list: the validated element bytes, the element count, and the element wire
/// type. Iteration decodes each element in place; nothing is allocated. The bytes are a view into
/// the input buffer (same lifetime contract as nm::bytes).
template <class E>
class list {
 public:
  using value_type = E;
  constexpr list() = default;
  constexpr list(input region, std::uint32_t count, std::uint8_t elem_wire, std::uint8_t depth,
                 tagged_wire w = tagged_wire::thrift_compact)
      : region_(region), count_(count), elem_wire_(elem_wire), depth_(depth), wire_(w) {}

  /// A list to WRITE (see nanom/tagged_encode.hpp): a view of the caller's elements, which must
  /// outlive it. It iterates, indexes and copies exactly like a decoded list.
  static constexpr list of(std::span<const E> elems) {
    list l;
    l.src_ = elems.data();
    l.src_n_ = elems.size();
    l.src_mode_ = true;
    return l;
  }
  /// True for a list made with of() (elements in memory), false for one decoded from the wire.
  constexpr bool          is_source() const { return src_mode_; }
  constexpr std::span<const E> source() const { return {src_, src_n_}; }

  constexpr std::size_t   size()      const { return src_mode_ ? src_n_ : count_; }
  constexpr bool          empty()     const { return size() == 0; }
  constexpr input         region()    const { return region_; }
  constexpr std::uint8_t  elem_wire() const { return elem_wire_; }

  /// Visit every element in order: f(E) (or f(E) -> bool; returning false stops early).
  template <class F>
  constexpr expected<unit, error> for_each(F&& f) const;
  /// Decode element i (O(i): earlier elements are skipped, not decoded).
  constexpr expected<E, error> at(std::size_t i) const;
  /// Owning copy of every element.
  constexpr expected<std::vector<E>, error> to_vector() const {
    if (src_mode_) return std::vector<E>(src_, src_ + src_n_);
    std::vector<E> out;
    out.reserve(count_);
    auto st = for_each([&](E e) { out.push_back(std::move(e)); });
    if (!st) return unexpected<error>(st.error());
    return out;
  }

 private:
  input         region_{};
  std::uint32_t count_     = 0;
  std::uint8_t  elem_wire_ = 0;
  std::uint8_t  depth_     = 0;
  tagged_wire   wire_      = tagged_wire::thrift_compact;
  bool          src_mode_  = false;  ///< of(): elements in memory, not on the wire
  const E*      src_       = nullptr;
  std::size_t   src_n_     = 0;
};

/// A nested message decoded on demand: holds the struct's (structurally validated) bytes.
template <class M>
class lazy {
 public:
  using value_type = M;
  constexpr lazy() = default;
  constexpr lazy(input region, std::uint8_t depth, tagged_wire w = tagged_wire::thrift_compact)
      : region_(region), depth_(depth), wire_(w) {}
  /// A nested message to WRITE (see nanom/tagged_encode.hpp): a view of the caller's message,
  /// which must outlive it. decode() returns a copy of it.
  static constexpr lazy of(const M& m) {
    lazy l;
    l.src_ = &m;
    return l;
  }
  constexpr const M* source() const { return src_; }
  constexpr input region() const { return region_; }
  /// Neither decoded from the wire nor set with of().
  constexpr bool  empty()  const { return region_.empty() && src_ == nullptr; }
  /// Decode the full message now.
  constexpr expected<M, error> decode() const;

 private:
  input        region_{};
  std::uint8_t depth_ = 0;
  tagged_wire  wire_  = tagged_wire::thrift_compact;
  const M*     src_   = nullptr;  ///< of(): the message in memory
};

// ---------------------------------------------------------------------------
// 25. Thrift compact protocol — decode + encode
// ---------------------------------------------------------------------------
//
// Wire summary (Apache Thrift compact protocol spec):
//   field header : (delta << 4) | type when the id delta is 1..15, else type byte + zigzag-varint i16 id
//   bool field   : value IS the header type (1 = true, 2 = false); in a list it is one byte
//   i8           : one byte;  i16/i32/i64 : zigzag varint;  double : 8 bytes little-endian
//   binary/string: varint length + bytes
//   list/set     : (size << 4) | elem_type when size < 15, else 0xF0 | elem_type + varint size
//   map          : varint size, then (key_type << 4) | value_type when size > 0
//   struct       : fields until a STOP (0x00) byte

namespace thrift {
enum class ctype : std::uint8_t {
  stop = 0, bool_true = 1, bool_false = 2, i8 = 3, i16 = 4, i32 = 5, i64 = 6, dbl = 7,
  binary = 8, list = 9, set = 10, map = 11, strct = 12
};
}  // namespace thrift

namespace detail::tc {

using thrift::ctype;

template <class> inline constexpr bool always_false = false;

/// The compact wire type a member type is carried as.
template <class T>
consteval std::uint8_t type_of() {
  if constexpr (is_optional_t<T>::value)                return type_of<typename T::value_type>();
  else if constexpr (std::is_same_v<T, bool>)           return std::uint8_t(ctype::bool_true);
  else if constexpr (std::is_same_v<T, std::int8_t>)    return std::uint8_t(ctype::i8);
  else if constexpr (std::is_same_v<T, std::int16_t>)   return std::uint8_t(ctype::i16);
  else if constexpr (std::is_same_v<T, std::int32_t>)   return std::uint8_t(ctype::i32);
  else if constexpr (std::is_same_v<T, std::int64_t>)   return std::uint8_t(ctype::i64);
  else if constexpr (std::is_same_v<T, double>)         return std::uint8_t(ctype::dbl);
  else if constexpr (std::is_enum_v<T>) {
    static_assert(sizeof(T) == 4 && std::is_signed_v<std::underlying_type_t<T>>,
                  "nanom thrift: enums travel as i32 — give the enum an int32_t underlying type");
    return std::uint8_t(ctype::i32);
  }
  else if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string> ||
                     std::is_same_v<T, bytes>)
    return std::uint8_t(ctype::binary);
  else if constexpr (is_vector_t<T>::value || is_list_t<T>::value) return std::uint8_t(ctype::list);
  else if constexpr (Message<T> || is_lazy_t<T>::value || std::is_same_v<T, empty_struct>)
    return std::uint8_t(ctype::strct);
  else static_assert(always_false<T>,
                     "nanom thrift: unsupported member type (Thrift has no unsigned integers or "
                     "float; use int8/16/32/64_t, double, bool, int32 enums, string_view/string/"
                     "bytes, nm::list/std::vector, nested messages, nm::lazy, nm::empty_struct)");
}

/// Does a wire type satisfy the member's expected type? (bool: 1 or 2; list members take sets too)
constexpr bool wire_ok(std::uint8_t expected, std::uint8_t wire) {
  if (expected == std::uint8_t(ctype::bool_true))
    return wire == std::uint8_t(ctype::bool_true) || wire == std::uint8_t(ctype::bool_false);
  if (expected == std::uint8_t(ctype::list))
    return wire == std::uint8_t(ctype::list) || wire == std::uint8_t(ctype::set);
  return wire == expected;
}

/// Smallest encoding of one element of a wire type (drives the hostile-count check).
constexpr std::size_t min_elem_bytes(std::uint8_t t) {
  return t == std::uint8_t(ctype::dbl) ? 8 : 1;
}

// ---- decoder ------------------------------------------------------------------------------------
//
// The hot loops run on raw [p, e) byte pointers with ONE fault slot per decode (ctx), instead of
// threading an expected<done<T>, error> through every byte: a Thrift footer is millions of tiny
// values, and the per-value result plumbing dominated the cost. Nothing here is less checked —
// every read is bounds-checked against e, every count and length against the bytes left — the
// error is just built once, at the API boundary (ctx::to_error), from the recorded fault.

enum class fault : std::uint8_t {
  none, truncated, bad_varint, out_of_range, bad_type, type_mismatch, too_deep, bad_count,
  bad_bool, bad_id, missing_required
};

struct ctx {
  input            origin;            ///< the input the decode started from (base, arena, live)
  const std::byte* at    = nullptr;   ///< where the first fault happened
  fault            f     = fault::none;
  std::uint32_t    need  = 0;         ///< for truncated: bytes known to be missing (0 = unknown)
  const char*      where = nullptr;   ///< message name for missing_required

  constexpr bool fail(fault k, const std::byte* p, std::size_t needed = 0) {
    if (f == fault::none) {
      f = k;
      at = p;
      need = std::uint32_t(std::min<std::size_t>(needed, max_incomplete_needed));
    }
    return false;
  }
  constexpr error to_error() const {
    error e;
    e.offset = std::uint32_t(at && origin.base ? std::size_t(at - origin.base) : origin.offset());
    switch (f) {
      case fault::truncated:
        e.kind = origin.live ? errk::incomplete : errk::err;
        e.expected = "more input";
        e.needed = need;
        break;
      case fault::bad_varint:       e.expected = "varint fitting the target width"; break;
      case fault::out_of_range:     e.expected = "integer within the member's range"; break;
      case fault::bad_type:         e.expected = "a valid thrift compact type"; break;
      case fault::type_mismatch:    e.expected = "thrift wire type matching the member's type"; break;
      case fault::too_deep:         e.expected = "thrift nesting within the depth limit"; break;
      case fault::bad_count:        e.expected = "thrift list/map count that fits the remaining bytes"; break;
      case fault::bad_bool:         e.expected = "thrift bool element (0, 1 or 2)"; break;
      case fault::bad_id:           e.expected = "thrift field id within i16"; break;
      case fault::missing_required: e.expected = "every required thrift field"; break;
      case fault::none:             e.expected = "(no fault)"; break;
    }
    if (f == fault::missing_required && where) e.push_context(where, e.offset);
    return e;
  }
};

using ptr = const std::byte*;

constexpr std::uint8_t u8at(ptr p) { return std::uint8_t(*p); }

/// ULEB128 into u64. Fast path: with ≥ 10 bytes left no per-byte bounds check is needed.
constexpr bool varint(ctx& c, ptr& p, ptr e, std::uint64_t& v) {
  const ptr s = p;
  if (e - p >= 10) {
    std::uint64_t b = u8at(p);
    if (b < 0x80) { v = b; p += 1; return true; }
    std::uint64_t r = b & 0x7f;
    for (int i = 1; i < 10; ++i) {
      b = u8at(p + i);
      r |= (b & 0x7f) << (7 * i);
      if (b < 0x80) {
        if (i == 9 && b > 1) return c.fail(fault::bad_varint, s);
        v = r;
        p += i + 1;
        return true;
      }
    }
    return c.fail(fault::bad_varint, s);
  }
  std::uint64_t r = 0;
  for (int i = 0; i < 10; ++i) {
    if (p + i >= e) return c.fail(fault::truncated, e, 1);
    const std::uint64_t b = u8at(p + i);
    r |= (b & 0x7f) << (7 * i);
    if (b < 0x80) {
      if (i == 9 && b > 1) return c.fail(fault::bad_varint, s);
      v = r;
      p += i + 1;
      return true;
    }
  }
  return c.fail(fault::bad_varint, s);
}

/// Step over one ULEB128 value without assembling it (same validity rules as varint()).
constexpr bool skip_varint(ctx& c, ptr& p, ptr e) {
  const ptr s = p;
  const ptr lim = e - p >= 10 ? p + 10 : e;
  for (ptr q = p; q < lim; ++q) {
    if (u8at(q) < 0x80) {
      if (q - s == 9 && u8at(q) > 1) return c.fail(fault::bad_varint, s);
      p = q + 1;
      return true;
    }
  }
  return lim == e && e - s < 10 ? c.fail(fault::truncated, e, 1) : c.fail(fault::bad_varint, s);
}

constexpr bool varint32(ctx& c, ptr& p, ptr e, std::uint32_t& v) {
  const ptr s = p;
  std::uint64_t w = 0;
  if (!varint(c, p, e, w)) return false;
  if (w > 0xffffffffu) return c.fail(fault::bad_varint, s);
  v = std::uint32_t(w);
  return true;
}

template <std::signed_integral S>
constexpr bool zigzag(ctx& c, ptr& p, ptr e, S& v) {
  const ptr s = p;
  std::uint64_t w = 0;
  if (!varint(c, p, e, w)) return false;
  const std::int64_t d = zigzag_decode(w);
  if (d < std::numeric_limits<S>::min() || d > std::numeric_limits<S>::max())
    return c.fail(fault::out_of_range, s);
  v = S(d);
  return true;
}

struct list_header { std::uint32_t count; std::uint8_t elem; };
constexpr bool read_list_header(ctx& c, ptr& p, ptr e, list_header& h) {
  const ptr s = p;
  if (p >= e) return c.fail(fault::truncated, p, 1);
  const std::uint8_t b = u8at(p++);
  h.elem = b & 0x0f;
  h.count = b >> 4;
  if (h.count == 15 && !varint32(c, p, e, h.count)) return false;
  if (h.count > std::size_t(e - p) / min_elem_bytes(h.elem)) return c.fail(fault::bad_count, s);
  return true;
}

constexpr bool skip(ctx& c, ptr& p, ptr e, std::uint8_t type, bool in_container, int depth);
constexpr bool skip_struct(ctx& c, ptr& p, ptr e, int depth);

/// Skip the elements of a list whose header was just read.
constexpr bool skip_elems(ctx& c, ptr& p, ptr e, list_header h, int depth) {
  switch (ctype(h.elem)) {  // fixed-size / scalar elements: no per-element recursion
    case ctype::bool_true: case ctype::bool_false: case ctype::i8:
      p += h.count;  // read_list_header proved count <= bytes left
      return true;
    case ctype::dbl:
      p += std::size_t(h.count) * 8;  // ... and count * 8 <= bytes left for doubles
      return true;
    case ctype::i16: case ctype::i32: case ctype::i64:
      for (std::uint32_t i = 0; i < h.count; ++i)
        if (!skip_varint(c, p, e)) return false;
      return true;
    default:
      for (std::uint32_t i = 0; i < h.count; ++i)
        if (!skip(c, p, e, h.elem, true, depth + 1)) return false;
      return true;
  }
}

constexpr bool skip_struct(ctx& c, ptr& p, ptr e, int depth) {
  if (depth > max_tagged_depth) return c.fail(fault::too_deep, p);
  for (;;) {
    if (p >= e) return c.fail(fault::truncated, p, 1);
    const std::uint8_t h = u8at(p++);
    if (h == 0) return true;
    if ((h >> 4) == 0 && !skip_varint(c, p, e)) return false;  // long-form id: parse, ignore
    // scalars inline (the common case); containers and structs recurse
    switch (ctype(h & 0x0f)) {
      case ctype::bool_true: case ctype::bool_false:
        continue;
      case ctype::i8:
        if (p >= e) return c.fail(fault::truncated, p, 1);
        ++p;
        continue;
      case ctype::i16: case ctype::i32: case ctype::i64:
        if (!skip_varint(c, p, e)) return false;
        continue;
      case ctype::binary: {
        std::uint32_t n = 0;
        if (!varint32(c, p, e, n)) return false;
        if (std::size_t(e - p) < n) return c.fail(fault::truncated, e, n - std::size_t(e - p));
        p += n;
        continue;
      }
      default:
        if (!skip(c, p, e, h & 0x0f, false, depth)) return false;
    }
  }
}

/// Structurally skip one value. `in_container`: a bool inside a list/set/map is one byte; a bool
/// FIELD carries its value in the header and occupies nothing here.
constexpr bool skip(ctx& c, ptr& p, ptr e, std::uint8_t type, bool in_container, int depth) {
  switch (ctype(type)) {
    case ctype::bool_true:
    case ctype::bool_false:
      if (!in_container) return true;
      [[fallthrough]];
    case ctype::i8:
      if (p >= e) return c.fail(fault::truncated, p, 1);
      ++p;
      return true;
    case ctype::i16: case ctype::i32: case ctype::i64:
      return skip_varint(c, p, e);
    case ctype::dbl:
      if (e - p < 8) return c.fail(fault::truncated, e, std::size_t(8 - (e - p)));
      p += 8;
      return true;
    case ctype::binary: {
      std::uint32_t n = 0;
      if (!varint32(c, p, e, n)) return false;
      if (std::size_t(e - p) < n) return c.fail(fault::truncated, e, n - std::size_t(e - p));
      p += n;
      return true;
    }
    case ctype::list: case ctype::set: {
      if (depth > max_tagged_depth) return c.fail(fault::too_deep, p);
      list_header h{};
      return read_list_header(c, p, e, h) && skip_elems(c, p, e, h, depth);
    }
    case ctype::map: {
      if (depth > max_tagged_depth) return c.fail(fault::too_deep, p);
      const ptr s = p;
      std::uint32_t n = 0;
      if (!varint32(c, p, e, n)) return false;
      if (n == 0) return true;
      if (p >= e) return c.fail(fault::truncated, p, 1);
      const std::uint8_t kv = u8at(p++);
      const std::uint8_t kt = kv >> 4, vt = kv & 0x0f;
      if (n > std::size_t(e - p) / (min_elem_bytes(kt) + min_elem_bytes(vt)))
        return c.fail(fault::bad_count, s);
      for (std::uint32_t i = 0; i < n; ++i)
        if (!skip(c, p, e, kt, true, depth + 1) || !skip(c, p, e, vt, true, depth + 1)) return false;
      return true;
    }
    case ctype::strct:
      return skip_struct(c, p, e, depth + 1);
    case ctype::stop:
      break;
  }
  return c.fail(fault::bad_type, p);
}

template <Message M>
constexpr bool read_struct(ctx& c, ptr& p, ptr e, int depth, M& m);

/// Decode one value of member type T whose wire type was already checked against type_of<T>.
template <class T>
constexpr bool read_value(ctx& c, ptr& p, ptr e, int depth, T& out) {
  if constexpr (std::is_same_v<T, bool>) {  // container element; bool fields are handled inline
    if (p >= e) return c.fail(fault::truncated, p, 1);
    const std::uint8_t b = u8at(p);
    if (b > 2) return c.fail(fault::bad_bool, p);
    ++p;
    out = b == 1;
    return true;
  } else if constexpr (std::is_same_v<T, std::int8_t>) {
    if (p >= e) return c.fail(fault::truncated, p, 1);
    out = std::bit_cast<std::int8_t>(u8at(p++));
    return true;
  } else if constexpr (std::is_same_v<T, std::int16_t> || std::is_same_v<T, std::int32_t> ||
                       std::is_same_v<T, std::int64_t>) {
    return zigzag(c, p, e, out);
  } else if constexpr (std::is_same_v<T, double>) {
    if (e - p < 8) return c.fail(fault::truncated, e, std::size_t(8 - (e - p)));
    std::uint64_t u = 0;
    for (int i = 0; i < 8; ++i) u |= std::uint64_t(u8at(p + i)) << (8 * i);
    p += 8;
    out = std::bit_cast<double>(u);
    return true;
  } else if constexpr (std::is_enum_v<T>) {
    std::int32_t v = 0;
    if (!zigzag(c, p, e, v)) return false;
    out = T(v);
    return true;
  } else if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string> ||
                       std::is_same_v<T, bytes>) {
    std::uint32_t n = 0;
    if (!varint32(c, p, e, n)) return false;
    if (std::size_t(e - p) < n) return c.fail(fault::truncated, e, n - std::size_t(e - p));
    const bytes b = c.origin.attested_span(p, n);
    p += n;
    if constexpr (std::is_same_v<T, bytes>) out = b;
    else out = T(as_str(b));
    return true;
  } else if constexpr (is_vector_t<T>::value) {
    using E = typename T::value_type;
    const ptr s = p;
    list_header h{};
    if (!read_list_header(c, p, e, h)) return false;
    if (h.count && !wire_ok(type_of<E>(), h.elem)) return c.fail(fault::type_mismatch, s);
    if (depth > max_tagged_depth) return c.fail(fault::too_deep, s);
    out.clear();
    out.reserve(h.count);  // bounded: read_list_header checked count against the bytes left
    for (std::uint32_t i = 0; i < h.count; ++i) {
      E v{};
      if (!read_value<E>(c, p, e, depth + 1, v)) return false;
      out.push_back(std::move(v));
    }
    return true;
  } else if constexpr (is_list_t<T>::value) {
    using E = typename T::value_type;
    const ptr s = p;
    list_header h{};
    if (!read_list_header(c, p, e, h)) return false;
    if (h.count && !wire_ok(type_of<E>(), h.elem)) return c.fail(fault::type_mismatch, s);
    if (depth > max_tagged_depth) return c.fail(fault::too_deep, s);
    const ptr body = p;
    // structural validation finds the end (Thrift lists carry no byte length); the elements are
    // decoded later, on iteration
    if (!skip_elems(c, p, e, h, depth)) return false;
    out = T(c.origin.with_range(body, p), h.count, h.elem, std::uint8_t(depth + 1));
    return true;
  } else if constexpr (is_lazy_t<T>::value) {
    const ptr s = p;
    if (!skip_struct(c, p, e, depth + 1)) return false;
    out = T(c.origin.with_range(s, p), std::uint8_t(depth + 1));
    return true;
  } else if constexpr (std::is_same_v<T, empty_struct>) {
    return skip_struct(c, p, e, depth + 1);
  } else if constexpr (Message<T>) {
    return read_struct<T>(c, p, e, depth + 1, out);
  } else {
    static_assert(always_false<T>, "nanom thrift: unsupported member type");
  }
}

template <Message M>
constexpr bool read_struct(ctx& c, ptr& p, ptr e, int depth, M& m) {
  using info = message_info<M>;
  if (depth > max_tagged_depth) return c.fail(fault::too_deep, p);
  const ptr start = p;
  std::uint64_t seen = 0;
  std::int32_t last = 0;
  for (;;) {
    if (p >= e) return c.fail(fault::truncated, p, 1);
    const ptr hp = p;
    const std::uint8_t hb = u8at(p++);
    if (hb == 0) break;  // STOP
    const std::uint8_t type = hb & 0x0f, delta = hb >> 4;
    if (delta == 0) {
      std::int16_t id = 0;
      if (!zigzag(c, p, e, id)) return false;
      last = id;
    } else {
      last += delta;
      if (last > 32767) return c.fail(fault::bad_id, hp);
    }
    const std::uint8_t slot = info::slot_of(last);
    if (slot == info::no_slot) {  // unknown field: skip, stay forward compatible
      if (!skip(c, p, e, type, false, depth)) return false;
      continue;
    }
    bool matched = true;
    const bool ok = with_field_index<M>(slot, [&]<std::size_t I>(std::integral_constant<std::size_t, I>) {
      using F = field_at_t<M, I>;
      using V = typename F::value_type;
      using T = unwrap_optional_t<V>;
      constexpr auto mp = std::tuple_element_t<I, fields_tuple_t<M>>::mem_ptr;
      if (!wire_ok(type_of<T>(), type)) {  // Thrift semantics: skip, never reinterpret
        matched = false;
        return skip(c, p, e, type, false, depth);
      }
      if constexpr (std::is_same_v<T, bool>) {  // bool field: the value is the header type
        (m.*mp).v = V(type == std::uint8_t(ctype::bool_true));
        return true;
      } else if constexpr (is_optional_t<V>::value) {
        auto& slot_v = (m.*mp).v;
        if (!slot_v) slot_v.emplace();
        return read_value<T>(c, p, e, depth, *slot_v);
      } else {
        return read_value<T>(c, p, e, depth, (m.*mp).v);
      }
    });
    if (!ok) return false;
    if (matched) seen |= std::uint64_t(1) << slot;
  }
  if ((seen & info::required_mask) != info::required_mask) {
    c.where = describe<M>::name();
    return c.fail(fault::missing_required, start);
  }
  return true;
}

}  // namespace detail::tc

/// thrift_compact<M>() — parser: one Thrift compact struct into the message M.
template <Message M>
constexpr auto thrift_compact() {
  return [](input in) -> result<M> {
    detail::tc::ctx c{in};
    detail::tc::ptr p = in.first;
    M m{};
    if (!detail::tc::read_struct<M>(c, p, in.last, 0, m)) return unexp(c.to_error());
    return done{std::move(m), in.advance(std::size_t(p - in.first))};
  };
}

/// Skip one Thrift compact struct without decoding it (validates structure and limits).
inline constexpr auto thrift_compact_skip = [](input in) -> result<unit> {
  detail::tc::ctx c{in};
  detail::tc::ptr p = in.first;
  if (!detail::tc::skip_struct(c, p, in.last, 0)) return unexp(c.to_error());
  return done{unit{}, in.advance(std::size_t(p - in.first))};
};

// ---- list / lazy out-of-line members (need the codec) ------------------------------------------

template <class E>
template <class F>
constexpr expected<unit, error> list<E>::for_each(F&& f) const {
  if (src_mode_) {
    for (std::size_t i = 0; i < src_n_; ++i) {
      if constexpr (std::is_same_v<std::invoke_result_t<F&, E>, bool>) {
        if (!f(E(src_[i]))) break;
      } else {
        f(E(src_[i]));
      }
    }
    return unit{};
  }
  detail::tc::ctx c{region_};
  detail::tc::ptr p = region_.first;
  for (std::uint32_t i = 0; i < count_; ++i) {
    E v{};
    if (!detail::tc::read_value<E>(c, p, region_.last, depth_, v)) return unexpected<error>(c.to_error());
    if constexpr (std::is_same_v<std::invoke_result_t<F&, E>, bool>) {
      if (!f(std::move(v))) break;
    } else {
      f(std::move(v));
    }
  }
  return unit{};
}

template <class E>
constexpr expected<E, error> list<E>::at(std::size_t i) const {
  if (src_mode_) {
    if (i >= src_n_) return unexpected<error>(make_err(region_, "list index in range").error());
    return src_[i];
  }
  detail::tc::ctx c{region_};
  if (i >= count_) {
    error e = make_err(region_, "list index in range").error();
    return unexpected<error>(e);
  }
  detail::tc::ptr p = region_.first;
  for (std::size_t k = 0; k < i; ++k)
    if (!detail::tc::skip(c, p, region_.last, elem_wire_, true, depth_)) return unexpected<error>(c.to_error());
  E v{};
  if (!detail::tc::read_value<E>(c, p, region_.last, depth_, v)) return unexpected<error>(c.to_error());
  return v;
}

template <class M>
constexpr expected<M, error> lazy<M>::decode() const {
  if (src_) return *src_;
  detail::tc::ctx c{region_};
  detail::tc::ptr p = region_.first;
  M m{};
  if (!detail::tc::read_struct<M>(c, p, region_.last, depth_, m)) return unexpected<error>(c.to_error());
  return m;
}

}  // namespace nanom

#endif  // NANOM_TAGGED_HPP_INCLUDED
