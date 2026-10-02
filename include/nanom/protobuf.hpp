// SPDX-License-Identifier: Apache-2.0
// nanom/protobuf.hpp — protobuf (proto3 wire format) for the tagged-message model of tagged.hpp.
//
// The same `field<Id, T>` description that tagged.hpp decodes as Thrift compact is decoded here as
// protobuf — the encoding of Lance's manifests and file metadata:
//
//   struct DataFile {
//     nm::field<1, std::string_view, nm::presence::defaulted>           path;
//     nm::field<2, std::vector<std::int32_t>, nm::presence::defaulted>  fields;
//   };
//   NANOM_DESCRIBE(DataFile, path, fields);
//   auto r = nm::protobuf<DataFile>()(in);      // the whole input is one message
//
// Member types and their wire types:
//   bool, int32/int64, uint32/uint64, enums       varint (negative int32 / int64: 10-byte two's complement)
//   pb_sint<int32_t / int64_t>                    varint, zigzag (proto sint32 / sint64)
//   pb_fixed<uint32_t / int32_t / uint64_t / …>   fixed32 / fixed64 (proto fixed* / sfixed*)
//   float / double                                fixed32 / fixed64
//   std::string_view, nm::bytes, std::string      length-delimited (views point into the input)
//   a described message M, std::optional<M>       length-delimited, decoded recursively
//   std::vector<E>                                repeated: scalars packed or not (both accepted),
//                                                 strings / messages one record each; a proto map
//                                                 is std::vector<Entry> with Entry {1: key, 2: value}
//   std::optional<T>                              explicit presence (proto3 `optional`, oneof members)
//   nm::pb_box<M>                                 an optional message on the heap (recursive models)
//   nm::pb_unknown (first member, id 0)           keeps the fields the model does not declare
//
// Presence: proto3 fields are implicit — absent means the default — so declare them
// presence::defaulted; presence::required makes absence an error (for formats that need it).
// Unknown fields, and known fields arriving with another wire type, are skipped (the protobuf rule),
// or kept verbatim in a pb_unknown member when the model declares one (written back on encode).
//
// Hostile-input posture, as in tagged.hpp: every length is checked against the remaining bytes,
// nesting is capped at max_tagged_depth, integers must fit the member (an over-wide varint is an
// error, never a silent truncation), and repeated counts never size an allocation before their
// bytes are proven present. Writing is nanom/protobuf_encode.hpp (reading code never needs it).
#ifndef NANOM_PROTOBUF_HPP_INCLUDED
#define NANOM_PROTOBUF_HPP_INCLUDED

#include "tagged.hpp"

#include <cstring>
#include <span>

namespace nanom {

/// proto sint32 / sint64: a signed integer zigzag-encoded on the wire.
template <class T>
  requires(std::same_as<T, std::int32_t> || std::same_as<T, std::int64_t>)
struct pb_sint {
  T v{};
  constexpr pb_sint() = default;
  constexpr pb_sint(T x) : v(x) {}
  constexpr operator T() const { return v; }
  constexpr bool operator==(const pb_sint&) const = default;
};
/// proto fixed32 / fixed64 / sfixed32 / sfixed64: little-endian, 4 or 8 bytes on the wire.
template <class T>
  requires(std::integral<T> && (sizeof(T) == 4 || sizeof(T) == 8))
struct pb_fixed {
  T v{};
  constexpr pb_fixed() = default;
  constexpr pb_fixed(T x) : v(x) {}
  constexpr operator T() const { return v; }
  constexpr bool operator==(const pb_fixed&) const = default;
};

namespace detail::pb {

using tc::always_false;
using tc::ptr;

enum wire : std::uint8_t { varint = 0, i64 = 1, len = 2, i32 = 5 };

template <class T> struct is_sint : std::false_type {};
template <class T> struct is_sint<pb_sint<T>> : std::true_type {};
template <class T> struct is_fixed : std::false_type {};
template <class T> struct is_fixed<pb_fixed<T>> : std::true_type {};

/// std::optional<M> and pb_box<M>: written when present, absent otherwise.
template <class T> constexpr bool opt_like = is_optional_t<T>::value || is_box_t<T>::value;
template <class T> struct inner { using type = T; };
template <class T> struct inner<std::optional<T>> { using type = T; };
template <class T> struct inner<pb_box<T>> { using type = T; };
template <class T> using inner_t = typename inner<T>::type;

/// The wire type a (non-repeated) member type is written with.
template <class T>
consteval std::uint8_t wire_of() {
  if constexpr (opt_like<T>)                                          return wire_of<typename T::value_type>();
  else if constexpr (is_sint<T>::value)                               return varint;
  else if constexpr (is_fixed<T>::value)                              return sizeof(T) == 4 ? i32 : i64;
  else if constexpr (std::is_same_v<T, float>)                        return i32;
  else if constexpr (std::is_same_v<T, double>)                       return i64;
  else if constexpr (std::is_same_v<T, bool> || std::is_integral_v<T> || std::is_enum_v<T>) return varint;
  else if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string> ||
                     std::is_same_v<T, bytes>)                        return len;
  else if constexpr (Message<T>)                                      return len;
  else static_assert(always_false<T>, "nanom protobuf: unsupported member type (see protobuf.hpp)");
}
/// Scalars that may be packed in a repeated field.
template <class T>
constexpr bool packable = !std::is_same_v<T, std::string_view> && !std::is_same_v<T, std::string> &&
                          !std::is_same_v<T, bytes> && !Message<T>;

/// Model rules the wire cannot express, checked at compile time for every message read or written.
template <Message M>
constexpr void check_model() {
  for_each_field<M>([](auto f) {
    using F = member_t<decltype(f)::mem_ptr>;
    if constexpr (is_vector_t<typename F::value_type>::value)
      static_assert(F::pres == presence::defaulted,
                    "nanom protobuf: a repeated field is presence::defaulted (an empty one is absent "
                    "on the wire, so it cannot be required)");
    if constexpr (is_box_t<typename F::value_type>::value)
      static_assert(F::pres == presence::defaulted, "nanom protobuf: a pb_box field is presence::defaulted");
  });
}

struct ctx {
  input in;
  const char* why = nullptr;
  ptr at = nullptr;
  bool fail(const char* w, ptr p) {
    if (!why) {
      why = w;
      at = p;
    }
    return false;
  }
  error to_error() const {
    const input here = in.with_range(at ? at : in.first, in.last);
    return make_err(here, why ? why : "a protobuf message").error();
  }
};

#if defined(__GNUC__)
#define NANOM_PB_NOINLINE __attribute__((noinline))
#define NANOM_PB_INLINE __attribute__((always_inline)) inline
#else
#define NANOM_PB_NOINLINE
#define NANOM_PB_INLINE inline
#endif

NANOM_PB_NOINLINE inline bool read_varint_slow(ctx& c, ptr& p, ptr e, std::uint64_t& v) {
  v = 0;
  for (unsigned shift = 0; shift < 64; shift += 7) {
    if (p >= e) return c.fail("a complete protobuf varint", p);
    const std::uint8_t b = std::uint8_t(*p++);
    if (shift == 63 && b > 1) return c.fail("a protobuf varint of at most 64 bits", p - 1);
    v |= std::uint64_t(b & 0x7f) << shift;
    if (!(b & 0x80)) return true;
  }
  return c.fail("a protobuf varint of at most 10 bytes", p);
}
/// One varint. Keys and small values are one byte: that case is inlined, the rest is not.
NANOM_PB_INLINE bool read_varint(ctx& c, ptr& p, ptr e, std::uint64_t& v) {
  if (p < e && !(std::uint8_t(*p) & 0x80)) [[likely]] {
    v = std::uint8_t(*p++);
    return true;
  }
  return read_varint_slow(c, p, e, v);
}
#undef NANOM_PB_NOINLINE
#undef NANOM_PB_INLINE

inline bool skip_value(ctx& c, ptr& p, ptr e, std::uint8_t wt) {
  std::uint64_t v;
  switch (wt) {
    case varint: return read_varint(c, p, e, v);
    case i64:
      if (e - p < 8) return c.fail("8 bytes of a fixed64 field", p);
      p += 8;
      return true;
    case i32:
      if (e - p < 4) return c.fail("4 bytes of a fixed32 field", p);
      p += 4;
      return true;
    case len:
      if (!read_varint(c, p, e, v)) return false;
      if (v > std::uint64_t(e - p)) return c.fail("a length-delimited field that fits the message", p);
      p += std::ptrdiff_t(v);
      return true;
    default:
      return c.fail("a protobuf wire type 0, 1, 2 or 5 (groups are not supported)", p);
  }
}

template <Message M> bool read_message(ctx& c, ptr p, ptr e, std::uint8_t depth, M& m);

/// Decode one scalar of member type T arriving with wire type wt (already checked to match).
template <class T>
bool read_scalar(ctx& c, ptr& p, ptr e, T& out) {
  if constexpr (is_sint<T>::value) {
    std::uint64_t v;
    if (!read_varint(c, p, e, v)) return false;
    const std::int64_t s = zigzag_decode(v);
    using V = decltype(out.v);
    if (!std::in_range<V>(s)) return c.fail("a sint value that fits the member", p);
    out.v = V(s);
    return true;
  } else if constexpr (is_fixed<T>::value) {
    using V = decltype(out.v);
    if (std::size_t(e - p) < sizeof(V)) return c.fail("the bytes of a fixed field", p);
    std::make_unsigned_t<V> u = 0;
    for (std::size_t i = 0; i < sizeof(V); ++i) u |= std::make_unsigned_t<V>(std::uint8_t(p[i])) << (8 * i);
    out.v = std::bit_cast<V>(u);
    p += sizeof(V);
    return true;
  } else if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
    using U = std::conditional_t<sizeof(T) == 4, std::uint32_t, std::uint64_t>;
    if (std::size_t(e - p) < sizeof(T)) return c.fail("the bytes of a floating-point field", p);
    U u = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) u |= U(std::uint8_t(p[i])) << (8 * i);
    out = std::bit_cast<T>(u);
    p += sizeof(T);
    return true;
  } else if constexpr (std::is_same_v<T, bool>) {
    std::uint64_t v;
    if (!read_varint(c, p, e, v)) return false;
    if (v > 1) return c.fail("a bool of 0 or 1", p);
    out = v != 0;
    return true;
  } else if constexpr (std::is_enum_v<T>) {  // open enums: any int32
    std::uint64_t v;
    if (!read_varint(c, p, e, v)) return false;
    const auto s = std::int64_t(v);
    if (!std::in_range<std::int32_t>(s)) return c.fail("an enum value that fits int32", p);
    out = T(std::int32_t(s));
    return true;
  } else if constexpr (std::is_integral_v<T>) {
    std::uint64_t v;
    if (!read_varint(c, p, e, v)) return false;
    if constexpr (std::is_signed_v<T>) {
      const auto s = std::int64_t(v);  // negative values are sign-extended to 64 bits on the wire
      if (!std::in_range<T>(s)) return c.fail("an integer that fits the member", p);
      out = T(s);
    } else {
      if (!std::in_range<T>(v)) return c.fail("an integer that fits the member", p);
      out = T(v);
    }
    return true;
  } else {
    static_assert(always_false<T>, "nanom protobuf: not a scalar");
  }
}

/// Decode one length-delimited value (its bytes are [p, e)) of member type T.
template <class T>
bool read_len(ctx& c, ptr p, ptr e, std::uint8_t depth, T& out) {
  if constexpr (std::is_same_v<T, std::string_view>) {
    out = std::string_view(reinterpret_cast<const char*>(p), std::size_t(e - p));
    return true;
  } else if constexpr (std::is_same_v<T, std::string>) {
    out.assign(reinterpret_cast<const char*>(p), std::size_t(e - p));
    return true;
  } else if constexpr (std::is_same_v<T, bytes>) {
    out = bytes(p, std::size_t(e - p));
    return true;
  } else if constexpr (Message<T>) {
    if (depth >= max_tagged_depth) return c.fail("protobuf nesting within the depth limit", p);
    return read_message<T>(c, p, e, std::uint8_t(depth + 1), out);
  } else {
    static_assert(always_false<T>, "nanom protobuf: not length-delimited");
  }
}

/// Decode one occurrence of a field of member type V (wire type wt) into `slot`.
/// key: the bytes of the field key just read (a repeated scalar's unpacked records usually follow
/// one another; their run is read here without going back through the message's field dispatch).
template <class V>
bool read_field(ctx& c, ptr& p, ptr e, std::uint8_t wt, std::uint8_t depth, V& slot, bool& matched,
                std::span<const std::byte> key) {
  if constexpr (std::is_same_v<V, unknown_fields>) {  // id 0: never dispatched here
    return skip_value(c, p, e, wt);
  } else if constexpr (is_vector_t<V>::value) {
    using E = typename V::value_type;
    constexpr std::uint8_t ew = wire_of<E>();
    if (wt == ew && !(ew == len && packable<E>)) {  // one element (unpacked / string / message)
      matched = true;
      E x{};
      if (ew == len) {
        std::uint64_t n;
        if (!read_varint(c, p, e, n)) return false;
        if (n > std::uint64_t(e - p)) return c.fail("a length-delimited field that fits the message", p);
        if constexpr (ew == len) {
          if (!read_len<E>(c, p, p + n, depth, x)) return false;
        }
        p += std::ptrdiff_t(n);
      } else if constexpr (ew != len) {
        if (!read_scalar<E>(c, p, e, x)) return false;
        slot.push_back(x);
        if (key.size() == 1) {  // field numbers 1..15: a one-byte key
          const std::byte k = key[0];
          while (e - p > 1 && *p == k) {
            ++p;
            if (!read_scalar<E>(c, p, e, x)) return false;
            slot.push_back(x);
          }
        } else {
          while (std::size_t(e - p) > key.size() && std::memcmp(p, key.data(), key.size()) == 0) {
            p += key.size();
            if (!read_scalar<E>(c, p, e, x)) return false;
            slot.push_back(x);
          }
        }
        return true;
      }
      slot.push_back(std::move(x));
      return true;
    }
    if constexpr (packable<E>) {
      if (wt == len) {  // packed run
        matched = true;
        std::uint64_t n;
        if (!read_varint(c, p, e, n)) return false;
        if (n > std::uint64_t(e - p)) return c.fail("a packed field that fits the message", p);
        const ptr pe = p + n;
        if constexpr (ew == i32 || ew == i64) {
          const std::size_t w = ew == i32 ? 4 : 8;
          if (n % w) return c.fail("a packed fixed-width field of whole values", p);
          slot.reserve(slot.size() + std::size_t(n / w));
        } else {  // one value per byte without the continuation bit: an exact count, no regrowth
          std::size_t count = 0;
          for (ptr q = p; q < pe; ++q) count += !(std::uint8_t(*q) & 0x80);
          slot.reserve(slot.size() + count);
        }
        while (p < pe)
          if (E x{}; read_scalar<E>(c, p, pe, x)) slot.push_back(x);
          else return false;
        return true;
      }
    }
    return skip_value(c, p, e, wt);  // another wire type: an unknown field
  } else {
    using T = inner_t<V>;
    constexpr std::uint8_t tw = wire_of<T>();
    if (wt != tw) return skip_value(c, p, e, wt);
    matched = true;
    T x{};
    if constexpr (tw == len) {
      std::uint64_t n;
      if (!read_varint(c, p, e, n)) return false;
      if (n > std::uint64_t(e - p)) return c.fail("a length-delimited field that fits the message", p);
      if constexpr (Message<T>) {  // a repeated occurrence of a message field merges (protobuf rule)
        if constexpr (opt_like<V>) {
          if (slot) x = std::move(*slot);
        } else {
          x = std::move(slot);
        }
      }
      if (!read_len<T>(c, p, p + n, depth, x)) return false;
      p += std::ptrdiff_t(n);
    } else {
      if (!read_scalar<T>(c, p, e, x)) return false;
    }
    slot = std::move(x);
    return true;
  }
}

/// Append one skipped field (key and value) to the message's pb_unknown member.
template <Message M>
void keep_unknown(M& m, ptr first, ptr last) {
  constexpr auto mp = std::get<0>(describe<M>::fields()).mem_ptr;
  auto& b = (m.*mp).v.bytes;
  b.insert(b.end(), first, last);
}

template <Message M>
bool read_message(ctx& c, ptr p, ptr e, std::uint8_t depth, M& m) {
  check_model<M>();
  using info = message_info<M>;
  std::uint64_t seen = 0;
  while (p < e) {
    const ptr tag_at = p;
    std::uint64_t key;
    if (!read_varint(c, p, e, key)) return false;
    const std::uint64_t id = key >> 3;
    const std::uint8_t wt = std::uint8_t(key & 7);
    if (id == 0 || id > 536870911) return c.fail("a protobuf field number of 1 .. 2^29-1", tag_at);
    const std::uint8_t slot = id > 32767 ? info::no_slot : info::slot_of(std::int32_t(id));
    if (slot == info::no_slot) {
      if (!skip_value(c, p, e, wt)) return false;
      if constexpr (info::has_unknown) keep_unknown(m, tag_at, p);
      continue;
    }
    bool matched = false;
    const bool ok = with_field_index<M>(slot, [&](auto I) {
      constexpr std::size_t i = decltype(I)::value;
      constexpr auto mp = std::get<i>(describe<M>::fields()).mem_ptr;
      return read_field(c, p, e, wt, depth, (m.*mp).v, matched,
                        std::span<const std::byte>(tag_at, std::size_t(p - tag_at)));
    });
    if (!ok) return false;
    if (matched) seen |= std::uint64_t(1) << slot;
    else if constexpr (info::has_unknown) keep_unknown(m, tag_at, p);  // a known id, another wire type
  }
  if ((seen & info::required_mask) != info::required_mask) {
    return c.fail("a protobuf message with every required field", p);
  }
  return true;
}

}  // namespace detail::pb

/// protobuf<M>() — parser: the whole input is one protobuf message M (protobuf messages are not
/// self-delimiting). Strings and bytes are views into the input.
template <Message M>
constexpr auto protobuf() {
  return [](input in) -> result<M> {
    detail::pb::ctx c{in};
    M m{};
    if (!detail::pb::read_message<M>(c, in.first, in.last, 0, m)) return unexp(c.to_error());
    return done{std::move(m), in.advance(in.size())};
  };
}

}  // namespace nanom

#endif  // NANOM_PROTOBUF_HPP_INCLUDED
