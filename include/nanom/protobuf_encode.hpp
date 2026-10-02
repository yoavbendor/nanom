// SPDX-License-Identifier: Apache-2.0
// nanom/protobuf_encode.hpp — WRITE the protobuf messages of nanom/protobuf.hpp (proto3 wire format).
//
// The same described struct that protobuf<M>() decodes is encoded here, into any byte sink:
//
//   std::vector<std::byte> out;
//   auto n = nm::protobuf_encode(manifest, out);           // append; n = bytes written or an error
//
//   std::array<std::byte, 256> buf;                         // fixed buffer: never written past
//   nm::span_sink s{buf};
//   if (auto r = nm::protobuf_encode(page, s); !r) ...      // r.error(): what + where
//
//   const std::size_t size = *nm::protobuf_size(manifest);  // exact, nothing written
//
// What is written (canonical proto3, what protoc / prost produce):
//   * presence::defaulted scalars, strings and bytes are left out when they hold the default (0,
//     false, +0.0, empty); presence::required ones are always written;
//   * std::optional<T> is written when it holds a value, whatever the value (proto3 `optional`);
//   * a member of message type is always written (use std::optional<M> for an absent message);
//   * repeated scalars are packed (one length-delimited record), repeated strings and messages are
//     one record each, an empty repeated field writes nothing;
//   * fields in declaration (= ascending id) order.
//
// Writing is checked like reading: nesting deeper than the decoder accepts, or a message, string or
// packed run longer than protobuf's 2 GiB limit, is an error, so whatever is written reads back.
// A sink that refuses bytes is an error, and nothing is written past a fixed buffer. The error
// names the message and field it happened in.
//
// Nested messages are length-prefixed. A first pass measures every nested message once (in the
// order they are written) and the write pass reuses those sizes, so encoding is linear in the
// message size whatever the nesting. Messages without nested messages skip the first pass.
//
// Reading code never needs this header (nanom/protobuf.hpp does not include it).
#ifndef NANOM_PROTOBUF_ENCODE_HPP_INCLUDED
#define NANOM_PROTOBUF_ENCODE_HPP_INCLUDED

#include "protobuf.hpp"
#include "sink.hpp"

namespace nanom {

namespace detail::pb {

inline constexpr std::size_t max_len = 0x7fffffff;  ///< protobuf's 2 GiB message / field limit

constexpr std::size_t varint_size(std::uint64_t v) { return std::size_t(std::bit_width(v | 1) + 6) / 7; }

/// The varint a varint-wire scalar is written as.
template <class T>
constexpr std::uint64_t varint_value(const T& v) {
  if constexpr (is_sint<T>::value) return zigzag_encode(v.v);
  else if constexpr (std::is_same_v<T, bool>) return v ? 1 : 0;
  else if constexpr (std::is_enum_v<T>) return std::uint64_t(std::int64_t(std::to_underlying(v)));
  else if constexpr (std::is_signed_v<T>) return std::uint64_t(std::int64_t(v));  // negative: 10 bytes
  else return std::uint64_t(v);
}
/// The little-endian bits of a fixed-wire scalar.
template <class T>
constexpr std::uint64_t fixed_bits(const T& v) {
  if constexpr (is_fixed<T>::value) return std::uint64_t(std::make_unsigned_t<decltype(v.v)>(v.v));
  else if constexpr (std::is_same_v<T, float>) return std::bit_cast<std::uint32_t>(v);
  else return std::bit_cast<std::uint64_t>(v);
}
template <class T>
constexpr std::size_t scalar_size(const T& v) {
  if constexpr (wire_of<T>() == varint) return varint_size(varint_value(v));
  else return wire_of<T>() == i32 ? 4 : 8;
}
/// proto3's "holds the default": what a defaulted field leaves off the wire (-0.0 is not +0.0).
template <class T>
constexpr bool is_default(const T& v) {
  if constexpr (is_sint<T>::value || is_fixed<T>::value) return v.v == 0;
  else if constexpr (std::is_floating_point_v<T>) return fixed_bits(v) == 0;
  else if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>) return v == T{};
  else if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string> ||
                     std::is_same_v<T, bytes>) return v.empty();
  else return false;  // a message member is always written
}
template <class F>
constexpr std::uint64_t key_of(std::uint8_t wt) { return (std::uint64_t(F::id) << 3) | wt; }

/// Whether writing M needs the measuring pass (it has a nested message somewhere).
template <class T>
consteval bool has_message() {
  if constexpr (is_optional_t<T>::value || is_vector_t<T>::value) return has_message<typename T::value_type>();
  else return Message<T>;
}
template <Message M>
consteval bool has_nested() {
  bool any = false;
  for_each_field<M>([&](auto f) { any = any || has_message<typename member_t<decltype(f)::mem_ptr>::value_type>(); });
  return any;
}

/// Shared state of both passes: the error (first one wins) and where the encoder is.
struct state {
  const char* err = nullptr;
  std::string_view message, field;
  std::vector<std::size_t> sizes;  ///< nested message sizes, in write order (pass 1 fills, pass 2 reads)
  std::size_t next = 0;
  void fail(const char* what) {
    if (!err) err = what;
  }
};

// --- pass 1: measure -------------------------------------------------------------------------

template <Message M> std::size_t measure(state& st, const M& m, int depth);

/// Bytes of one value after its key (length prefix included for length-delimited values).
template <class T>
std::size_t value_size(state& st, const T& v, int depth) {
  if constexpr (Message<T>) {
    const std::size_t k = st.sizes.size();
    st.sizes.push_back(0);
    const std::size_t n = measure(st, v, depth + 1);
    st.sizes[k] = n;
    return varint_size(n) + n;
  } else if constexpr (wire_of<T>() == len) {
    const std::size_t n = v.size();
    if (n > max_len) st.fail("a string or bytes field longer than protobuf's 2 GiB limit");
    return varint_size(n) + n;
  } else {
    return scalar_size(v);
  }
}

template <class V>
std::size_t packed_size(const V& vec) {
  using E = typename V::value_type;
  if constexpr (wire_of<E>() == i32) return 4 * vec.size();
  else if constexpr (wire_of<E>() == i64) return 8 * vec.size();
  else {
    std::size_t n = 0;
    for (const auto& e : vec) n += scalar_size<E>(e);
    return n;
  }
}

template <Message M>
std::size_t measure(state& st, const M& m, int depth) {
  if (depth > max_tagged_depth) {
    st.fail("protobuf nesting within the decoder's depth limit");
    return 0;
  }
  std::size_t total = 0;
  for_each_field<M>([&](auto f) {
    using F = member_t<decltype(f)::mem_ptr>;
    using V = typename F::value_type;
    const V& fv = (m.*(decltype(f)::mem_ptr)).v;
    if constexpr (is_vector_t<V>::value) {
      using E = typename V::value_type;
      if constexpr (packable<E>) {
        if (fv.empty()) return;
        const std::size_t n = packed_size(fv);
        if (n > max_len) st.fail("a packed repeated field longer than protobuf's 2 GiB limit");
        total += varint_size(key_of<F>(len)) + varint_size(n) + n;
      } else {
        for (const auto& e : fv) total += varint_size(key_of<F>(len)) + value_size<E>(st, e, depth);
      }
    } else if constexpr (is_optional_t<V>::value) {
      using T = typename V::value_type;
      if (fv) total += varint_size(key_of<F>(wire_of<T>())) + value_size<T>(st, *fv, depth);
    } else {
      if (F::pres == presence::defaulted && is_default(fv)) return;
      total += varint_size(key_of<F>(wire_of<V>())) + value_size<V>(st, fv, depth);
    }
  });
  if (total > max_len && !st.err) {
    st.message = describe<M>::name();
    st.fail("a message longer than protobuf's 2 GiB limit");
  }
  return total;
}

// --- pass 2: write ---------------------------------------------------------------------------

/// Stages small writes (keys, varints) in a local buffer and hands them to the sink in blocks;
/// large payloads go straight through. After the first failure every write is a no-op.
template <byte_sink S>
struct writer {
  writer(S& s, state& t) : sink(s), st(t) {}
  S& sink;
  state& st;
  std::size_t total = 0;
  std::size_t len = 0;
  std::byte buf[256];

  void flush() {
    if (st.err || !len) return;
    if (!sink.put(buf, len)) return st.fail("the sink refused the bytes (full or failed)");
    total += len;
    len = 0;
  }
  void varint(std::uint64_t v) {
    if (sizeof(buf) - len < leb128_max_bytes<std::uint64_t>) flush();
    if (st.err) return;
    len += uleb128_encode(v, buf + len);
  }
  void fixed(std::uint64_t u, std::size_t n) {
    if (sizeof(buf) - len < 8) flush();
    if (st.err) return;
    for (std::size_t i = 0; i < n; ++i) buf[len++] = std::byte(std::uint8_t(u >> (8 * i)));
  }
  void raw(const std::byte* p, std::size_t n) {
    if (st.err || !n) return;
    if (n <= sizeof(buf) - len) {
      std::memcpy(buf + len, p, n);
      len += n;
      return;
    }
    flush();
    if (st.err) return;
    if (!sink.put(p, n)) return st.fail("the sink refused the bytes (full or failed)");
    total += n;
  }
};

template <Message M, class W> void write_message(W& w, const M& m);

template <class T, class W>
void write_scalar(W& w, const T& v) {
  if constexpr (wire_of<T>() == varint) w.varint(varint_value(v));
  else w.fixed(fixed_bits(v), wire_of<T>() == i32 ? 4 : 8);
}

/// One value after its key.
template <class T, class W>
void write_value(W& w, const T& v) {
  if constexpr (Message<T>) {
    w.varint(w.st.sizes[w.st.next++]);
    write_message(w, v);
  } else if constexpr (std::is_same_v<T, bytes>) {
    w.varint(v.size());
    w.raw(v.data(), v.size());
  } else if constexpr (wire_of<T>() == len) {
    w.varint(v.size());
    w.raw(reinterpret_cast<const std::byte*>(v.data()), v.size());
  } else {
    write_scalar(w, v);
  }
}

template <Message M, class W>
void write_message(W& w, const M& m) {
  const auto saved_message = w.st.message, saved_field = w.st.field;
  w.st.message = describe<M>::name();
  for_each_field<M>([&](auto f) {
    if (w.st.err) return;
    using F = member_t<decltype(f)::mem_ptr>;
    using V = typename F::value_type;
    w.st.field = decltype(f)::name.sv();
    const V& fv = (m.*(decltype(f)::mem_ptr)).v;
    if constexpr (is_vector_t<V>::value) {
      using E = typename V::value_type;
      if constexpr (packable<E>) {
        if (fv.empty()) return;
        w.varint(key_of<F>(len));
        w.varint(packed_size(fv));
        for (const auto& e : fv) write_scalar<E>(w, e);
      } else {
        for (const auto& e : fv) {
          w.varint(key_of<F>(len));
          write_value<E>(w, e);
        }
      }
    } else if constexpr (is_optional_t<V>::value) {
      using T = typename V::value_type;
      if (!fv) return;
      w.varint(key_of<F>(wire_of<T>()));
      write_value<T>(w, *fv);
    } else {
      if (F::pres == presence::defaulted && is_default(fv)) return;
      w.varint(key_of<F>(wire_of<V>()));
      write_value<V>(w, fv);
    }
  });
  if (w.st.err) return;  // keep the innermost message / field as the error location
  w.st.message = saved_message;
  w.st.field = saved_field;
}

template <Message M>
encode_error error_of(const state& st) {
  return encode_error{st.err, st.message.empty() ? describe<M>::name() : st.message, st.field};
}

}  // namespace detail::pb

/// Encode m into `sink`. Returns the bytes written, or where and why it failed (on failure a
/// growable sink may hold a partial encoding; a span_sink is never written past its end).
template <Message M, byte_sink S>
expected<std::size_t, encode_error> protobuf_encode(const M& m, S& sink) {
  detail::pb::check_model<M>();
  detail::pb::state st;
  if constexpr (detail::pb::has_nested<M>()) {
    detail::pb::measure(st, m, 0);
    if (st.err) return unexpected<encode_error>(detail::pb::error_of<M>(st));
    st.message = st.field = {};
  }
  detail::pb::writer<S> w(sink, st);
  detail::pb::write_message(w, m);
  w.flush();
  if (st.err) return unexpected<encode_error>(detail::pb::error_of<M>(st));
  return w.total;
}

/// Append the encoding of m to `out`.
template <Message M>
expected<std::size_t, encode_error> protobuf_encode(const M& m, std::vector<std::byte>& out) {
  vector_sink s{&out};
  return protobuf_encode(m, s);
}

/// The exact number of bytes protobuf_encode(m, …) writes (nothing is written).
template <Message M>
expected<std::size_t, encode_error> protobuf_size(const M& m) {
  detail::pb::check_model<M>();
  detail::pb::state st;
  const std::size_t n = detail::pb::measure(st, m, 0);
  if (st.err) return unexpected<encode_error>(detail::pb::error_of<M>(st));
  return n;
}

}  // namespace nanom

#endif  // NANOM_PROTOBUF_ENCODE_HPP_INCLUDED
