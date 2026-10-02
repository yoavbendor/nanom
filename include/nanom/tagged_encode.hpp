// SPDX-License-Identifier: Apache-2.0
// nanom/tagged_encode.hpp — WRITE the tagged messages of nanom/tagged.hpp (Thrift compact).
//
// The same described struct that thrift_compact<M>() decodes is encoded here, into any byte sink:
//
//   std::vector<std::byte> out;
//   auto n = nm::thrift_compact_encode(meta, out);          // append; n = bytes written or an error
//
//   std::array<std::byte, 256> buf;                         // fixed buffer: never written past
//   nm::span_sink s{buf};
//   if (auto r = nm::thrift_compact_encode(header, s); !r) ...   // r.error(): what + where
//
//   const std::size_t size = *nm::thrift_compact_size(meta);    // exact, nothing written
//
// Building a message to write is zero-copy: std::string_view / nm::bytes members are views,
// repeated members are nm::list<E>::of(span) over the caller's elements, nested messages
// nm::lazy<M>::of(m). A list or message decoded from a file is written back verbatim (its wire
// bytes are already valid), so read-modify-write keeps whatever the model does not declare.
//
// Writing is checked like reading:
//   * a string, binary or list longer than the wire's i32 is an error (never a truncated length);
//   * a lazy<M> that was neither decoded nor set with of() is an error (it has no bytes to write);
//   * a sink that refuses bytes (a full span_sink, a failed stream) is an error, and nothing is
//     written past a fixed buffer;
//   * field ids stay ascending and unique — the same static_asserts as decoding.
// The error names the struct and field it happened in.
//
// Reading code never needs this header (nanom/tagged.hpp does not include it).
#ifndef NANOM_TAGGED_ENCODE_HPP_INCLUDED
#define NANOM_TAGGED_ENCODE_HPP_INCLUDED

#include "tagged.hpp"

namespace nanom {

// ---------------------------------------------------------------------------
// 41. byte sinks
// ---------------------------------------------------------------------------

/// Anything bytes can be written to: put() returns false when it cannot take them all (a full
/// buffer, a failed stream); the encoder then stops and reports the error.
template <class S>
concept byte_sink = requires(S& s, const std::byte* p, std::size_t n) {
  { s.put(p, n) } -> std::convertible_to<bool>;
};

/// Appends to a vector (grows as needed).
struct vector_sink {
  std::vector<std::byte>* out;
  bool put(const std::byte* p, std::size_t n) {
    out->insert(out->end(), p, p + n);
    return true;
  }
};

/// Writes into a fixed buffer; refuses (writing nothing) what does not fit.
struct span_sink {
  std::span<std::byte> out;
  std::size_t used = 0;
  bool put(const std::byte* p, std::size_t n) {
    if (n > out.size() - used) return false;
    if (n) std::memcpy(out.data() + used, p, n);
    used += n;
    return true;
  }
  std::span<std::byte> written() const { return out.first(used); }
};

/// Counts bytes without storing them (exact encoded size).
struct counting_sink {
  std::size_t count = 0;
  bool put(const std::byte*, std::size_t n) {
    count += n;
    return true;
  }
};

/// Why an encode failed, and where: the struct (describe<M>::name()) and field being written.
struct encode_error {
  const char*      what = "";
  std::string_view message;
  std::string_view field;
};

// ---------------------------------------------------------------------------
// 42. Thrift compact protocol — encode
// ---------------------------------------------------------------------------

namespace detail::tc {

/// Stages small writes (headers, varints) in a local buffer and hands them to the sink in blocks;
/// large payloads go straight through. After the first failure every write is a no-op.
template <byte_sink S>
struct writer {
  explicit writer(S& s) : sink(s) {}
  S& sink;
  std::size_t total = 0;
  const char* err = nullptr;
  std::string_view message, field;  ///< where the encoder is (for errors)
  std::size_t len = 0;
  std::byte buf[256];

  void fail(const char* what) {
    if (!err) err = what;
  }
  void flush() {
    if (err || !len) return;
    if (!sink.put(buf, len)) return fail("the sink refused the bytes (full or failed)");
    total += len;
    len = 0;
  }
  void u8(std::uint8_t b) {
    if (len == sizeof(buf)) flush();
    if (err) return;
    buf[len++] = std::byte(b);
  }
  void varint(std::uint64_t v) {
    if (sizeof(buf) - len < leb128_max_bytes<std::uint64_t>) flush();
    if (err) return;
    len += uleb128_encode(v, buf + len);
  }
  void raw(const std::byte* p, std::size_t n) {
    if (err || !n) return;
    if (n <= sizeof(buf) - len) {
      std::memcpy(buf + len, p, n);
      len += n;
      return;
    }
    flush();
    if (err) return;
    if (!sink.put(p, n)) return fail("the sink refused the bytes (full or failed)");
    total += n;
  }
  /// A wire length or count: Thrift compact carries them as (non-negative) i32.
  bool length(std::size_t n) {
    if (n > std::size_t(INT32_MAX)) {
      fail("a string, binary or list longer than the wire's i32 length");
      return false;
    }
    varint(n);
    return true;
  }
  void list_header(std::size_t n, std::uint8_t et) {
    if (n > std::size_t(INT32_MAX)) return fail("a list longer than the wire's i32 count");
    if (n < 15) {
      u8(std::uint8_t((n << 4) | et));
    } else {
      u8(std::uint8_t(0xf0 | et));
      varint(n);
    }
  }
};

template <Message M, class W> void write_struct(W& w, const M& m);

template <class T, class W>
void write_value(W& w, const T& v) {
  if constexpr (std::is_same_v<T, bool>) {
    w.u8(v ? 1 : 2);  // in a list; a bool field carries its value in the field header
  } else if constexpr (std::is_same_v<T, std::int8_t>) {
    w.u8(std::bit_cast<std::uint8_t>(v));
  } else if constexpr (std::is_same_v<T, std::int16_t> || std::is_same_v<T, std::int32_t> ||
                       std::is_same_v<T, std::int64_t>) {
    w.varint(zigzag_encode(v));
  } else if constexpr (std::is_same_v<T, double>) {
    const auto u = std::bit_cast<std::uint64_t>(v);
    std::byte le[8];
    for (int i = 0; i < 8; ++i) le[i] = std::byte(std::uint8_t(u >> (8 * i)));
    w.raw(le, 8);
  } else if constexpr (std::is_enum_v<T>) {
    w.varint(zigzag_encode(std::int32_t(v)));
  } else if constexpr (std::is_same_v<T, std::string_view> || std::is_same_v<T, std::string>) {
    if (w.length(v.size())) w.raw(reinterpret_cast<const std::byte*>(v.data()), v.size());
  } else if constexpr (std::is_same_v<T, bytes>) {
    if (w.length(v.size())) w.raw(v.data(), v.size());
  } else if constexpr (is_vector_t<T>::value) {
    using E = typename T::value_type;
    w.list_header(v.size(), type_of<E>());
    for (const auto& e : v) write_value<E>(w, e);
  } else if constexpr (is_list_t<T>::value) {
    using E = typename T::value_type;
    if (v.is_source()) {
      const auto src = v.source();
      w.list_header(src.size(), type_of<E>());
      for (const auto& e : src) write_value<E>(w, e);
    } else {
      // decoded from the wire: the region is already-valid encoding of exactly these elements
      w.list_header(v.size(), v.size() ? v.elem_wire() : type_of<E>());
      w.raw(v.region().first, v.region().size());
    }
  } else if constexpr (is_lazy_t<T>::value) {
    if (const auto* src = v.source()) write_struct(w, *src);
    else if (!v.region().empty()) w.raw(v.region().first, v.region().size());
    else w.fail("a nested message (lazy<M>) that was neither decoded nor set with lazy<M>::of()");
  } else if constexpr (std::is_same_v<T, empty_struct>) {
    w.u8(0);
  } else if constexpr (Message<T>) {
    write_struct(w, v);
  } else {
    static_assert(always_false<T>, "nanom thrift: unsupported member type");
  }
}

template <Message M, class W>
void write_struct(W& w, const M& m) {
  const auto saved_message = w.message, saved_field = w.field;
  w.message = describe<M>::name();
  std::int32_t last = 0;
  for_each_field<M>([&](auto f) {
    if (w.err) return;
    using F = member_t<decltype(f)::mem_ptr>;
    using V = typename F::value_type;
    w.field = decltype(f)::name.sv();
    const V& fv = (m.*(decltype(f)::mem_ptr)).v;
    const auto emit = [&](const auto& val) {
      using T = std::remove_cvref_t<decltype(val)>;
      std::uint8_t type = type_of<T>();
      if constexpr (std::is_same_v<T, bool>)
        type = val ? std::uint8_t(ctype::bool_true) : std::uint8_t(ctype::bool_false);
      const std::int32_t delta = std::int32_t(F::id) - last;
      if (delta >= 1 && delta <= 15) {
        w.u8(std::uint8_t((delta << 4) | type));
      } else {
        w.u8(type);
        w.varint(zigzag_encode(std::int16_t(F::id)));
      }
      last = F::id;
      if constexpr (!std::is_same_v<T, bool>) write_value<T>(w, val);
    };
    if constexpr (is_optional_t<V>::value) {
      if (fv) emit(*fv);
    } else {
      emit(fv);
    }
  });
  if (w.err) return;  // keep the innermost struct / field as the error location
  w.u8(0);
  w.message = saved_message;
  w.field = saved_field;
}

}  // namespace detail::tc

/// Encode m into `sink`. Returns the bytes written, or where and why it failed (on failure a
/// growable sink may hold a partial encoding; a span_sink is never written past its end).
template <Message M, byte_sink S>
expected<std::size_t, encode_error> thrift_compact_encode(const M& m, S& sink) {
  detail::tc::writer<S> w(sink);
  detail::tc::write_struct(w, m);
  w.flush();
  if (w.err) return unexpected<encode_error>(encode_error{w.err, w.message, w.field});
  return w.total;
}

/// Append the encoding of m to `out`.
template <Message M>
expected<std::size_t, encode_error> thrift_compact_encode(const M& m, std::vector<std::byte>& out) {
  vector_sink s{&out};
  return thrift_compact_encode(m, s);
}

/// The exact number of bytes thrift_compact_encode(m, …) writes (nothing is written).
template <Message M>
expected<std::size_t, encode_error> thrift_compact_size(const M& m) {
  counting_sink s;
  return thrift_compact_encode(m, s);
}

}  // namespace nanom

#endif  // NANOM_TAGGED_ENCODE_HPP_INCLUDED
