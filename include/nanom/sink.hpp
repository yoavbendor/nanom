// SPDX-License-Identifier: Apache-2.0
// nanom/sink.hpp — where encoders write: byte sinks and the encode error type. Shared by the
// write-side headers (nanom/tagged_encode.hpp, nanom/emit.hpp); reading code never includes it.
#ifndef NANOM_SINK_HPP_INCLUDED
#define NANOM_SINK_HPP_INCLUDED

#include "prelude.hpp"

#include <cstring>
#include <span>
#include <string_view>
#include <vector>

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
    if (n) {
      const std::size_t off = out->size();
      out->resize(off + n);
      std::memcpy(out->data() + off, p, n);
    }
    return true;
  }
  /// Reserve `n` zero-initialized bytes at the end of `*out` and return their starting offset
  /// (safe across subsequent vector reallocations, for back-patching headers or length prefixes).
  std::size_t reserve_slot(std::size_t n) {
    const std::size_t off = out->size();
    out->resize(off + n, std::byte{0});
    return off;
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
  /// Reserve `n` bytes in-place and return a mutable span over them for back-patching
  /// (returns std::nullopt without advancing `used` if fewer than `n` bytes remain).
  std::optional<std::span<std::byte>> reserve(std::size_t n) {
    if (n > out.size() - used) return std::nullopt;
    auto slot = out.subspan(used, n);
    used += n;
    return slot;
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

namespace detail {

/// Shared 256-byte staging buffer for encoders (Thrift compact, Protobuf, etc.).
/// Batches small writes (tags, varints, fixed scalars) and streams large payloads
/// straight through to the sink. Once `err` is set, all subsequent writes are no-ops.
template <byte_sink S>
struct buffered_writer {
  S&           sink;
  const char*& err;
  std::size_t  total = 0;
  std::size_t  len   = 0;
  std::byte    buf[256];

  buffered_writer(S& s, const char*& err_slot) noexcept : sink(s), err(err_slot) {}

  void fail(const char* what) noexcept {
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
    if (sizeof(buf) - len < 10) flush();  // max ULEB128 for uint64_t is 10 bytes
    if (err) return;
    do {
      std::uint8_t b = std::uint8_t(v & 0x7fu);
      v >>= 7;
      if (v) b |= 0x80u;
      buf[len++] = std::byte(b);
    } while (v);
  }
  void fixed_le(std::uint64_t u, std::size_t n) {
    if (sizeof(buf) - len < 8) flush();
    if (err) return;
    for (std::size_t i = 0; i < n; ++i) buf[len++] = std::byte(std::uint8_t(u >> (8 * i)));
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
};

}  // namespace detail

}  // namespace nanom

#endif  // NANOM_SINK_HPP_INCLUDED
