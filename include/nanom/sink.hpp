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

}  // namespace nanom

#endif  // NANOM_SINK_HPP_INCLUDED
