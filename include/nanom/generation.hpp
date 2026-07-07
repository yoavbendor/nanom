// SPDX-License-Identifier: Apache-2.0
// nanom/generation.hpp — opt-in wire-buffer generation tracking (NANOM_GENERATION).
//
// Compiled out entirely when NANOM_GENERATION=0. When enabled, register buffers with
// wire_arena and parse via from(span, arena); view::get/raw/to_struct validate that
// the arena generation is unchanged and the access lies in bounds.

#ifndef NANOM_GENERATION_HPP_INCLUDED
#define NANOM_GENERATION_HPP_INCLUDED

#include "prelude.hpp"

#if NANOM_GENERATION

#include <cstdio>
#include <exception>
#include <string>

#if defined(__cpp_lib_source_location) && __cpp_lib_source_location >= 201907L
#include <source_location>
#define NANOM_HAS_SOURCE_LOCATION 1
#else
#define NANOM_HAS_SOURCE_LOCATION 0
#endif

namespace nanom {

enum class gen_fault_kind : std::uint8_t {
  stale_generation,
  out_of_arena,
  null_arena,
  null_pointer,
};

enum class gen_action : std::uint8_t { abort, ignore };

/// Registration for a caller-owned wire buffer. Bump generation on invalidate()
/// (free, realloc, vector::clear, scope end).
struct wire_arena {
  const std::byte* base       = nullptr;
  std::size_t      size       = 0;
  std::uint64_t    generation = 1;
#if NANOM_HAS_SOURCE_LOCATION
  std::source_location opened{};
  std::source_location last_invalidate{};
#endif

  constexpr wire_arena() = default;

  constexpr wire_arena(const void* data, std::size_t n) noexcept
      : base(static_cast<const std::byte*>(data)), size(n) {}

  void open(const void* data, std::size_t n
#if NANOM_HAS_SOURCE_LOCATION
            ,
            std::source_location loc = std::source_location::current()
#endif
  ) noexcept {
    base = static_cast<const std::byte*>(data);
    size = n;
    ++generation;
#if NANOM_HAS_SOURCE_LOCATION
    opened = loc;
#endif
  }

  void invalidate(
#if NANOM_HAS_SOURCE_LOCATION
      std::source_location loc = std::source_location::current()
#endif
  ) noexcept {
    ++generation;
    base = nullptr;
    size = 0;
#if NANOM_HAS_SOURCE_LOCATION
    last_invalidate = loc;
#endif
  }

  [[nodiscard]] constexpr bool contains(const std::byte* p, std::size_t len) const noexcept {
    if (len == 0) return true;
    if (!base || !p) return false;
    const auto* end = base + size;
    return p >= base && p + len <= end;
  }
};

struct generation_fault {
  gen_fault_kind    kind = gen_fault_kind::null_pointer;
  const wire_arena* arena = nullptr;
  std::uint64_t     expected_gen = 0;
  std::uint64_t     actual_gen   = 0;
  const std::byte*  access_ptr     = nullptr;
  std::size_t       access_len     = 0;
  std::uint32_t     offset_in_arena = 0;
  const char*       site           = "";
};

using generation_handler_fn = gen_action (*)(const generation_fault&);

/// Optional fault hook (return ignore to continue — unsafe unless testing).
inline generation_handler_fn generation_handler = nullptr;

inline std::string render_generation_fault(const generation_fault& f) {
  std::string out = "nanom generation fault: ";
  switch (f.kind) {
    case gen_fault_kind::stale_generation: out += "stale_generation"; break;
    case gen_fault_kind::out_of_arena: out += "out_of_arena"; break;
    case gen_fault_kind::null_arena: out += "null_arena"; break;
    case gen_fault_kind::null_pointer: out += "null_pointer"; break;
  }
  if (f.site && f.site[0]) {
    out += "\n  at ";
    out += f.site;
  }
  if (f.arena) {
    out += "\n  arena: base=";
    char buf[24];
    std::snprintf(buf, sizeof buf, "%p", static_cast<const void*>(f.arena->base));
    out += buf;
    out += " size=" + std::to_string(f.arena->size);
    out += " gen expected=" + std::to_string(f.expected_gen);
    out += " actual=" + std::to_string(f.actual_gen);
#if NANOM_HAS_SOURCE_LOCATION
    if (f.arena->last_invalidate.line())
      out += "\n  last invalidate: " + std::string(f.arena->last_invalidate.file_name()) + ":" +
             std::to_string(f.arena->last_invalidate.line());
    if (f.arena->opened.line())
      out += "\n  arena opened: " + std::string(f.arena->opened.file_name()) + ":" +
             std::to_string(f.arena->opened.line());
#endif
  }
  out += "\n  access: offset " + std::to_string(f.offset_in_arena);
  out += " len " + std::to_string(f.access_len);
  if (f.arena && f.arena->base && f.access_ptr) {
    const std::size_t total = f.arena->size;
    const std::size_t off   = f.offset_in_arena;
    if (off < total) {
      const std::size_t lo = off >= 8 ? off - 8 : 0;
      const std::size_t hi = std::min(off + 8, total);
      static constexpr char hexd[] = "0123456789abcdef";
      std::string line = "  hex:", caret = "      ";
      for (std::size_t i = lo; i < hi; ++i) {
        const auto b = std::uint8_t(f.arena->base[i]);
        line += ' ';
        line += hexd[b >> 4];
        line += hexd[b & 15];
        caret += (i == off) ? " ^^" : "   ";
      }
      out += "\n" + line + "\n" + caret;
    }
  }
  out += "\n  hint: keep wire_arena alive while using view/bytes; call invalidate() on free/realloc";
  return out;
}

class generation_exception : public std::exception {
 public:
  explicit generation_exception(generation_fault f) : fault_(std::move(f)) {
    msg_ = render_generation_fault(fault_);
  }
  const char* what() const noexcept override { return msg_.c_str(); }
  const generation_fault& fault() const noexcept { return fault_; }

 private:
  generation_fault fault_;
  std::string      msg_;
};

namespace detail {
inline void dispatch_generation_fault(generation_fault f);
inline void check_wire_access(const wire_arena* arena, std::uint64_t expected_gen,
                              const std::byte* p, std::size_t len, const char* site);
}  // namespace detail

/// Zero-copy byte span with optional generation attestation. When arena is null
/// (untracked parse), subscript behaves like a plain span. When arena is set,
/// operator[] / at() validate generation and bounds before access.
struct attested_bytes {
  std::span<const std::byte> span_{};
  const wire_arena*          arena_ = nullptr;
  std::uint64_t              gen_   = 0;

  constexpr attested_bytes() = default;
  constexpr attested_bytes(std::span<const std::byte> s) noexcept : span_(s) {}
  constexpr attested_bytes(std::span<const std::byte> s, const wire_arena* a,
                           std::uint64_t g) noexcept
      : span_(s), arena_(a), gen_(g) {}
  constexpr attested_bytes(const std::byte* p, std::size_t n) noexcept : span_(p, n) {}
  constexpr attested_bytes(const std::byte* p, std::size_t n, const wire_arena* a,
                           std::uint64_t g) noexcept
      : span_(p, n), arena_(a), gen_(g) {}

  [[nodiscard]] constexpr const std::byte* data() const noexcept { return span_.data(); }
  [[nodiscard]] constexpr std::size_t      size() const noexcept { return span_.size(); }
  [[nodiscard]] constexpr bool             empty() const noexcept { return span_.empty(); }
  [[nodiscard]] constexpr auto             begin() const noexcept { return span_.begin(); }
  [[nodiscard]] constexpr auto             end() const noexcept { return span_.end(); }
  [[nodiscard]] constexpr std::span<const std::byte> unchecked_span() const noexcept {
    return span_;
  }

  [[nodiscard]] constexpr attested_bytes subspan(std::size_t offset,
                                                 std::size_t count) const noexcept {
    return attested_bytes{span_.subspan(offset, count), arena_, gen_};
  }

  [[nodiscard]] constexpr attested_bytes subspan(std::size_t offset) const noexcept {
    return attested_bytes{span_.subspan(offset), arena_, gen_};
  }

  NANOM_HD std::uint8_t operator[](std::size_t i) const {
    if consteval {
      return std::uint8_t(span_[i]);
    } else {
      detail::check_wire_access(arena_, gen_, span_.data(), span_.size(),
                                "attested_bytes::operator[]");
      return std::uint8_t(span_[i]);
    }
  }

  NANOM_HD std::uint8_t at(std::size_t i) const {
    if consteval {
      return std::uint8_t(span_[i]);
    } else {
      if (i >= span_.size()) {
        generation_fault f{};
        f.kind = gen_fault_kind::out_of_arena;
        f.arena = arena_;
        f.expected_gen = gen_;
        f.actual_gen = arena_ ? arena_->generation : 0;
        f.access_ptr = span_.data();
        f.access_len = span_.size();
        f.offset_in_arena =
            span_.data() && arena_ && arena_->base && span_.data() >= arena_->base
                ? std::uint32_t(std::size_t(span_.data() - arena_->base) + i)
                : 0;
        f.site = "attested_bytes::at";
        detail::dispatch_generation_fault(std::move(f));
      }
      detail::check_wire_access(arena_, gen_, span_.data(), span_.size(), "attested_bytes::at");
      return std::uint8_t(span_[i]);
    }
  }
};

namespace detail {
inline void dispatch_generation_fault(generation_fault f) {
  if (generation_handler) {
    if (generation_handler(f) == gen_action::ignore) return;
  }
  const std::string msg = render_generation_fault(f);
#if NANOM_GENERATION_THROW
  throw generation_exception(std::move(f));
#else
  std::fputs(msg.c_str(), stderr);
  std::fputc('\n', stderr);
  std::abort();
#endif
}

inline void check_wire_access(const wire_arena* arena, std::uint64_t expected_gen,
                              const std::byte* p, std::size_t len, const char* site) {
  if (!arena) return;  // untracked parse — no generation checks
  if (!p) {
    generation_fault f{};
    f.kind = gen_fault_kind::null_pointer;
    f.arena = arena;
    f.expected_gen = expected_gen;
    f.actual_gen = arena ? arena->generation : 0;
    f.access_ptr = p;
    f.access_len = len;
    f.site = site;
    dispatch_generation_fault(std::move(f));
    return;
  }
  if (arena->generation != expected_gen) {
    generation_fault f{};
    f.kind = gen_fault_kind::stale_generation;
    f.arena = arena;
    f.expected_gen = expected_gen;
    f.actual_gen = arena->generation;
    f.access_ptr = p;
    f.access_len = len;
    f.offset_in_arena =
        p >= arena->base ? std::uint32_t(std::size_t(p - arena->base)) : 0;
    f.site = site;
    dispatch_generation_fault(std::move(f));
    return;
  }
  if (!arena->contains(p, len)) {
    generation_fault f{};
    f.kind = gen_fault_kind::out_of_arena;
    f.arena = arena;
    f.expected_gen = expected_gen;
    f.actual_gen = arena->generation;
    f.access_ptr = p;
    f.access_len = len;
    f.offset_in_arena =
        p >= arena->base ? std::uint32_t(std::size_t(p - arena->base)) : 0;
    f.site = site;
    dispatch_generation_fault(std::move(f));
  }
}

}  // namespace detail
}  // namespace nanom

#endif  // NANOM_GENERATION
#endif  // NANOM_GENERATION_HPP_INCLUDED
