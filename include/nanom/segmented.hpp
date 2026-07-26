// SPDX-License-Identifier: Apache-2.0
// nanom/segmented.hpp — parsing over DISJOINT byte ranges (scatter-gather / "strudel" input).
//
// The core cursor (nom.hpp's `input`) is a contiguous [first,last) pointer pair, and stays that
// way: this header is the opt-in sibling for the one case that model cannot express — a logical
// buffer whose bytes live in several disjoint spans (the motivating consumer is IP fragment
// reassembly, examples/nano_shark/core/defrag.hpp, where a reassembled datagram's fragments sit
// scattered through the capture file). Design contract, in order of priority:
//
//   1. ZERO COST WHEN UNUSED. Nothing in nom.hpp/reflect.hpp changes; `input`, its layout, and
//      every combinator are untouched. Don't include this header, don't pay for it.
//   2. PAY ONLY AT THE SEAMS. A read that lies inside one segment compiles to the same
//      pointer-based code as the contiguous cursor; only a read that STRADDLES a segment
//      boundary pays — a bounded, stack-only gather of at most one struct's wire_size_v<T>
//      bytes (seg_window's inline buffer). Never a heap allocation, never a whole-buffer copy.
//   3. HONEST ZERO-COPY VIEWS. overlay_seg<T> hands out view<T> pointers into caller-owned
//      segment memory or fails with a recoverable error — it never points a view at a hidden
//      temporary. Straddling callers use strct_seg<T> (by value) instead.
//
// Deliberately NOT supported over segments (v1): the general combinator vocabulary
// (alt/many0/tag/take_until/dec/hex/...) — the text-oriented members need physically contiguous
// memory (`from_chars`, `memcmp`, `std::search`) and cannot be segmented without copies. What IS
// here: the struct parsers (strct_seg/overlay_seg), a small cursor kit for hand-rolled walkers
// (seg_u8/seg_be16/seg_be32/...), and zero-copy narrowing (subrange). Bit FIELDS inside a
// described struct work fine — they decode from the gathered window like every other field.

#ifndef NANOM_SEGMENTED_HPP_INCLUDED
#define NANOM_SEGMENTED_HPP_INCLUDED

#include "reflect.hpp"  // pulls in nom.hpp (error/expected/result plumbing) + strct/view machinery

namespace nanom {

/// Upper bound on the number of parts a seg_subrange can carry inline (subrange() returns nullopt
/// past it — no allocation, ever). 64 covers IP fragmentation's worst case with headroom: a 64 KiB
/// datagram over IPv6's 1280-byte minimum MTU is ~52 fragments. Override with -DNANOM_SEG_MAX_PARTS.
#ifndef NANOM_SEG_MAX_PARTS
#define NANOM_SEG_MAX_PARTS 64
#endif
inline constexpr std::size_t seg_max_parts = NANOM_SEG_MAX_PARTS;

// ---------------------------------------------------------------------------
// segments — an ordered list of disjoint byte ranges viewed as one logical buffer
// ---------------------------------------------------------------------------

/// Non-owning: both the part-descriptor array AND the bytes the parts point at are caller-owned
/// and must outlive the segments object (same lifetime contract as input over a span). Under
/// NANOM_GENERATION one optional {arena, gen} pair attests ALL parts (the motivating consumer's
/// fragments all point into one capture buffer); multi-arena segments are a v1 non-goal.
class segments {
 public:
  constexpr segments() = default;
  explicit constexpr segments(std::span<const std::span<const std::byte>> parts NANOM_LIFETIMEBOUND)
      : parts_(parts) {
    for (const auto& p : parts_) total_ += p.size();
  }
#if NANOM_GENERATION
  constexpr segments(std::span<const std::span<const std::byte>> parts NANOM_LIFETIMEBOUND,
                     const wire_arena* arena, std::uint64_t gen)
      : segments(parts) {
    arena_ = arena;
    gen_   = gen;
  }
#endif

  [[nodiscard]] constexpr std::size_t size() const { return total_; }   ///< total logical bytes
  [[nodiscard]] constexpr std::size_t parts() const { return parts_.size(); }
  [[nodiscard]] constexpr std::span<const std::byte> part(std::size_t i) const { return parts_[i]; }

  /// Byte at logical offset i (linear in parts; for diagnostics, not hot paths).
  [[nodiscard]] constexpr std::uint8_t byte_at(std::size_t i) const {
    for (const auto& p : parts_) {
      if (i < p.size()) return std::uint8_t(p[i]);
      i -= p.size();
    }
    return 0;  // out of range: callers bounds-check first (render() clamps)
  }

#if NANOM_GENERATION
  [[nodiscard]] constexpr const wire_arena* arena() const { return arena_; }
  [[nodiscard]] constexpr std::uint64_t     gen() const { return gen_; }
#endif

 private:
  std::span<const std::span<const std::byte>> parts_{};
  std::size_t                                 total_ = 0;
#if NANOM_GENERATION
  const wire_arena* arena_ = nullptr;
  std::uint64_t     gen_   = 0;
#endif
};

// ---------------------------------------------------------------------------
// seg_window — a gathered N-byte read window (N compile-time, e.g. wire_size_v<T>)
// ---------------------------------------------------------------------------

/// Either a zero-copy pointer into segment memory (fast path — the window fell inside one part)
/// or a stack copy in the inline buffer (slow path — the window straddled a boundary). data()
/// resolves which, so the object is safely copyable either way (the buffer travels by value; an
/// external pointer stays valid as long as the underlying segment memory does).
template <std::size_t N>
class seg_window {
 public:
  [[nodiscard]] NANOM_HD constexpr const std::byte* data() const {
    return ext_ ? ext_ : buf_.data();
  }
  [[nodiscard]] constexpr bool zero_copy() const { return ext_ != nullptr; }

 private:
  friend struct seg_input;
  const std::byte*         ext_ = nullptr;
  std::array<std::byte, N> buf_;  // deliberately uninitialized: the fast path never touches it,
                                  // and zeroing it would put a memset on every windowed parse
};

class seg_subrange;  // fwd (zero-copy narrowing, defined after seg_input)

// ---------------------------------------------------------------------------
// seg_input — the cursor
// ---------------------------------------------------------------------------

/// Mirrors input's member API (size/empty/offset/operator[]/safe_at/advance/checked_advance) so
/// cursor-generic helper code can be written against either. Hot fields are raw pointers into the
/// CURRENT part, so within-segment reads are a pointer compare + deref, exactly like `input`.
/// The segments descriptor travels BY VALUE inside the cursor, so only the part-descriptor ARRAY
/// (and the bytes) must outlive it -- from(owner.view()) with a temporary `segments` is safe.
/// Invariant: cur == nullptr  <=>  the cursor is exhausted (empty parts are always skipped over).
struct seg_input {
  segments         src{};              ///< the part list, by value
  std::size_t      seg_i   = 0;        ///< current part index
  const std::byte* cur     = nullptr;  ///< cursor within the current part
  const std::byte* seg_end = nullptr;  ///< current part's end
  std::size_t      abs     = 0;        ///< absolute logical offset (error::offset)
  bool             live    = false;    ///< streaming flag; same error-kind contract as input

  constexpr seg_input() = default;
  explicit constexpr seg_input(segments s) : src(s) { enter(0); }

  [[nodiscard]] constexpr std::size_t size() const { return src.size() - abs; }
  [[nodiscard]] constexpr bool        empty() const { return cur == nullptr; }
  [[nodiscard]] constexpr std::size_t offset() const { return abs; }

  /// Remaining bytes of the CURRENT part only — the zero-copy fast-path probe.
  [[nodiscard]] constexpr std::span<const std::byte> contiguous() const {
    return cur ? std::span<const std::byte>(cur, std::size_t(seg_end - cur))
               : std::span<const std::byte>{};
  }

  /// Unchecked cross-part indexed read (precondition: i < size(), like input::operator[]).
  [[nodiscard]] constexpr std::uint8_t operator[](std::size_t i) const {
    const std::byte* c = cur;
    const std::byte* e = seg_end;
    std::size_t      si = seg_i;
    while (true) {
      const std::size_t here = std::size_t(e - c);
      if (i < here) return std::uint8_t(c[i]);
      i -= here;
      do { ++si; } while (src.part(si).empty());  // precondition guarantees a next byte exists
      const auto p = src.part(si);
      c = p.data();
      e = p.data() + p.size();
    }
  }

  /// Bounds-checked index; empty when i >= size().
  [[nodiscard]] constexpr std::optional<std::uint8_t> safe_at(std::size_t i) const {
    if (i >= size()) return std::nullopt;
    return (*this)[i];
  }

  /// Cursor advanced by n logical bytes (precondition: n <= size(); clamps at end otherwise,
  /// mirroring input::advance's precondition contract).
  [[nodiscard]] constexpr seg_input advance(std::size_t n) const {
    seg_input o = *this;
    o.abs += n;
    while (o.cur) {
      const std::size_t here = std::size_t(o.seg_end - o.cur);
      if (n < here) {
        o.cur += n;
        return o;
      }
      n -= here;
      o.enter(o.seg_i + 1);
      if (n == 0) return o;
    }
    o.abs = src.size();  // clamped
    return o;
  }

  /// Bounds-checked advance; empty when n > size().
  [[nodiscard]] constexpr std::optional<seg_input> checked_advance(std::size_t n) const {
    if (n > size()) return std::nullopt;
    return advance(n);
  }

  /// THE key primitive: an N-byte read window at the cursor. Fast path (window inside the current
  /// part): w points at segment memory, no copy. Slow path (straddles >= 1 boundary): gathers the
  /// N bytes into w's inline stack buffer. Returns false when fewer than N bytes remain.
  template <std::size_t N>
  constexpr bool gather(seg_window<N>& w) const {
    if (cur != nullptr && std::size_t(seg_end - cur) >= N) {  // fast path first
      w.ext_ = cur;
      return true;
    }
    if (size() < N) return false;
    w.ext_ = nullptr;
    std::size_t      got = 0;
    const std::byte* c   = cur;
    const std::byte* e   = seg_end;
    std::size_t      si  = seg_i;
    while (got < N) {
      const std::size_t here = std::min(N - got, std::size_t(e - c));
      for (std::size_t k = 0; k < here; ++k) w.buf_[got + k] = c[k];  // -O2 lowers to memcpy
      got += here;
      if (got == N) break;
      do { ++si; } while (src.part(si).empty());  // size() >= N guarantees a next part
      const auto p = src.part(si);
      c = p.data();
      e = p.data() + p.size();
    }
    return true;
  }

  /// Convenience form; the returned window is safely copyable (see seg_window).
  template <std::size_t N>
  [[nodiscard]] constexpr std::optional<seg_window<N>> gather() const {
    std::optional<seg_window<N>> out(std::in_place);
    if (!gather(*out)) return std::nullopt;
    return out;
  }

  /// Runtime-length gather into caller storage (take-style needs). False when short.
  constexpr bool gather(std::span<std::byte> dst) const {
    if (size() < dst.size()) return false;
    std::size_t      got = 0;
    const std::byte* c   = cur;
    const std::byte* e   = seg_end;
    std::size_t      si  = seg_i;
    while (got < dst.size()) {
      const std::size_t here = std::min(dst.size() - got, std::size_t(e - c));
      for (std::size_t k = 0; k < here; ++k) dst[got + k] = c[k];
      got += here;
      if (got == dst.size()) break;
      do { ++si; } while (src.part(si).empty());
      const auto p = src.part(si);
      c = p.data();
      e = p.data() + p.size();
    }
    return true;
  }

  /// Zero-copy narrowing: the next n logical bytes as a self-contained part list (first/last
  /// parts trimmed via subspan). Defined after seg_subrange below.
  [[nodiscard]] constexpr std::optional<seg_subrange> subrange(std::size_t n) const;

#if NANOM_GENERATION
  [[nodiscard]] constexpr const wire_arena* arena() const { return src.arena(); }
  [[nodiscard]] constexpr std::uint64_t     gen() const { return src.gen(); }
#endif

 private:
  /// Position at the start of part i, skipping empty parts; null cursor once exhausted.
  constexpr void enter(std::size_t i) {
    seg_i = i;
    while (seg_i < src.parts()) {
      const auto p = src.part(seg_i);
      if (!p.empty()) {
        cur     = p.data();
        seg_end = p.data() + p.size();
        return;
      }
      ++seg_i;
    }
    cur = seg_end = nullptr;
  }
};

constexpr seg_input from(segments s) { return seg_input(s); }
constexpr seg_input streaming(seg_input in) {
  in.live = true;
  return in;
}

/// Owner for the common single-part case: keeps the one part descriptor inline so callers can
/// wrap a contiguous payload as segmented input without managing a separate descriptor array.
/// Must outlive any cursor made from view() (the cursor copies the `segments` value, but that
/// value points at THIS object's descriptor).
class single_segment {
 public:
  explicit constexpr single_segment(std::span<const std::byte> s NANOM_LIFETIMEBOUND) : part_(s) {}
#if NANOM_GENERATION
  constexpr single_segment(std::span<const std::byte> s NANOM_LIFETIMEBOUND,
                           const wire_arena* arena, std::uint64_t gen)
      : part_(s), arena_(arena), gen_(gen) {}
  /// From attested bytes: carry the arena/gen through so overlay_seg<T> views over this segment
  /// stay generation-checked, exactly as from(bytes) does for the contiguous cursor. (Under
  /// NANOM_GENERATION, nanom::bytes IS attested_bytes, so `single_segment{payload}` selects this.)
  explicit single_segment(const attested_bytes& b)
      : part_(b.unchecked_span()), arena_(b.arena_), gen_(b.gen_) {}
#endif
  [[nodiscard]] constexpr segments view() const NANOM_LIFETIMEBOUND {
#if NANOM_GENERATION
    return segments{std::span<const std::span<const std::byte>>(&part_, 1), arena_, gen_};
#else
    return segments{std::span<const std::span<const std::byte>>(&part_, 1)};
#endif
  }

 private:
  std::span<const std::byte> part_;
#if NANOM_GENERATION
  const wire_arena* arena_ = nullptr;
  std::uint64_t     gen_   = 0;
#endif
};

// ---------------------------------------------------------------------------
// seg_subrange — zero-copy narrowing (owns its part descriptors inline)
// ---------------------------------------------------------------------------

/// A subrange cannot alias the parent's part array (its first/last descriptors are trimmed), so it
/// carries its own inline descriptor array — allocation-free, capped at seg_max_parts intersecting
/// parts (subrange() returns nullopt past the cap; gather into owned storage as the fallback).
/// ~1 KiB by value at the default cap: fine as a local, don't store thousands.
class seg_subrange {
 public:
  /// View over this object's own descriptors — this seg_subrange must outlive it (and any cursor
  /// made from it).
  [[nodiscard]] constexpr segments view() const NANOM_LIFETIMEBOUND {
#if NANOM_GENERATION
    return segments{std::span<const std::span<const std::byte>>(parts_.data(), count_), arena_, gen_};
#else
    return segments{std::span<const std::span<const std::byte>>(parts_.data(), count_)};
#endif
  }
  [[nodiscard]] constexpr std::size_t size() const { return total_; }
  [[nodiscard]] constexpr std::size_t parts() const { return count_; }

 private:
  friend struct seg_input;
  std::array<std::span<const std::byte>, seg_max_parts> parts_{};
  std::size_t                                           count_ = 0;
  std::size_t                                           total_ = 0;
#if NANOM_GENERATION
  const wire_arena* arena_ = nullptr;
  std::uint64_t     gen_   = 0;
#endif
};

constexpr std::optional<seg_subrange> seg_input::subrange(std::size_t n) const {
  if (n > size()) return std::nullopt;
  seg_subrange out;
#if NANOM_GENERATION
  out.arena_ = arena();
  out.gen_   = gen();
#endif
  out.total_ = n;
  const std::byte* c  = cur;
  const std::byte* e  = seg_end;
  std::size_t      si = seg_i;
  while (n > 0) {
    if (out.count_ == seg_max_parts) return std::nullopt;  // over the inline cap
    const std::size_t here = std::min(n, std::size_t(e - c));
    out.parts_[out.count_++] = std::span<const std::byte>(c, here);
    n -= here;
    if (n == 0) break;
    do { ++si; } while (src.part(si).empty());
    const auto p = src.part(si);
    c = p.data();
    e = p.data() + p.size();
  }
  return out;
}

// ---------------------------------------------------------------------------
// results + errors (parallel carriers; done<T>/make_err in nom.hpp stay input-typed)
// ---------------------------------------------------------------------------

template <class T>
struct seg_done {
  using type = T;
  T         value;
  seg_input rest;
};
template <class T>
seg_done(T, seg_input) -> seg_done<T>;

template <class T>
using seg_result = expected<seg_done<T>, error>;  // reuses nanom::error verbatim

inline unexpected<error> seg_make_err(const seg_input& at, const char* expected) {
  error e;
  e.kind     = errk::err;
  e.offset   = std::uint32_t(at.offset());
  e.expected = expected;
  return unexp(e);
}
inline unexpected<error> seg_make_incomplete(const seg_input& at, std::size_t needed) {
  error e;
  e.kind     = at.live ? errk::incomplete : errk::err;
  e.offset   = std::uint32_t(at.offset() + at.size());
  e.expected = "more input";
  e.needed   = std::uint32_t(std::min(needed, std::size_t(max_incomplete_needed)));
  return unexp(e);
}

/// error::render's segmented twin: same message shape, hex window via segments::byte_at.
inline std::string render(const error& e, const segments& whole) {
  std::string out;
  out += "parse ";
  out += e.kind == errk::incomplete ? "incomplete" : e.kind == errk::fail ? "failure" : "error";
  out += " at offset " + std::to_string(e.offset);
  if (e.needed) out += " (need " + std::to_string(e.needed) + " more byte(s))";
  out += ": expected ";
  out += e.expected;
  for (std::uint8_t i = 0; i < e.nctx; ++i) {
    out += "\n  in ";
    out += e.ctx[i].label;
    out += " (starting at offset " + std::to_string(e.ctx[i].offset) + ")";
  }
  const std::size_t total = whole.size();
  const std::size_t off   = std::min<std::size_t>(e.offset, total);
  if (e.offset > total) out += " (offset beyond input, hex window clamped)";
  if (total > 0) {
    const std::size_t lo = off >= 8 ? off - 8 : 0;
    const std::size_t hi = std::min(off + 8, total);
    static constexpr char hexd[] = "0123456789abcdef";
    std::string line = "  ", caret = "  ";
    for (std::size_t i = lo; i < hi; ++i) {
      const auto b = whole.byte_at(i);
      line += hexd[b >> 4];
      line += hexd[b & 15];
      line += ' ';
      caret += (i == off) ? "^^ " : "   ";
    }
    if (off == total) caret += "^^ (end of input)";
    out += "\n" + line + "\n" + caret;
  }
  return out;
}

// ---------------------------------------------------------------------------
// struct parsing over segments — strct_seg<T>() / overlay_seg<T>()
// ---------------------------------------------------------------------------

/// strct<T>'s segmented twin: identical decode (the same detail::assign_field walk reflect.hpp's
/// strct uses — decode_field/assign_field already take a raw pointer, so segmentation is solved
/// entirely by WINDOWING one level above). Within-part parses are zero-copy reads off segment
/// memory; a straddling parse gathers wire_size_v<T> bytes onto the stack first.
template <Described T>
constexpr auto strct_seg(std::endian dflt = std::endian::native) {
  static_assert(detail::layout_ok<T>(),
                "nanom: bit fields must pack to byte boundaries and every "
                "non-bit field must start byte-aligned");
  return [dflt](seg_input in) -> seg_result<T> {
    constexpr std::size_t need = wire_size_v<T>;
    seg_window<need>      w;
    if (!in.gather(w)) return seg_make_incomplete(in, need - in.size());
    T out{};
    constexpr auto offs = detail::field_bit_offsets<T>();
    std::size_t    i    = 0;
    detail::for_each_field<T>([&](auto f) {
      out.*(decltype(f)::mem_ptr) =
          detail::assign_field<detail::member_t<decltype(f)::mem_ptr>>(w.data(), offs[i++], dflt);
    });
    return seg_done{std::move(out), in.advance(need)};
  };
}

// ---------------------------------------------------------------------------
// cursor kit — scalar reads for hand-rolled walkers (SOME/IP-style TLV cursors)
// ---------------------------------------------------------------------------
// Each is a thin wrapper over gather<N>/advance, replacing `rd_be16(p + off)`-style raw pointer
// arithmetic in consumer code. All return seg_result so short input reports exactly like the
// struct parsers (incomplete on a live cursor, recoverable err otherwise).

namespace detail_seg {
template <std::size_t N, std::endian E>
constexpr seg_result<detail::uint_for_bytes<N>> seg_uint(seg_input in) {
  seg_window<N> w;
  if (!in.gather(w)) return seg_make_incomplete(in, N - in.size());
  using U = detail::uint_for_bytes<N>;
  U u = 0;
  const std::byte* p = w.data();
  if constexpr (E == std::endian::big)
    for (std::size_t i = 0; i < N; ++i) u = U(U(u << 8) | std::uint8_t(p[i]));
  else
    for (std::size_t i = 0; i < N; ++i) u |= U(U(std::uint8_t(p[i])) << (8 * i));
  return seg_done{u, in.advance(N)};
}
}  // namespace detail_seg

constexpr seg_result<std::uint8_t> seg_u8(seg_input in) {
  return detail_seg::seg_uint<1, std::endian::big>(in);
}
constexpr seg_result<std::uint16_t> seg_be16(seg_input in) {
  return detail_seg::seg_uint<2, std::endian::big>(in);
}
constexpr seg_result<std::uint32_t> seg_be32(seg_input in) {
  return detail_seg::seg_uint<4, std::endian::big>(in);
}
constexpr seg_result<std::uint64_t> seg_be64(seg_input in) {
  return detail_seg::seg_uint<8, std::endian::big>(in);
}
constexpr seg_result<std::uint16_t> seg_le16(seg_input in) {
  return detail_seg::seg_uint<2, std::endian::little>(in);
}
constexpr seg_result<std::uint32_t> seg_le32(seg_input in) {
  return detail_seg::seg_uint<4, std::endian::little>(in);
}
constexpr seg_result<std::uint64_t> seg_le64(seg_input in) {
  return detail_seg::seg_uint<8, std::endian::little>(in);
}

/// Skip n bytes (bounds-checked take-nothing).
constexpr seg_result<unit> seg_skip(seg_input in, std::size_t n) {
  if (in.size() < n) return seg_make_incomplete(in, n - in.size());
  return seg_done{unit{}, in.advance(n)};
}

/// Gathering take: copy the next n bytes into caller storage (dst.size() == n).
constexpr seg_result<unit> seg_take(seg_input in, std::span<std::byte> dst) {
  if (!in.gather(dst)) return seg_make_incomplete(in, dst.size() - in.size());
  return seg_done{unit{}, in.advance(dst.size())};
}

/// overlay<T>'s segmented twin: ZERO-COPY OR ERROR, never a hidden copy. When the struct's window
/// lies inside the current part, the returned view<T> points straight at segment memory (arena/gen
/// threaded through when generation tracking is on). When it straddles a boundary, a view would
/// have to point at a temporary — dishonest — so this fails with a recoverable error instead;
/// parse straddling structs by value with strct_seg<T>().
template <Described T>
constexpr auto overlay_seg(std::endian dflt = std::endian::native) {
  static_assert(detail::layout_ok<T>(),
                "nanom: bit fields must pack to byte boundaries and every "
                "non-bit field must start byte-aligned");
  return [dflt](seg_input in) -> seg_result<view<T>> {
    constexpr std::size_t need = wire_size_v<T>;
    if (in.size() < need) return seg_make_incomplete(in, need - in.size());
    if (in.contiguous().size() < need)
      return seg_make_err(in, "contiguous view (struct straddles a segment boundary; use strct_seg)");
#if NANOM_GENERATION
    return seg_done{view<T>{in.contiguous().data(), dflt, in.arena(), in.gen()}, in.advance(need)};
#else
    return seg_done{view<T>{in.contiguous().data(), dflt}, in.advance(need)};
#endif
  };
}

}  // namespace nanom

#endif  // NANOM_SEGMENTED_HPP_INCLUDED
