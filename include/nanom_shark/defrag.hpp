// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/core/defrag.hpp — IPv4/IPv6 fragment reassembly. New: no precedent anywhere in the
// nano-family (nanom/nanotins detect fragmentation and stop the walk; nothing reassembles).
//
// Fragments arrive non-contiguously in the source file, so "the datagram" is a set of disjoint
// byte ranges. Reassembly is now FULLY ZERO-COPY: on completion, add_fragment returns an ordered,
// overlap-trimmed list of VIEWS into the source buffer (Result::parts, a nanom::segments), and the
// L4 re-entry parses straight over it with strct_seg -- no stitched buffer is ever built. This is
// what nanom/segmented.hpp exists for: it teaches nanom to parse a logical buffer split across
// disjoint spans, decoding each struct off the segment it lies in (a bounded, stack-only gather
// only when a struct straddles a fragment seam -- never a whole-datagram copy). The earlier design
// (an owned std::vector<std::byte> stitched once per completed datagram) is gone; a lazy
// materialize() escape hatch remains for the rare consumer that genuinely needs one contiguous
// buffer, and it is the only place a copy can still happen -- and only if asked.
//
// (Historical note: this file once documented segmented parsing as impractical -- "a join_view
// over disjoint spans is only a forward_range, can't yield the pointer+length pair the parser
// needs, so teaching the core cursor to understand segmented input would be a real change to the
// LIBRARY, out of scope." That library change is exactly what nanom/segmented.hpp is. The insight
// that made it cheap: nanom's field decode (detail::decode_field/assign_field) already takes a raw
// pointer, so segmentation is solved by WINDOWING one level above it -- the ~124 core combinators
// never had to change at all.)
//
// Known scope trim: decode_pass.hpp re-enters L4 parsing over the reassembled segments via a plain
// nanom::from(result.parts) (an "unattested" segments), not a dedicated NANOM_GENERATION wire_arena
// scoped to the Reassembly's lifetime. Functionally complete either way; wiring a per-datagram
// arena would add use-after-evict detection on TOP of that (catching a stale view<T> that outlives
// evict_stale()) as a follow-up hardening pass, not a correctness requirement for reassembly.
//
// ---- Buffer lifetime: the Token contract -----------------------------------------------------
//
// The spans above are views into whatever buffer the fragment's packet came from. The whole-file
// decode pass keeps the entire capture resident, so "when may that buffer be reused?" never had to
// be answered. A STREAMING caller (nanom_shark/streaming.hpp), which feeds one EPB at a time out of
// a bounded buffer pool, does need an answer -- and it has to be correct by construction, not by
// convention.
//
// So every fragment carries a caller-opaque `Token` (a ring-slot index, a pointer cast to an
// integer -- this table never interprets it, only hands it back). A token is pinned by AT MOST ONE
// Reassembly at a time, because one packet contributes at most one fragment. There are exactly two
// release events, and each now reports the tokens it frees:
//
//   1. retire(datagram_id)  -- the COMPLETION release. Genuinely clears the entry's `fragments`
//      and `parts` (so not one span survives) and returns their tokens. It must be called AFTER
//      the caller has finished dispatching over Result::parts, since those parts are a view into
//      the entry's own `parts` storage. Optional: the whole-file path may skip it entirely and
//      nothing observable changes (the summary integers a retired entry still needs -- total_length,
//      fragment_count, the coverage high-water mark -- are maintained incrementally, not re-derived
//      from the spans).
//   2. evict_stale()        -- the AGE-OUT release. Already erased the entry outright; it now
//      reports the tokens that entry held, in ReassemblySummary::tokens.
//
// A packet that is not a fragment never reaches add_fragment() at all, so its token is free the
// moment the per-packet walk returns -- that half of the contract needs no support here.

#include <nanom/nanom.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <unordered_map>
#include <vector>

#include <nanom_shark/node_row.hpp>

namespace nanom_shark::defrag {

// "The buffer this fragment's bytes live in", from the caller's point of view -- opaque to this
// file, which only stores it and hands it back. kNoToken means "untracked": the caller is not
// managing this buffer's lifetime (the whole-file path), and it is never reported as released.
using Token = std::uint64_t;
inline constexpr Token kNoToken = 0;

struct Ipv4Key {
  std::array<std::uint8_t, 4> src, dst;
  std::uint8_t                proto;
  std::uint16_t               ident;
  bool operator==(const Ipv4Key&) const = default;
};
struct Ipv6Key {
  std::array<std::uint8_t, 16> src, dst;
  std::uint32_t                ident;
  bool operator==(const Ipv6Key&) const = default;
};

// Plain hasher functors (rather than std::hash<Ipv4Key>/std::hash<Ipv6Key> specializations) so
// ReassemblyTable's unordered_map member never depends on a std::hash specialization being visible
// at its own point of instantiation.
struct Ipv4KeyHash {
  std::size_t operator()(const Ipv4Key& k) const noexcept {
    std::uint64_t h = 1469598103934665603ull;
    auto mix = [&](std::uint64_t v) { h = (h ^ v) * 1099511628211ull; };
    for (auto b : k.src) mix(b);
    for (auto b : k.dst) mix(b);
    mix(k.proto);
    mix(k.ident);
    return std::size_t(h);
  }
};
struct Ipv6KeyHash {
  std::size_t operator()(const Ipv6Key& k) const noexcept {
    std::uint64_t h = 1469598103934665603ull;
    auto mix = [&](std::uint64_t v) { h = (h ^ v) * 1099511628211ull; };
    for (auto b : k.src) mix(b);
    for (auto b : k.dst) mix(b);
    mix(k.ident);
    return std::size_t(h);
  }
};
template <class Key> struct key_hash_for;
template <> struct key_hash_for<Ipv4Key> { using type = Ipv4KeyHash; };
template <> struct key_hash_for<Ipv6Key> { using type = Ipv6KeyHash; };

// One reassembly attempt's outcome, whether it finished cleanly or was cleaned up. Used both right
// after a completing add_fragment() call and for entries evict_stale() removes.
struct ReassemblySummary {
  std::uint32_t datagram_id      = 0;
  std::uint32_t total_length     = 0;   // 0 if the terminal fragment was never seen
  std::uint32_t fragment_count   = 0;
  packet_id_t   first_packet_id  = kNoPacket;
  packet_id_t   last_packet_id   = kNoPacket;
  std::uint8_t  completion_status = 0;  // 0=complete 1=timed_out 2=evicted_capacity 3=overlap_conflict
  std::uint32_t gap_bytes        = 0;   // total_length - covered bytes (0 once complete)
  // Buffer tokens this entry still pinned when it was evicted -- now safe for the caller to reuse.
  // Empty for an entry already retire()d (it gave its tokens back at completion time) and for a
  // caller that never passed tokens at all. Only ever populated by evict_stale().
  std::vector<Token> tokens;
};

namespace detail {

struct FragmentSpan {
  std::uint32_t               offset_bytes;
  packet_id_t                 packet_id;
  bool                        more_fragments;
  std::span<const std::byte>  data;  // a VIEW into the caller's source buffer, not a copy -- valid
                                     // until this entry is retire()d or evicted (see file header)
  Token                       token = kNoToken;  // which caller buffer `data` points into
};

struct Reassembly {
  std::uint32_t              datagram_id = 0;
  std::vector<FragmentSpan>  fragments;       // unordered as received; cleared by retire()
  std::uint32_t              total_length = 0;
  bool                       have_last = false;
  bool                       conflict = false;   // two fragments disagree on an overlapping byte range
  packet_id_t                first_packet_id = kNoPacket;
  packet_id_t                last_packet_id  = kNoPacket;
  bool                       completed = false;
  bool                       retired = false;    // retire() dropped every span this entry held
  // Summary integers maintained as fragments arrive rather than re-derived from `fragments`, so
  // they survive retire() clearing the spans. Both are exactly what the old re-derivation computed.
  std::uint32_t              fragment_count = 0;  // == fragments.size() before retire()
  std::uint32_t              covered_high = 0;    // max(offset_bytes + data.size()) over fragments
  // Once complete: the datagram as an ordered, overlap-trimmed list of VIEWS into the source
  // buffer -- zero-copy (see nanom/segmented.hpp). Consumers parse straight over these via
  // seg_input; nothing is ever stitched unless materialize() is explicitly called.
  std::vector<std::span<const std::byte>> parts;
  std::vector<std::byte>                  materialized;  // lazy; see ReassemblyTable::materialize
};

// Compare `want` against the datagram content already emitted in `parts` at logical offset
// `at` (parts are contiguous from 0, in order). Used for overlap conflict detection -- the
// segmented equivalent of comparing against the stitched buffer's bytes.
inline bool range_equals(const std::vector<std::span<const std::byte>>& parts, std::size_t at,
                         std::span<const std::byte> want) {
  std::size_t skip = at, wi = 0;
  for (const auto& p : parts) {
    if (skip >= p.size()) {
      skip -= p.size();
      continue;
    }
    const std::size_t here = std::min(p.size() - skip, want.size() - wi);
    if (std::memcmp(p.data() + skip, want.data() + wi, here) != 0) return false;
    wi += here;
    skip = 0;
    if (wi == want.size()) return true;
  }
  return wi == want.size();
}

}  // namespace detail

template <class Key>
class ReassemblyTable {
 public:
  struct Config {
    std::size_t   max_datagram_bytes = 64 * 1024;
    std::size_t   max_concurrent     = 4096;
    std::uint64_t timeout_ticks      = 30;   // deterministic proxy: packet_id delta, not wall-clock
  };
  explicit ReassemblyTable(Config cfg = {}) : cfg_(cfg) {}

  // The datagram_id is always returned (even mid-reassembly, so the caller can attach it to a
  // per-fragment forensic row) -- only `completed`/`parts` depend on whether this call finished
  // reassembly (no gaps in [0,total_length), a terminal fragment seen, no content conflict).
  struct Result {
    std::uint32_t   datagram_id = 0;
    bool            completed   = false;
    // True when this call actually STORED the fragment's span (so the caller's buffer is now
    // pinned by this table until the entry is retire()d or evicted). False when the fragment was
    // dropped instead -- at capacity, or oversized -- in which case nothing was retained and the
    // caller's buffer is free the moment add_fragment returns.
    bool            retained    = false;
    // The completed datagram as ZERO-COPY segments: ordered, overlap-trimmed views into the
    // source buffer, ready for nanom::from(parts) -> strct_seg/seg_* parsing (see segmented.hpp).
    // The part descriptors live in this table's Reassembly entry: valid until that entry is
    // evicted (the same lifetime the old stitched-buffer span had). Empty unless completed.
    nanom::segments parts;
  };

  // Feed one fragment (already offset/MF-decoded by the caller from Ipv4/Ipv6Fragment).
  // `token` names the caller's buffer that `payload` points into; it is stored verbatim alongside
  // the span and handed back by retire()/evict_stale() when the span is dropped. kNoToken (the
  // default, used by the whole-file path) means the caller is not tracking buffer lifetimes.
  Result add_fragment(const Key& key, packet_id_t pid, std::uint32_t offset_bytes,
                      bool more_fragments, std::span<const std::byte> payload,
                      Token token = kNoToken) {
    Result out;
    std::uint32_t id;
    auto kit = key_to_id_.find(key);
    if (kit == key_to_id_.end()) {
      if (by_id_.size() >= cfg_.max_concurrent) return out;  // at capacity; drop silently (id == 0)
      id = next_id_++;
      key_to_id_.emplace(key, id);
      detail::Reassembly r{};
      r.datagram_id = id;
      r.first_packet_id = pid;
      by_id_.emplace(id, std::move(r));
    } else {
      id = kit->second;
    }
    out.datagram_id = id;
    detail::Reassembly& r = by_id_.at(id);
    r.last_packet_id = pid;
    if (!more_fragments) {
      r.have_last = true;
      r.total_length = offset_bytes + std::uint32_t(payload.size());
    }

    std::size_t already = 0;
    for (const auto& f : r.fragments) already += f.data.size();
    if (already + payload.size() > cfg_.max_datagram_bytes) return out;  // oversized; drop

    r.fragments.push_back(detail::FragmentSpan{offset_bytes, pid, more_fragments, payload, token});
    ++r.fragment_count;
    r.covered_high =
        std::max(r.covered_high, offset_bytes + std::uint32_t(payload.size()));
    out.retained = true;  // the span is now stored: `token`'s buffer is pinned by this table

    if (!r.have_last) return out;  // can't know completeness without the terminal fragment

    std::vector<const detail::FragmentSpan*> ordered;
    ordered.reserve(r.fragments.size());
    for (const auto& f : r.fragments) ordered.push_back(&f);
    std::sort(ordered.begin(), ordered.end(), [](const auto* a, const auto* b) {
      return a->offset_bytes != b->offset_bytes ? a->offset_bytes < b->offset_bytes
                                                 : a->packet_id < b->packet_id;
    });

    // ZERO-COPY completion: build an ordered, overlap-trimmed list of views into the source
    // buffer instead of stitching an owned copy (nanom's segmented input -- see segmented.hpp --
    // parses straight over the list). Semantics preserved from the old stitch loop exactly:
    //   * gap (a fragment starting past the covered prefix)     -> still incomplete;
    //   * overlap whose bytes AGREE with what's already covered -> trimmed away (content is
    //     byte-identical to the old last-writer-wins overwrite, since equal);
    //   * overlap whose bytes DISAGREE                          -> conflict, never completes
    //     (evict_stale reports it as status 3);
    //   * bytes extending past the declared total_length        -> clamped (old code: ignored);
    //   * completeness check uses the UNCLAMPED end             -> same as the old `covered`.
    std::vector<std::span<const std::byte>> parts;
    parts.reserve(ordered.size());
    std::uint32_t covered = 0;  // unclamped high-water mark, matching the old loop's `covered`
    for (const detail::FragmentSpan* f : ordered) {
      if (f->offset_bytes > covered) return out;  // gap: still incomplete
      const std::uint32_t clamped_covered = std::min(covered, r.total_length);
      const std::uint32_t end = f->offset_bytes + std::uint32_t(f->data.size());
      // overlap with already-covered content: verify byte equality (conflict detection)
      if (f->offset_bytes < clamped_covered) {
        const std::size_t ov =
            std::min<std::size_t>(clamped_covered - f->offset_bytes, f->data.size());
        if (!detail::range_equals(parts, f->offset_bytes, f->data.first(ov))) {
          r.conflict = true;  // two fragments disagree on an overlapping byte
          return out;         // never completes; evict_stale reports it as a conflict
        }
      }
      // emit the new tail, clamped to the declared total
      const std::uint32_t emit_from = std::max(f->offset_bytes, clamped_covered);
      const std::uint32_t emit_to   = std::min(end, r.total_length);
      if (emit_from < emit_to)
        parts.push_back(f->data.subspan(emit_from - f->offset_bytes, emit_to - emit_from));
      if (end > covered) covered = end;
    }
    if (covered < r.total_length) return out;  // still missing bytes

    r.parts = std::move(parts);
    r.completed = true;
    key_to_id_.erase(key);  // free the 4-tuple so a NEW datagram reusing it starts fresh
    out.completed = true;
    out.parts = nanom::segments{
        std::span<const std::span<const std::byte>>(r.parts.data(), r.parts.size())};
    return out;
  }

  /// Release point 1 of 2 (see the Token contract in this file's header): the COMPLETION release.
  ///
  /// Drops every span a completed datagram's entry still holds -- `fragments` and `parts` are
  /// genuinely cleared, not flagged -- and returns the tokens those fragments pinned, now safe for
  /// the caller to reuse. The entry itself stays in the table (so DatagramRow bookkeeping and
  /// find() still resolve) carrying only summary integers; evict_stale() removes it later as
  /// before, then reporting no tokens because this call already gave them back.
  ///
  /// MUST be called only after the caller has finished using Result::parts (dispatch first, retire
  /// second) -- Result::parts is a view into this entry's own `parts` storage.
  ///
  /// A no-op returning {} for an unknown, incomplete, or already-retired datagram: an in-flight
  /// reassembly's buffers are NOT releasable, and saying so here is what makes the contract safe
  /// against a caller that retires optimistically.
  std::vector<Token> retire(std::uint32_t datagram_id) {
    std::vector<Token> out;
    auto it = by_id_.find(datagram_id);
    if (it == by_id_.end()) return out;
    detail::Reassembly& r = it->second;
    if (!r.completed || r.retired) return out;
    out.reserve(r.fragments.size());
    for (const auto& f : r.fragments) out.push_back(f.token);
    r.fragments.clear();
    r.fragments.shrink_to_fit();  // give the storage back too, not just the size
    r.parts.clear();
    r.parts.shrink_to_fit();
    r.retired = true;
    return out;
  }

  /// Escape hatch for a consumer that genuinely needs the completed datagram as ONE contiguous
  /// buffer: stitches lazily on first call (the copy the segmented path exists to avoid) and
  /// caches. Returns nullptr for an unknown/incomplete datagram. Valid until eviction.
  /// Also nullptr once the entry has been retire()d without a prior materialize(): the source
  /// spans are gone by then, and returning the (empty) cache would silently claim a 0-byte
  /// datagram.
  const std::vector<std::byte>* materialize(std::uint32_t datagram_id) {
    auto it = by_id_.find(datagram_id);
    if (it == by_id_.end() || !it->second.completed) return nullptr;
    detail::Reassembly& r = it->second;
    if (r.retired && r.materialized.empty() && r.total_length > 0) return nullptr;
    if (r.materialized.empty() && r.total_length > 0) {
      r.materialized.reserve(r.total_length);
      for (const auto& p : r.parts) r.materialized.insert(r.materialized.end(), p.begin(), p.end());
    }
    return &r.materialized;
  }

  // Release point 2 of 2 (see the Token contract in this file's header): the AGE-OUT release.
  //
  // Evicts every entry last touched more than timeout_ticks packets ago (whether complete or not)
  // and returns a summary for each, so the caller can emit a DatagramRow even for reassemblies that
  // never finished (timed_out / overlap_conflict) or that simply aged out after completing. Each
  // summary now also carries the buffer tokens that entry was still pinning (empty if it was
  // retire()d first) -- this is where an in-flight reassembly that never completes finally gives
  // its caller's buffers back.
  std::vector<ReassemblySummary> evict_stale(packet_id_t now_packet_id) {
    std::vector<ReassemblySummary> out;
    for (auto it = by_id_.begin(); it != by_id_.end();) {
      detail::Reassembly& r = it->second;
      const bool aged_out =
          now_packet_id >= r.last_packet_id + cfg_.timeout_ticks || r.last_packet_id == kNoPacket;
      if (!aged_out) {
        ++it;
        continue;
      }
      ReassemblySummary s;
      s.datagram_id = r.datagram_id;
      s.total_length = r.total_length;
      // Both maintained incrementally in add_fragment (identical values to the old re-derivation
      // from `fragments`) so a retire()d entry -- whose spans are gone -- still reports correctly.
      s.fragment_count = r.fragment_count;
      s.first_packet_id = r.first_packet_id;
      s.last_packet_id = r.last_packet_id;
      const std::uint32_t covered = r.covered_high;
      // Deliberately unreserved: a caller that passes no tokens (the whole-file path) pushes
      // nothing and pays no allocation here at all.
      for (const auto& f : r.fragments)
        if (f.token != kNoToken) s.tokens.push_back(f.token);
      if (r.conflict) {
        s.completion_status = 3;
      } else if (r.completed) {
        s.completion_status = 0;
      } else {
        s.completion_status = 1;
      }
      s.gap_bytes = (r.have_last && r.total_length > covered) ? (r.total_length - covered) : 0;
      out.push_back(s);
      // A completed reassembly already erased its own key_to_id_ entry in add_fragment(); a
      // still-open one (timed out / evicted for capacity / stuck in conflict) has not, so its
      // 4-tuple key would otherwise keep resolving to this about-to-be-freed id forever -- the next
      // add_fragment() call reusing that key would call by_id_.at(stale_id) and throw. Reassembly
      // doesn't carry its own key (it's Key-agnostic, shared by every ReassemblyTable<Key>
      // instantiation), so find it by value instead; key_to_id_ is bounded by max_concurrent, so
      // this scan is cheap and only runs for entries actually being evicted.
      const std::uint32_t evicted_id = it->first;
      for (auto kit = key_to_id_.begin(); kit != key_to_id_.end();) {
        if (kit->second == evicted_id) kit = key_to_id_.erase(kit);
        else ++kit;
      }
      it = by_id_.erase(it);
    }
    return out;
  }

  const detail::Reassembly* find(std::uint32_t datagram_id) const {
    auto it = by_id_.find(datagram_id);
    return it == by_id_.end() ? nullptr : &it->second;
  }

 private:
  std::unordered_map<Key, std::uint32_t, typename key_hash_for<Key>::type> key_to_id_;
  std::unordered_map<std::uint32_t, detail::Reassembly>                   by_id_;
  std::uint32_t next_id_ = 1;
  Config        cfg_;
};

struct Ipv4FragMeta {
  packet_id_t   packet_id;
  std::uint32_t datagram_id;
  std::uint16_t frag_offset_bytes;
  bool          more_fragments;
  bool          is_first;
  bool          is_last;
};
struct Ipv6FragMeta {
  packet_id_t   packet_id;
  std::uint32_t datagram_id;
  std::uint32_t frag_offset_bytes;
  bool          more_fragments;
  bool          is_first;
  bool          is_last;
};

struct DatagramRow {
  std::uint32_t datagram_id;
  std::uint8_t  ip_version;         // 4 or 6
  std::uint32_t total_length;       // 0 if never completed
  std::uint32_t fragment_count;
  std::uint64_t first_packet_id;
  std::uint64_t last_packet_id;
  std::uint8_t  completion_status;  // 0=complete 1=timed_out 2=evicted_capacity 3=overlap_conflict
  std::uint32_t gap_bytes;          // 0 if complete
};

inline DatagramRow to_datagram_row(const ReassemblySummary& s, std::uint8_t ip_version) {
  return DatagramRow{s.datagram_id,        ip_version,
                    s.total_length,       s.fragment_count,
                    s.first_packet_id,    s.last_packet_id,
                    s.completion_status,  s.gap_bytes};
}

// The two reassembly tables a decode pass needs, bundled together for convenience.
struct DefragState {
  ReassemblyTable<Ipv4Key> ipv4;
  ReassemblyTable<Ipv6Key> ipv6;
};

}  // namespace nanom_shark::defrag

NANOM_DESCRIBE(nanom_shark::defrag::Ipv4FragMeta, packet_id, datagram_id, frag_offset_bytes,
              more_fragments, is_first, is_last);
NANOM_DESCRIBE(nanom_shark::defrag::Ipv6FragMeta, packet_id, datagram_id, frag_offset_bytes,
              more_fragments, is_first, is_last);
NANOM_DESCRIBE(nanom_shark::defrag::DatagramRow, datagram_id, ip_version, total_length,
              fragment_count, first_packet_id, last_packet_id, completion_status, gap_bytes);
