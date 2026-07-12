// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/defrag.hpp — IPv4/IPv6 fragment reassembly. New: no precedent anywhere in the
// nano-family (nanom/nanotins detect fragmentation and stop the walk; nothing reassembles).
//
// This is the ONE deliberate, narrowly-scoped departure from nanom's zero-copy pledge: fragments
// arrive non-contiguously in the source file, so reconstructing "the datagram" requires an owned,
// stitched-together buffer. Every individual fragment's own IP header is still decoded zero-copy
// over the original file bytes (see core/decode_pass.hpp). Fragments are BUFFERED as non-owning
// spans into that same source buffer (valid for the whole decode pass -- the caller's `file` bytes
// outlive every ReassemblyTable, which is local to one run_decode_pass call); only the final
// cross-fragment stitch (Reassembly::assembled, built once a datagram completes) is an owned copy
// -- exactly one copy per completed datagram, not one per fragment plus one more at the end.
//
// A fully zero-copy reassembly (fragments kept as spans, joined lazily via std::views::join
// instead of ever stitching) isn't practical here: nanom's parsing surface (nom.hpp's `input`,
// strct<T>(), overlay<T>()) is built on a contiguous [first,last) pointer pair, not a generalized
// range. A join_view over disjoint spans is only a forward_range -- its elements aren't adjacent
// in memory, so it can't yield the pointer+length pair nanom's parser needs; feeding it in would
// still require materializing (copying) at the parse call site, likely losing nanom's
// pointer-arithmetic fast paths in the process. Teaching nanom's core cursor to understand
// segmented input would be a real change to the LIBRARY itself, out of scope for this example.
//
// Known scope trim: decode_pass.hpp re-enters L4 parsing over the reassembled buffer via a plain
// nanom::from() (an "unattested" span), not a dedicated NANOM_GENERATION wire_arena scoped to the
// Reassembly's lifetime. Functionally complete either way; wiring a per-datagram arena would add
// use-after-evict detection on TOP of that (catching a stale view<T> that outlives evict_stale())
// as a follow-up hardening pass, not a correctness requirement for reassembly itself.

#include <nanom/nanom.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <unordered_map>
#include <vector>

#include "node_row.hpp"

namespace nano_shark::defrag {

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
};

namespace detail {

struct FragmentSpan {
  std::uint32_t               offset_bytes;
  packet_id_t                 packet_id;
  bool                        more_fragments;
  std::span<const std::byte>  data;  // a VIEW into the caller's source buffer, not a copy -- valid
                                     // for the lifetime of the ReassemblyTable (see file header)
};

struct Reassembly {
  std::uint32_t              datagram_id = 0;
  std::vector<FragmentSpan>  fragments;       // unordered as received
  std::uint32_t              total_length = 0;
  bool                       have_last = false;
  bool                       conflict = false;   // two fragments disagree on an overlapping byte range
  packet_id_t                first_packet_id = kNoPacket;
  packet_id_t                last_packet_id  = kNoPacket;
  bool                       completed = false;
  std::vector<std::byte>     assembled;          // filled only once complete
};

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
  // per-fragment forensic row) -- only `completed`/`assembled` depend on whether this call finished
  // reassembly (no gaps in [0,total_length), a terminal fragment seen, no content conflict).
  struct Result {
    std::uint32_t               datagram_id = 0;
    bool                        completed   = false;
    std::span<const std::byte>  assembled;   // valid only when completed
  };

  // Feed one fragment (already offset/MF-decoded by the caller from Ipv4/Ipv6Fragment).
  Result add_fragment(const Key& key, packet_id_t pid, std::uint32_t offset_bytes,
                      bool more_fragments, std::span<const std::byte> payload) {
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

    r.fragments.push_back(detail::FragmentSpan{offset_bytes, pid, more_fragments, payload});

    if (!r.have_last) return out;  // can't know completeness without the terminal fragment

    std::vector<const detail::FragmentSpan*> ordered;
    ordered.reserve(r.fragments.size());
    for (const auto& f : r.fragments) ordered.push_back(&f);
    std::sort(ordered.begin(), ordered.end(), [](const auto* a, const auto* b) {
      return a->offset_bytes != b->offset_bytes ? a->offset_bytes < b->offset_bytes
                                                 : a->packet_id < b->packet_id;
    });

    std::vector<std::byte> assembled(r.total_length);
    std::vector<bool>      written(r.total_length, false);
    std::uint32_t          covered = 0;
    for (const detail::FragmentSpan* f : ordered) {
      if (f->offset_bytes > covered) return out;  // gap: still incomplete
      const std::uint32_t end = f->offset_bytes + std::uint32_t(f->data.size());
      for (std::uint32_t i = 0; i < f->data.size(); ++i) {
        const std::uint32_t at = f->offset_bytes + i;
        if (at >= r.total_length) break;  // a fragment extending past the declared total is ignored
        if (written[at] && assembled[at] != f->data[i]) {
          r.conflict = true;  // two fragments disagree on an overlapping byte
        }
        assembled[at] = f->data[i];
        written[at] = true;
      }
      if (end > covered) covered = end;
    }
    if (r.conflict) return out;             // never completes; evict_stale reports it as a conflict
    if (covered < r.total_length) return out;  // still missing bytes

    r.assembled = std::move(assembled);
    r.completed = true;
    key_to_id_.erase(key);  // free the 4-tuple so a NEW datagram reusing it starts fresh
    out.completed = true;
    out.assembled = std::span<const std::byte>(r.assembled.data(), r.assembled.size());
    return out;
  }

  // Evicts every entry last touched more than timeout_ticks packets ago (whether complete or not)
  // and returns a summary for each, so the caller can emit a DatagramRow even for reassemblies that
  // never finished (timed_out / overlap_conflict) or that simply aged out after completing.
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
      s.fragment_count = std::uint32_t(r.fragments.size());
      s.first_packet_id = r.first_packet_id;
      s.last_packet_id = r.last_packet_id;
      std::uint32_t covered = 0;
      for (const auto& f : r.fragments) {
        const std::uint32_t end = f.offset_bytes + std::uint32_t(f.data.size());
        if (end > covered) covered = end;
      }
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

}  // namespace nano_shark::defrag

NANOM_DESCRIBE(nano_shark::defrag::Ipv4FragMeta, packet_id, datagram_id, frag_offset_bytes,
              more_fragments, is_first, is_last);
NANOM_DESCRIBE(nano_shark::defrag::Ipv6FragMeta, packet_id, datagram_id, frag_offset_bytes,
              more_fragments, is_first, is_last);
NANOM_DESCRIBE(nano_shark::defrag::DatagramRow, datagram_id, ip_version, total_length,
              fragment_count, first_packet_id, last_packet_id, completion_status, gap_bytes);
