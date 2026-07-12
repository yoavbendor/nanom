// SPDX-License-Identifier: Apache-2.0

// Coverage-guided libFuzzer entry point for defrag::ReassemblyTable -- the first heap-owning,
// cross-packet stateful table in the nano-family (every other described struct fuzzed elsewhere is
// a single-packet, zero-copy decode; this one buffers fragments across packets and stitches an
// owned buffer once a datagram completes -- see defrag.hpp's header comment). Exercises:
// out-of-order fragments, overlapping/conflicting fragments, oversized fragments, capacity/timeout
// eviction, and find() after eviction -- all under ASan+UBSan, so a heap-buffer-overflow or
// use-after-free in the stitch loop or the eviction bookkeeping shows up as a crash, not a wrong
// answer. Build via -DNANOM_BUILD_FUZZERS with Clang; run: ./fuzz_defrag -max_total_time=60 corpus/

#include "../examples/nano_shark/core/defrag.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

using nano_shark::defrag::Ipv4Key;
using nano_shark::defrag::ReassemblyTable;

struct Cursor {
  const std::uint8_t* p;
  const std::uint8_t* end;
  std::uint8_t u8() { return p < end ? *p++ : 0; }
  std::uint16_t u16() {
    const std::uint8_t a = u8(), b = u8();
    return std::uint16_t((std::uint16_t(a) << 8) | b);
  }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 4) return 0;
  Cursor c{data, data + size};

  // Small caps so the capacity/oversize/timeout paths trigger often instead of only on rare inputs.
  ReassemblyTable<Ipv4Key>::Config cfg;
  cfg.max_datagram_bytes = 4096;
  cfg.max_concurrent = 8;
  cfg.timeout_ticks = 5;
  ReassemblyTable<Ipv4Key> table(cfg);

  // A small, fixed pool of 4-tuples so colliding/concurrent/reused datagrams get exercised without
  // needing many input bytes per fragment (one selector byte picks among them).
  const Ipv4Key keys[4] = {
      Ipv4Key{{1, 2, 3, 4}, {5, 6, 7, 8}, 17, 100},
      Ipv4Key{{1, 2, 3, 4}, {5, 6, 7, 8}, 17, 101},
      Ipv4Key{{9, 9, 9, 9}, {8, 8, 8, 8}, 6, 200},
      Ipv4Key{{0, 0, 0, 0}, {0, 0, 0, 0}, 0, 0},
  };

  nano_shark::packet_id_t pid = 0;
  while (c.p + 4 <= c.end) {
    const std::uint8_t ctrl = c.u8();
    if ((ctrl & 0x0F) == 0) {  // occasionally just age the table forward
      table.evict_stale(pid);
      ++pid;
      continue;
    }
    const Ipv4Key& key = keys[ctrl % 4];
    const bool more_fragments = (ctrl & 0x10) != 0;
    const std::uint32_t offset_bytes = std::uint32_t(c.u16()) & 0x1FFF;  // boundedly wild, not huge
    const std::size_t want = c.u8();
    const std::size_t avail = std::size_t(c.end - c.p);
    const std::size_t take = std::min(want, avail);
    const std::span<const std::byte> payload(reinterpret_cast<const std::byte*>(c.p), take);
    c.p += take;

    const auto r = table.add_fragment(key, pid, offset_bytes, more_fragments, payload);
    if (r.completed) {
      volatile std::size_t touch = 0;
      for (std::byte b : r.assembled) touch ^= std::size_t(b);  // actually read the stitched bytes
      (void)touch;
    }
    (void)table.find(r.datagram_id);
    ++pid;
  }
  table.evict_stale(pid + cfg.timeout_ticks + 1);  // force a final drain of anything left open
  return 0;
}
