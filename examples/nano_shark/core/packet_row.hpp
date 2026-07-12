// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/packet_row.hpp — one row per captured packet (frame), independent of whether
// L2/L3 decode succeeds or is even attempted: this is exactly the file offset/length metadata
// every pcap/pcapng record carries regardless. It is the "packet table" a byte-level sink (e.g.
// the sibling `nanoshark` repo's Lance bridge) anchors a lance.blob.v2 payload_ref column to
// (uri = the capture file, position = file_offset, size = caplen) -- every other per-protocol
// table only needs to join back to it by packet_id, never touching raw file bytes itself.

#include "node_row.hpp"

#include <nanom/nanom.hpp>

#include <cstdint>

namespace nano_shark {

struct PacketRow {
  packet_id_t   packet_id   = kNoPacket;
  std::uint64_t file_offset = 0;  // absolute byte offset of the packet's payload in the source file
  std::uint32_t caplen      = 0;  // captured length (bytes actually present in the file)
  std::uint32_t origlen     = 0;  // original on-wire length (may exceed caplen if truncated)
};

}  // namespace nano_shark

NANOM_DESCRIBE(nano_shark::PacketRow, packet_id, file_offset, caplen, origlen);
