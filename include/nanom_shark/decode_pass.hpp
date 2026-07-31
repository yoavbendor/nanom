// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/decode_pass.hpp — the whole-file decode entry point: pcap/pcapng scan -> per-packet
// walk -> tables (+ optional per-packet JSON). It is now a thin driver over the streaming session:
// scan_blocks finds the block boundaries as it always did, and each block is handed to ONE
// StreamingDecodeSession (streaming.hpp), which owns the cross-block state that used to live as
// locals in this function -- interface link types, the defrag tables, the decoder's per-pass
// protocol states, the packet-id counter.
//
// The point of routing through the session is that the two entry points can't drift: there is one
// per-block body (packet_visitor.hpp's PacketVisitor, driven by the session), not a streaming copy
// of a whole-file loop. The existing golden fixtures are the regression net -- byte-identical
// output before and after this unification is the acceptance bar.
//
// Buffer tokens (defrag.hpp) are deliberately unused here: `file` stays alive for the whole pass,
// so every fragment span is trivially valid and there is nothing to release. Everything is fed as
// defrag::kNoToken, which the session never reports.

#include <nanom_shark/packet_visitor.hpp>
#include <nanom_shark/streaming.hpp>

#include <nanom_shark/pcap.hpp>  // nmpcap::scan_blocks / parse_idb / parse_epb

#include <nanom/nanom.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace nanom_shark {

// The ONE decode pass: scan_blocks -> per EPB/pcap-record, walk_packet_ext (feeding IPv4/IPv6
// fragments to defrag; a completed reassembly re-enters the same L4 dispatch over the zero-copy
// reassembled segment list). Pushes every row into `tables` always, and (when sink.json_packets is
// set) a "frame" + one entry per decoded layer into that packet's PacketJson.
//
// `Decoder` is deduced from `tables` -- `tables_of<my_decoder> t; run_decode_pass(file, t, ...)`
// selects that decoder's protocol set, with no other change at the call site. A malformed layer
// stops that packet's walk only (walk_packet contract, see protocols.hpp); this function returns
// false only when the pcap/pcapng block scan itself fails (a corrupt file, not a corrupt packet).
template <class Decoder>
inline bool run_decode_pass(nanom::bytes file, tables_of<Decoder>& tables, SinkHub sink,
                            const DecodeOptions& opts, std::string& error) {
  std::vector<nmpcap::BlockRef> refs;
  if (!nmpcap::scan_blocks(file, refs, error)) return false;

  StreamingDecodeSession<Decoder> session(tables, sink, opts);

  for (const nmpcap::BlockRef& ref : refs) {
    const std::size_t off = std::size_t(ref.file_offset);
    if (off > file.size()) continue;
    // scan_blocks bounded every ref against the file, except the synthetic IDB it fabricates for a
    // classic-pcap global header: that one declares length 24 (the discriminator parse_idb keys
    // off) while the bytes it must read are the 4-byte magic plus 24 more. Hand the session what it
    // needs to read and tell it separately what the block claims to be.
    const std::size_t avail = file.size() - off;
    const std::size_t want =
        ref.kind == nmpcap::Kind::Idb ? std::max<std::size_t>(ref.length, 28) : ref.length;
    const std::size_t take = std::min<std::size_t>(want, avail);
    const nanom::bytes block = file.subspan(off, take);

    if (ref.kind == nmpcap::Kind::Shb) {
      session.feed_shb(block);
      continue;
    }
    if (ref.kind == nmpcap::Kind::Idb) {
      session.feed_idb(block, ref.little_endian, ref.length);
      continue;
    }
    if (ref.kind != nmpcap::Kind::Epb && ref.kind != nmpcap::Kind::PcapRecord) continue;
    session.feed_epb(block, ref.little_endian, defrag::kNoToken, ref.kind, ref.file_offset);
  }
  return true;
}

}  // namespace nanom_shark
