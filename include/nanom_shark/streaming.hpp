// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/streaming.hpp — the EPB-at-a-time decode entry point.
//
// run_decode_pass takes the WHOLE capture as one nanom::bytes: the entire file has to be resident
// before anything is decoded, and stays resident for the whole pass. That is not a parsing
// limitation -- pcap.hpp's parse_epb/parse_idb are already pure, per-block functions -- it is a
// LIFETIME one. Reassembly is zero-copy, so defrag.hpp's tables hold spans into whatever buffer
// each fragment's packet came from; keeping the file alive is what made those spans trivially
// valid. A caller who wants to stream (feed one block, reuse the buffer, feed the next) needs a
// hard answer to "when is this buffer free?", and that answer has to be correct by construction.
//
// StreamingDecodeSession is that answer. It owns exactly the state run_decode_pass keeps as loop
// locals -- iface_link, the defrag tables, the decoder's per-pass protocol states, the packet-id
// counter -- across separate feed_* calls, and every feed_epb reports which caller buffers are now
// free (defrag::Token values, opaque handles the caller chose: a ring slot, a pointer, anything).
//
//   * a non-fragment packet          -> its token is released the instant the walk returns;
//   * a fragment that completes here -> after dispatch_l4 finishes with the reassembled segments,
//                                       retire() drops every span and returns their tokens;
//   * a fragment still in flight     -> pinned; reported released only when its datagram later
//                                       completes-and-dispatches or ages out of evict_stale().
//
// The two paths do NOT fork: run_decode_pass (decode_pass.hpp) is implemented on top of this
// session -- it scans the file with scan_blocks as before, then feeds each block through one
// session instance, with kNoToken throughout (the file outlives the pass, so there is nothing to
// release). The existing golden tests are therefore the regression net for both.

#include <nanom_shark/decode_options.hpp>
#include <nanom_shark/defrag.hpp>
#include <nanom_shark/packet_row.hpp>
// The per-packet body (detail::PacketVisitor + SinkHub) both entry points share. Deliberately NOT
// decode_pass.hpp: that one is a driver over THIS header, so including it here would be a cycle.
#include <nanom_shark/packet_visitor.hpp>
#include <nanom_shark/pcap.hpp>
#include <nanom_shark/protocol.hpp>
#include <nanom_shark/protocols.hpp>

#include <nanom/nanom.hpp>

#include <algorithm>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace nanom_shark {

/// What one fed block did to the caller's buffers.
struct FeedResult {
  /// The block parsed. False only for a malformed block (a bad EPB header, a caplen that does not
  /// fit) -- a malformed *packet* inside a well-formed block still yields ok == true, matching
  /// run_decode_pass, which only fails the whole pass on a corrupt file.
  bool ok = false;
  /// True if THIS block's own buffer must stay alive past this call, because a fragment span
  /// pointing into it is held by a reassembly that has not finished. When false, this block's
  /// token is in `released` (unless it was defrag::kNoToken, which is never reported).
  bool pinned = false;
  /// Every token whose buffer became free during THIS call: this block's own if it was not pinned,
  /// plus any OTHER in-flight datagram's buffers whose reassembly just completed-and-dispatched
  /// (retire) or aged out (evict_stale) here. Never contains defrag::kNoToken.
  std::vector<defrag::Token> released;
};

/// One streaming decode. Blocks are fed in capture order; state (interface link types, open
/// reassemblies, per-protocol decode state, the packet-id counter) persists across calls.
///
/// Buffer contract: the bytes handed to feed_epb must stay valid for the duration of that call,
/// and afterwards only while FeedResult::pinned says so. Tokens are opaque; the session compares
/// them for equality and hands them back, nothing else. defrag::kNoToken (0) means "untracked" --
/// use it when the buffer's lifetime is not being managed (run_decode_pass does), and pass any
/// non-zero handle otherwise.
template <class Decoder>
class StreamingDecodeSession {
 public:
  StreamingDecodeSession(tables_of<Decoder>& tables, SinkHub sink, const DecodeOptions& opts)
      : tables_(&tables),
        sink_(sink),
        opts_(&opts),
        defrag_{defrag::ReassemblyTable<defrag::Ipv4Key>(opts.ipv4_defrag),
                defrag::ReassemblyTable<defrag::Ipv6Key>(opts.ipv6_defrag)} {}

  /// A Section Header Block starts a new section: interface numbering restarts from 0. Also
  /// records the section's endianness (from the SHB's own byte_order_magic), which a caller with
  /// no whole-file scan behind it needs in order to feed subsequent blocks correctly.
  void feed_shb(nanom::bytes shb_block) {
    iface_link_.clear();
    bool little = true;
    nmpcap::shb_byte_order(nanom::from(shb_block), little);  // leaves the default on a short block
    section_little_ = little;
  }

  /// An Interface Description Block appends one interface's link type, in interface-id order.
  /// `declared_length` overrides the block length recorded in the synthetic BlockRef; it exists
  /// for the one caller that needs it -- scan_blocks exposes a classic-pcap global header as a
  /// synthetic 24-byte IDB, and parse_idb keys off exactly that length to recognise it.
  void feed_idb(nanom::bytes idb_block, bool little_endian, std::uint32_t declared_length = 0) {
    const nmpcap::BlockRef ref{
        /*file_offset=*/0,
        /*length=*/declared_length ? declared_length : std::uint32_t(idb_block.size()),
        /*type_or_link=*/nmpcap::kIdb, nmpcap::Kind::Idb, little_endian};
    nmpcap::IdbView idb{};
    if (nmpcap::parse_idb(idb_block, ref, idb)) iface_link_.push_back(idb.link_type);
  }

  /// Decode one packet block: an Enhanced Packet Block (pcapng) or, with `kind`
  /// nmpcap::Kind::PcapRecord, a classic pcap record. `epb_block` is the block's own bytes, framing
  /// included, starting at its first byte -- parse_epb is called over a synthetic single-block
  /// BlockRef, so no file and no scan are involved.
  ///
  /// `token` names the buffer `epb_block` lives in; see the class contract.
  /// `block_file_offset` is reporting-only: it is added to the block-relative payload offset so
  /// PacketRow carries the same absolute file offset the whole-file path emits. Leave it 0 when
  /// there is no file.
  FeedResult feed_epb(nanom::bytes epb_block, bool little_endian, defrag::Token token,
                      nmpcap::Kind kind = nmpcap::Kind::Epb, std::uint64_t block_file_offset = 0) {
    FeedResult fr;
    if (token != defrag::kNoToken) tracking_ = true;
    const nmpcap::BlockRef ref{/*file_offset=*/0, /*length=*/std::uint32_t(epb_block.size()),
                               /*type_or_link=*/nmpcap::kEpb, kind, little_endian};
    nmpcap::EpbView e{};
    if (!nmpcap::parse_epb(epb_block, ref, e)) {
      // Malformed block: nothing was decoded, nothing retained, and (matching run_decode_pass,
      // which `continue`s here) the packet id does not advance. The buffer is free immediately.
      release_own_token(fr, token);
      return fr;
    }
    fr.ok = true;

    const std::uint16_t link_type =
        e.interface_id < iface_link_.size() ? iface_link_[e.interface_id] : std::uint16_t{0};

    tables_->template get<"packets">().push(
        PacketRow{pid_, block_file_offset + e.payload_file_offset, e.caplen, e.origlen});

    PacketJson* pj = nullptr;
    if (sink_.json_packets) {
      sink_.json_packets->emplace_back(pid_);
      pj = &sink_.json_packets->back();
      pj->add_layer_json("frame", detail::frame_json(e, link_type));
    }

    std::vector<defrag::Token> retired;  // stays empty (no allocation) unless something completes
    std::uint32_t pins_added = 0;

    const std::size_t poff = std::size_t(e.payload_file_offset);
    if (opts_->decode_l2l3 && poff + e.caplen <= epb_block.size()) {
      const nanom::bytes pkt = epb_block.subspan(poff, e.caplen);
      decode_ctx ctx{};
      ctx.opts = opts_;
      ctx.packet_id = pid_;
      ctx.link_type = link_type;
      ctx.pkt = pkt;
      detail::PacketVisitor<Decoder, tables_of<Decoder>, states_of<Decoder>> visitor{
          ctx, tables_, &states_, pj, opts_->decode_defrag ? &defrag_ : nullptr};
      visitor.token = token;
      // The COMPLETION release is opt-in: only a caller that actually tracks buffer lifetimes
      // needs retire(), and it is not free (it drops the entry's fragment/parts storage). A pass
      // that never passes a token -- run_decode_pass, whose file outlives everything -- leaves
      // this null and does exactly the work it did before this session existed.
      if (tracking_) visitor.retired_tokens = &retired;
      nmproto::walk_packet_ext(link_type, pkt, visitor);
      pins_added = visitor.pin_count;
    }

    // completion_status 0 (complete) was already pushed at completion time inside the walk; only
    // timed_out/conflict/capacity entries are new information here. Their tokens, however, are
    // always news: an entry that never completed has been holding its caller's buffers until now.
    for (auto& s : defrag_.ipv4.evict_stale(pid_)) {
      if (s.completion_status != 0)
        tables_->template get<"datagram">().push(defrag::to_datagram_row(s, 4));
      for (defrag::Token t : s.tokens) unpin(t, fr.released);
    }
    for (auto& s : defrag_.ipv6.evict_stale(pid_)) {
      if (s.completion_status != 0)
        tables_->template get<"datagram">().push(defrag::to_datagram_row(s, 6));
      for (defrag::Token t : s.tokens) unpin(t, fr.released);
    }
    ++pid_;

    // Token bookkeeping. `pins_` counts, per token, how many fragment spans across BOTH tables
    // currently point into that buffer. In practice one packet contributes at most one fragment,
    // so the count is 0 or 1 -- but counting rather than flagging costs nothing here and keeps the
    // release contract sound even for a pathological packet that yields two fragments (an IPv6
    // header chain with two Fragment extension headers), where flagging would report the buffer
    // free while the second reassembly still pointed into it.
    if (pins_added != 0 && token != defrag::kNoToken) pins_[token] += pins_added;
    for (defrag::Token t : retired) unpin(t, fr.released);

    fr.pinned = token != defrag::kNoToken && pins_.find(token) != pins_.end();
    if (!fr.pinned) release_own_token(fr, token);
    return fr;
  }

  /// Number of packet blocks decoded so far == the packet id the next feed_epb will use.
  [[nodiscard]] packet_id_t packets_fed() const { return pid_; }
  /// Endianness of the section the last feed_shb opened (true == little). Defaults to true.
  [[nodiscard]] bool section_little_endian() const { return section_little_; }
  /// How many caller buffers are pinned right now by an unfinished reassembly. The streaming
  /// memory bound: a caller's pool needs this many slots plus one, never the file size.
  [[nodiscard]] std::size_t pinned_buffers() const { return pins_.size(); }
  /// Direct access for callers that want to inspect/drive reassembly themselves (tests do).
  [[nodiscard]] defrag::DefragState& defrag_state() { return defrag_; }

 private:
  // Drop one pin on `t`; when the last one goes, the buffer is free -- report it exactly once.
  void unpin(defrag::Token t, std::vector<defrag::Token>& out) {
    if (t == defrag::kNoToken) return;
    auto it = pins_.find(t);
    if (it == pins_.end()) return;  // never pinned (dropped at capacity/oversize), or already freed
    if (--it->second == 0) {
      pins_.erase(it);
      out.push_back(t);
    }
  }

  // Report this block's own buffer as free, unless it is untracked or already in the list (it can
  // be: the fragment that completes a datagram releases its own token through retire()).
  static void release_own_token(FeedResult& fr, defrag::Token token) {
    if (token == defrag::kNoToken) return;
    if (std::find(fr.released.begin(), fr.released.end(), token) != fr.released.end()) return;
    fr.released.push_back(token);
  }

  tables_of<Decoder>*  tables_;
  SinkHub              sink_;
  const DecodeOptions* opts_;
  defrag::DefragState  defrag_;
  states_of<Decoder>   states_{};        // per-pass mutable protocol state (gPTP's msg_index, ...)
  std::vector<std::uint16_t> iface_link_;  // per-interface link type, reset at each SHB
  packet_id_t          pid_ = 0;
  bool                 section_little_ = true;
  // Latched by the first tracked token fed. Until then the session behaves exactly like the old
  // whole-file loop: no retire(), no token bookkeeping, nothing to report.
  bool                 tracking_ = false;
  // Only ever holds TRACKED tokens with a live pin, so it stays empty for the whole-file path and
  // for any capture without fragmentation -- the common case pays no hashing at all.
  std::unordered_map<defrag::Token, std::uint32_t> pins_;
};

}  // namespace nanom_shark
