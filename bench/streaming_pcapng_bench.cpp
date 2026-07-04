// SPDX-License-Identifier: Apache-2.0
//
// Streaming pcapng parse on nanom — the apples-to-apples counterpart of bench/rust_nom (stable Rust
// nom via the pcap-parser crate). BOTH do exactly the same work per packet: walk the pcapng block
// stream through a bounded, refilling buffer (never the whole file resident) and read the Enhanced
// Packet Block FIXED fields (interface_id, timestamp, caplen, origlen) via a describe'd struct. NO
// payload copy, NO option-TLV walk on either side. Both emit the identical aggregate
// (packets, sum_caplen, sum_origlen, fnv1a checksum of ts_raw/caplen/origlen) so bench/compare_rust.py
// can prove the two parsers agree before reporting timings.
//
// The block-header read uses nanom's STREAMING mode (nm::streaming -> errk::incomplete + .needed): a
// short buffer yields `incomplete`, the harness refills and retries — nom's streaming contract.
//
// usage: streaming_pcapng_bench <file.pcapng> <iters>   (best of 5; parses in-memory bytes `iters`x)

#include "nm_pcap.hpp"  // nmpcap:: block/EPB structs + magics (reused from the parity example)

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace nm = nanom;
using namespace nmpcap;

namespace {

constexpr std::size_t CAP = 65536;  // refill-buffer capacity — MUST match the Rust side
constexpr std::uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
constexpr std::uint64_t FNV_PRIME = 0x00000100000001b3ULL;

struct Agg {
    std::uint64_t packets = 0, sum_caplen = 0, sum_origlen = 0, checksum = FNV_OFFSET;
};
inline std::uint64_t mix(std::uint64_t h, std::uint64_t v) { return (h ^ v) * FNV_PRIME; }

// One streaming pass over the whole capture held in `data`, through a bounded window `buf` of CAP
// bytes that refills from `data` (never the whole file resident in the parser's working set).
Agg parse_once(const std::vector<std::uint8_t>& data) {
    Agg a;
    std::vector<std::uint8_t> buf(CAP);
    std::size_t src = 0;   // next unread byte in `data`
    std::size_t pos = 0;   // read cursor: parsed up to buf[pos)  (== pcap-parser's `consume`)
    std::size_t have = 0;  // filled: valid bytes in buf[0..have)
    bool little = true;    // section endianness (from the SHB byte-order magic)

    // Compact the unparsed tail [pos,have) to the front and read more source into the free space —
    // the only place bytes move, mirroring pcap-parser's refill(). Returns false at real EOF.
    auto refill = [&]() -> bool {
        if (pos > 0) {
            std::memmove(buf.data(), buf.data() + pos, have - pos);
            have -= pos;
            pos = 0;
        }
        std::size_t n = std::min(buf.size() - have, data.size() - src);
        if (n == 0) return false;
        std::memcpy(buf.data() + have, data.data() + src, n);
        src += n;
        have += n;
        return true;
    };

    while (true) {
        const std::size_t avail = have - pos;
        // Read the 8-byte block header in nanom STREAMING mode; refill on `incomplete`.
        nm::input in = nm::streaming(nm::from(buf.data() + pos, avail));
        auto hdr = nm::strct<png_block_hdr>(order_of(little))(in);
        if (!hdr) {
            if (hdr.error().kind == nm::errk::incomplete && refill()) continue;
            break;  // clean EOF (no more full header) or malformed
        }
        // SHB type is a byte-order-independent palindrome; its byte-order magic sets the section order.
        if (hdr->value.type == kShb) {
            nm::input bo = nm::streaming(nm::from(buf.data() + pos, avail));
            auto probe = nm::preceded(nm::take(std::size_t{8}), nm::le_u32)(bo);
            if (!probe) {
                if (probe.error().kind == nm::errk::incomplete && refill()) continue;
                break;
            }
            little = (probe->value == kByteOrderMagic);
            nm::input in2 = nm::streaming(nm::from(buf.data() + pos, avail));
            hdr = nm::strct<png_block_hdr>(order_of(little))(in2);
            if (!hdr) break;
        }
        const std::uint32_t total = hdr->value.total_len;
        if (total < 12 || total % 4 != 0) break;   // malformed framing
        if (total > buf.size()) break;             // block larger than the window (n/a for this data)
        if (total > avail) {                       // block not fully resident -> refill and retry
            if (refill()) continue;
            break;                                 // truncated tail at EOF
        }
        // The block is fully resident at buf[pos..pos+total). If EPB, decode its fixed body at +8.
        if (hdr->value.type == kEpb) {
            nm::input body = nm::from(buf.data() + pos + 8, total - 8);
            auto e = nm::strct<png_epb_body>(order_of(little))(body);
            if (e) {
                const std::uint64_t ts_raw = (std::uint64_t(e->value.ts_high) << 32) | e->value.ts_low;
                a.packets += 1;
                a.sum_caplen += e->value.caplen;
                a.sum_origlen += e->value.origlen;
                a.checksum = mix(a.checksum, ts_raw);
                a.checksum = mix(a.checksum, e->value.caplen);
                a.checksum = mix(a.checksum, e->value.origlen);
            }
        }
        pos += total;  // consume: advance the cursor only (no per-block memmove)
    }
    return a;
}

std::vector<std::uint8_t> read_file(const char* path) {
    std::vector<std::uint8_t> out;
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return out;
    std::uint8_t chunk[1 << 16];
    std::size_t n;
    while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) out.insert(out.end(), chunk, chunk + n);
    std::fclose(f);
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <file.pcapng> <iters>\n", argv[0]);
        return 2;
    }
    const std::vector<std::uint8_t> data = read_file(argv[1]);
    if (data.empty()) {
        std::fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    const std::uint32_t iters = std::uint32_t(std::stoul(argv[2]));

    const Agg base = parse_once(data);  // reference aggregate + warm-up
    std::uint64_t best_ns = UINT64_MAX;
    for (int run = 0; run < 5; ++run) {
        const auto t0 = std::chrono::steady_clock::now();
        std::uint64_t acc = 0;
        for (std::uint32_t i = 0; i < iters; ++i) acc += parse_once(data).checksum;
        const auto t1 = std::chrono::steady_clock::now();
        volatile std::uint64_t sink = acc;
        (void)sink;
        const std::uint64_t ns =
            std::uint64_t(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()) / iters;
        if (ns < best_ns) best_ns = ns;
    }
    const double bytes = double(data.size());
    const double ns_per_pkt = double(best_ns) / double(base.packets ? base.packets : 1);
    const double mbps = bytes / (double(best_ns) / 1e9) / (1024.0 * 1024.0);
    std::printf(
        "RESULT engine=nanom packets=%llu sum_caplen=%llu sum_origlen=%llu checksum=%016llx "
        "file_bytes=%zu best_ns_per_pass=%llu ns_per_pkt=%.2f mbps=%.1f\n",
        (unsigned long long)base.packets, (unsigned long long)base.sum_caplen,
        (unsigned long long)base.sum_origlen, (unsigned long long)base.checksum, data.size(),
        (unsigned long long)best_ns, ns_per_pkt, mbps);
    return 0;
}
