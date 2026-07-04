// Streaming pcapng parse on stable Rust nom — the apples-to-apples counterpart of
// bench/streaming_pcapng_bench.cpp (nanom). Two modes so the comparison is honest:
//
//   min  : a HAND-WRITTEN minimal streaming scanner using nom's own combinators
//          (nom::number::streaming::{le,be}_u32) over a bounded, refilling buffer — reads the block
//          header + the Enhanced Packet Block FIXED fields only, no payload copy, NO option walk, no
//          allocation per packet. This is EQUAL WORK to the nanom harness -> the fair parser-combinator
//          number. (This is the headline "nanom vs Rust nom" row.)
//
//   full : the community-standard nom-based `pcap-parser` crate via its streaming PcapNGReader. Realistic
//          "what people actually use", but it ALSO parses every packet's options into a Vec<PcapNGOption>
//          (opt_parse_options) — i.e. it does strictly MORE work than `min`/nanom. Reported as context,
//          clearly labeled, so nobody can say the minimal scanner strawmans nom.
//
// Both modes emit the identical aggregate (packets, sum_caplen, sum_origlen, fnv1a checksum) so
// bench/compare_rust.py can prove all parsers agree before reporting timings.
//
// usage: rust_nom_bench <file.pcapng> <iters> <min|full>   (best of 5; parses in-memory bytes `iters`x)

use std::io::Cursor;
use std::time::Instant;

use nom::number::streaming::{be_u32, le_u32};
use nom::Err as NomErr;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Block, PcapBlockOwned, PcapError, PcapNGReader};

const CAP: usize = 65536; // refill-buffer capacity — MUST match the nanom side
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const SHB: u32 = 0x0A0D_0D0A;
const EPB: u32 = 6;
const BOM: u32 = 0x1A2B_3C4D;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct Agg {
    packets: u64,
    sum_caplen: u64,
    sum_origlen: u64,
    checksum: u64,
}
#[inline]
fn mix(h: u64, v: u64) -> u64 {
    (h ^ v).wrapping_mul(FNV_PRIME)
}
#[inline]
fn u32_at(b: &[u8], off: usize, little: bool) -> u32 {
    let (i, v) = if little { le_u32::<_, ()>(&b[off..]) } else { be_u32::<_, ()>(&b[off..]) }.unwrap();
    let _ = i;
    v
}

// ---- `min`: hand-written minimal streaming scanner on nom combinators (equal work to nanom) --------
fn parse_min(data: &[u8]) -> Agg {
    let mut a = Agg { checksum: FNV_OFFSET, ..Default::default() };
    let mut buf = vec![0u8; CAP];
    let mut src = 0usize; // next unread byte in data
    let mut pos = 0usize; // read cursor (== "consume")
    let mut have = 0usize; // filled bytes
    let mut little = true;

    // Compact unparsed tail [pos,have) to front, then read more source into the free space.
    macro_rules! refill {
        () => {{
            if pos > 0 {
                buf.copy_within(pos..have, 0);
                have -= pos;
                pos = 0;
            }
            let n = std::cmp::min(buf.len() - have, data.len() - src);
            if n == 0 {
                false
            } else {
                buf[have..have + n].copy_from_slice(&data[src..src + n]);
                src += n;
                have += n;
                true
            }
        }};
    }

    loop {
        let avail = have - pos;
        // block header = type:u32 + total_len:u32, read via nom streaming combinators (Incomplete->refill)
        let win = &buf[pos..have];
        let (typ, total) = match be_or_le_hdr(win, little) {
            Ok(v) => v,
            Err(true) => {
                if refill!() { continue } else { break }
            } // incomplete
            Err(false) => break, // malformed / EOF
        };
        if typ == SHB {
            // SHB type is byte-order independent; its byte-order magic (bytes 8..12) sets section order.
            if avail < 12 {
                if refill!() { continue } else { break };
            }
            little = u32_at(&buf[pos..], 8, true) == BOM;
        }
        let total = if typ == SHB { u32_at(&buf[pos..], 4, little) } else { total };
        if total < 12 || total % 4 != 0 || total as usize > buf.len() {
            break;
        }
        if total as usize > avail {
            if refill!() { continue } else { break };
        }
        if typ == EPB {
            // EPB fixed body at +8: if_id, ts_high, ts_low, caplen, origlen (5x u32), via nom.
            let b = &buf[pos + 8..];
            let ts_raw = ((u32_at(b, 4, little) as u64) << 32) | u32_at(b, 8, little) as u64;
            let caplen = u32_at(b, 12, little) as u64;
            let origlen = u32_at(b, 16, little) as u64;
            a.packets += 1;
            a.sum_caplen += caplen;
            a.sum_origlen += origlen;
            a.checksum = mix(a.checksum, ts_raw);
            a.checksum = mix(a.checksum, caplen);
            a.checksum = mix(a.checksum, origlen);
        }
        pos += total as usize;
    }
    a
}

// Read (type,total_len) from a resident window using nom streaming combinators.
// Err(true) = incomplete (need refill), Err(false) = malformed/eof.
fn be_or_le_hdr(win: &[u8], little: bool) -> Result<(u32, u32), bool> {
    let rd = |off: usize| -> Result<u32, bool> {
        let s = win.get(off..).ok_or(true)?;
        let r = if little { le_u32::<_, ()>(s) } else { be_u32::<_, ()>(s) };
        match r {
            Ok((_, v)) => Ok(v),
            Err(NomErr::Incomplete(_)) => Err(true),
            Err(_) => Err(false),
        }
    };
    Ok((rd(0)?, rd(4)?))
}

// ---- `full`: the pcap-parser library (also parses+allocates options per packet) --------------------
fn parse_full(data: &[u8]) -> Agg {
    let mut a = Agg { checksum: FNV_OFFSET, ..Default::default() };
    let mut reader = PcapNGReader::new(CAP, Cursor::new(data)).expect("reader");
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::NG(Block::EnhancedPacket(epb)) = block {
                    let ts_raw = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                    a.packets += 1;
                    a.sum_caplen += epb.caplen as u64;
                    a.sum_origlen += epb.origlen as u64;
                    a.checksum = mix(a.checksum, ts_raw);
                    a.checksum = mix(a.checksum, epb.caplen as u64);
                    a.checksum = mix(a.checksum, epb.origlen as u64);
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(e) => panic!("parse error: {:?}", e),
        }
    }
    a
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: {} <file.pcapng> <iters> <min|full>", args[0]);
        std::process::exit(2);
    }
    let data = std::fs::read(&args[1]).expect("read file");
    let iters: u32 = args[2].parse().expect("iters");
    let mode = args[3].as_str();
    let engine = match mode {
        "min" => "rust-nom-min",
        "full" => "rust-pcap-parser",
        _ => {
            eprintln!("mode must be min|full");
            std::process::exit(2);
        }
    };
    let run = |d: &[u8]| if mode == "min" { parse_min(d) } else { parse_full(d) };

    let base = run(&data); // reference aggregate + warm-up
    let mut best_ns = u64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        let mut acc = 0u64;
        for _ in 0..iters {
            acc = acc.wrapping_add(run(&data).checksum);
        }
        let ns = t.elapsed().as_nanos() as u64 / iters as u64;
        std::hint::black_box(acc);
        best_ns = best_ns.min(ns);
    }
    let ns_per_pkt = best_ns as f64 / base.packets.max(1) as f64;
    let mbps = data.len() as f64 / (best_ns as f64 / 1e9) / (1024.0 * 1024.0);
    println!(
        "RESULT engine={} packets={} sum_caplen={} sum_origlen={} checksum={:016x} \
         file_bytes={} best_ns_per_pass={} ns_per_pkt={:.2} mbps={:.1}",
        engine, base.packets, base.sum_caplen, base.sum_origlen, base.checksum, data.len(), best_ns,
        ns_per_pkt, mbps
    );
}
