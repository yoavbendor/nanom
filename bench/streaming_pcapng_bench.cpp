// SPDX-License-Identifier: Apache-2.0
//
// Streaming pcapng parse on nanom — see streaming_pcapng_parse.hpp and docs/BENCH_RUST_NOM.md.
//
// usage: streaming_pcapng_bench <file.pcapng> <iters>

#include "streaming_pcapng_parse.hpp"

#include <chrono>
#include <cstdio>
#include <vector>

#ifndef NANOM_SAFETY_PROFILE
#define NANOM_SAFETY_PROFILE "minimal"
#endif

namespace {

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

  const auto base = streaming_pcapng::parse(data);
  std::uint64_t best_ns = UINT64_MAX;
  for (int run = 0; run < 5; ++run) {
    const auto t0 = std::chrono::steady_clock::now();
    std::uint64_t acc = 0;
    for (std::uint32_t i = 0; i < iters; ++i) acc += streaming_pcapng::parse(data).checksum;
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
      "RESULT engine=nanom safety=%s packets=%llu sum_caplen=%llu sum_origlen=%llu opts=%llu "
      "checksum=%016llx file_bytes=%zu best_ns_per_pass=%llu ns_per_pkt=%.2f mbps=%.1f\n",
      NANOM_SAFETY_PROFILE, (unsigned long long)base.packets, (unsigned long long)base.sum_caplen,
      (unsigned long long)base.sum_origlen, (unsigned long long)base.opts,
      (unsigned long long)base.checksum, data.size(), (unsigned long long)best_ns, ns_per_pkt, mbps);
  return 0;
}
