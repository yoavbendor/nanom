// SPDX-License-Identifier: Apache-2.0
//
// libFuzzer harness for streaming pcapng parse with variable refill-window sizes.
// Exercises nm::streaming incomplete/refill paths under ASan+UBSan.
//
// Build: -DNANOM_BUILD_FUZZERS=ON with Clang (see CMakeLists.txt).
// Run:   ./fuzz_streaming_pcapng -max_total_time=60 corpus_streaming/

#include "../bench/streaming_pcapng_parse.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) return 0;

  // Derive refill cap from input (16..8192) to hit short-prefix boundaries.
  const std::size_t cap = 16 + (std::size_t(data[0]) | (std::size_t(data[1]) << 8)) % 8177;
  const std::vector<std::uint8_t> blob(data, data + size);
  volatile std::uint64_t sink = streaming_pcapng::parse(blob, cap).checksum;
  (void)sink;
  return 0;
}
