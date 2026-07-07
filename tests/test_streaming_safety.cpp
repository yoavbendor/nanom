// Streaming + incremental parser safety tests (NANOM_GENERATION=1 in CI).
//
// Exercises short-prefix incomplete handling, one-byte growth, refill boundaries,
// and variable-cap streaming pcapng parse under the safety-first profile.

#include <nanom/nanom.hpp>

#include "../bench/streaming_pcapng_parse.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

namespace nm = nanom;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

struct vlan_tag {
  nm::ubits<3>     pcp;
  nm::ubits<1>     dei;
  nm::ubits<12>    vid;
  nm::be<uint16_t> ether;
};
NANOM_DESCRIBE(vlan_tag, pcp, dei, vid, ether);

static void test_incremental_byte_growth() {
  const std::uint8_t wire[] = {0x60, 0x2a, 0x08, 0x00};
  for (std::size_t n = 0; n < 4; ++n) {
    auto r = nm::strct<vlan_tag>()(nm::streaming(nm::from(wire, n)));
    if (n < 4) {
      CHECK(!r);
      CHECK(r.error().kind == nm::errk::incomplete);
      CHECK(r.error().needed == 4 - n);
      CHECK(r.error().needed <= nm::max_incomplete_needed);
    }
  }
  auto ok = nm::strct<vlan_tag>()(nm::streaming(nm::from(wire, sizeof wire)));
  CHECK(ok && ok->value.vid == 42);
}

static void test_complete_downgrades_incomplete() {
  auto r = nm::complete(nm::tag("abc"))(nm::streaming(nm::from("ab", 2)));
  CHECK(!r && r.error().kind == nm::errk::err);
}

static void test_take_incomplete_needed_bounded() {
  const std::uint8_t wire[] = {0xff, 0xff, 0xff, 0xff};
  auto r = nm::take(1'000'000)(nm::streaming(nm::from(wire, sizeof wire)));
  CHECK(!r && r.error().kind == nm::errk::incomplete);
  CHECK(r.error().needed <= nm::max_incomplete_needed);
}

static std::vector<std::uint8_t> read_fixture(const char* path) {
  std::ifstream in(path, std::ios::binary);
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
}

static void test_streaming_pcapng_variable_cap() {
#ifndef NANOM_STREAMING_FIXTURE
#define NANOM_STREAMING_FIXTURE "examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng"
#endif
  const auto data = read_fixture(NANOM_STREAMING_FIXTURE);
  CHECK(!data.empty());

  const auto ref = streaming_pcapng::parse(data, streaming_pcapng::kDefaultCap);
  CHECK(ref.packets == 224);
  CHECK(ref.opts == 896);

  // Caps below the largest EPB block cannot complete a full pass — only assert no crash.
  for (std::size_t cap = 1; cap <= 1024; cap = (cap < 16 ? cap + 1 : cap + 16)) {
    (void)streaming_pcapng::parse(data, cap);
  }

  // Large enough to hold any block: refill boundaries must not change the aggregate.
  const std::size_t caps[] = {2048, 4096, 8192, streaming_pcapng::kDefaultCap};
  for (std::size_t cap : caps) {
    const auto a = streaming_pcapng::parse(data, cap);
    CHECK(a.packets == ref.packets);
    CHECK(a.sum_caplen == ref.sum_caplen);
    CHECK(a.sum_origlen == ref.sum_origlen);
    CHECK(a.opts == ref.opts);
    CHECK(a.checksum == ref.checksum);
  }
}

static void test_streaming_one_byte_refill_steps() {
#ifndef NANOM_STREAMING_FIXTURE
#define NANOM_STREAMING_FIXTURE "examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng"
#endif
  const auto data = read_fixture(NANOM_STREAMING_FIXTURE);
  CHECK(!data.empty());
  const auto ref = streaming_pcapng::parse(data, streaming_pcapng::kDefaultCap);

  // Window sizes that still fit the largest block — many refill steps, same result.
  for (std::size_t cap = 2048; cap <= 4096; cap += 64) {
    const auto a = streaming_pcapng::parse(data, cap);
    CHECK(a.checksum == ref.checksum);
  }
}

static void test_generation_tracked_streaming_overlay() {
  const std::uint8_t wire[] = {0x60, 0x2a, 0x08, 0x00};
  nm::wire_arena arena;
  auto in = nm::from(wire, sizeof wire, arena);
  in = nm::streaming(in);
  auto r = nm::overlay<vlan_tag>()(in);
  CHECK(r);
  CHECK(r->value.get<"vid">() == 42);
  arena.invalidate();
  bool faulted = false;
  try {
    (void)r->value.get<"vid">();
  } catch (const nm::generation_exception&) {
    faulted = true;
  }
  CHECK(faulted);
}

int main() {
  std::printf("nanom streaming safety tests\n");
  test_incremental_byte_growth();
  test_complete_downgrades_incomplete();
  test_take_incomplete_needed_bounded();
  test_streaming_pcapng_variable_cap();
  test_streaming_one_byte_refill_steps();
  test_generation_tracked_streaming_overlay();
  if (failures) {
    std::printf("%d FAILURE(S)\n", failures);
    return 1;
  }
  std::printf("all streaming safety tests passed\n");
  return 0;
}
