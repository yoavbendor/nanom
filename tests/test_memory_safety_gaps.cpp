// nanom memory-safety GAP suite — intentionally FAILING tests (WILL_FAIL in ctest).
//
// Each case documents a residual hazard from docs/THREAT_MODEL.md that nanom does
// not yet enforce at runtime. Tests avoid UB in the test process (no deliberate OOB
// reads or use-after-free); they fail via CHECK until guards land.
//
// Built with NANOM_GENERATION=0 to focus on untracked-parse and hot-path API gaps.
// Generation-specific gaps live in test_memory_safety_gaps_generation.cpp.
//
//   cmake -B build && cmake --build build -j --target nanom_memory_safety_gap_tests
//   ./build/nanom_memory_safety_gap_tests

#include <nanom/nanom.hpp>

#include <cstdio>
#include <cstdlib>
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

// GAP: THREAT_MODEL — in-place wire mutation behind a live view (contract-only today).
static void gap_wire_mutation_faults() {
  std::array<std::byte, 4> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08},
                                   std::byte{0x00}};
  auto r = nm::overlay<vlan_tag>()(nm::from(wire.data(), wire.size()));
  CHECK(r);
  nm::view<vlan_tag> v = r->value;
  CHECK(v.get<"vid">() == 42);
  wire[1] = std::byte{0xff};

  bool faulted = false;
  try {
    (void)v.get<"vid">();
  } catch (...) {
    faulted = true;
  }
  CHECK(faulted);
  CHECK(nm::wire_mutation_is_runtime_detected);
}

// GAP: hot-path input::operator[] has no bounds check (safe_at is opt-in).
static void gap_input_subscript_unchecked() {
  CHECK(nm::input_subscript_is_bounds_checked);
}

// GAP: input::advance(n) when n > size() is unchecked (checked_advance is opt-in).
static void gap_input_advance_unchecked() {
  CHECK(nm::input_advance_validates_bounds);
}

// GAP: untracked parse — no runtime hook to detect owner realloc/free.
static void gap_untracked_lifetime_undetected() {
  nm::bytes payload{};
  {
    std::vector<std::byte> wire = {std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};
    auto r = nm::take(4)(nm::from(wire.data(), wire.size()));
    CHECK(r);
    payload = r->value;
    CHECK(std::to_integer<std::uint8_t>(payload[0]) == 0xde);
  }
  CHECK(nm::runtime_span_lifetime_is_enforced);
}

// GAP: view can outlive owner without wire_arena — contract-only when untracked.
static void gap_view_uaf_untracked() {
  CHECK(nm::runtime_span_lifetime_is_enforced);
}

int main() {
  std::printf("nanom memory-safety GAP tests (NANOM_GENERATION=0, expected WILL_FAIL)\n");
  gap_wire_mutation_faults();
  gap_input_subscript_unchecked();
  gap_input_advance_unchecked();
  gap_untracked_lifetime_undetected();
  gap_view_uaf_untracked();
  if (failures) {
    std::printf("%d GAP FAILURE(S) — documented residual hazards\n", failures);
    return 1;
  }
  std::printf("all gap tests passed (hardening complete)\n");
  return 0;
}
