// Generation gap tests — document hazards not yet caught by attested_bytes / generation.
// Expected to fail (WILL_FAIL in CMake) until future hardening lands.
#include <nanom/nanom.hpp>

#include <cstdio>
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

// In-place mutation without invalidate should be detected (future: wire immutability).
static void test_inplace_mutation_undetected() {
  std::vector<std::byte> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08},
                                 std::byte{0x00}};
  nm::wire_arena arena;
  auto r = nm::overlay<vlan_tag>()(nm::from(wire.data(), wire.size(), arena));
  CHECK(r);
  auto v = r->value;
  CHECK(v.get<"vid">() == 42);
  wire[0] = std::byte{0xff};
  bool threw = false;
  try {
    (void)v.get<"vid">();
  } catch (const nm::generation_exception&) {
    threw = true;
  }
  CHECK(threw);  // WANT: fault; HAVE: generation unchanged on in-place write
}

// Stale bytes tied to arena_a should reject use after arena_b re-registers same pointer.
static void test_cross_arena_bytes_mismatch() {
  std::array<std::byte, 4> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08},
                                   std::byte{0x00}};
  nm::wire_arena arena_a;
  nm::wire_arena arena_b;
  nm::bytes b{};
  {
    auto r = nm::take(4)(nm::from(wire.data(), wire.size(), arena_a));
    CHECK(r);
    b = r->value;
    CHECK(b[0] == 0x60);
  }
  arena_b.open(wire.data(), wire.size());
  bool threw = false;
  try {
    (void)b[0];
  } catch (const nm::generation_exception&) {
    threw = true;
  }
  CHECK(threw);  // WANT: arena identity check; HAVE: only gen on arena_a
}

// Realloc without invalidate leaves generation unchanged (caller must open/invalidate).
static void test_realloc_without_invalidate() {
  std::vector<std::byte> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08},
                                 std::byte{0x00}};
  nm::wire_arena arena;
  const std::byte* old_ptr = nullptr;
  std::uint64_t gen = 0;
  {
    auto r = nm::take(4)(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    old_ptr = r->value.data();
    gen     = arena.generation;
  }
  wire.resize(64);
  CHECK(wire.data() != old_ptr);
  CHECK(arena.generation != gen);  // WANT: auto-bump on realloc; HAVE: unchanged until invalidate
}

// alpha1 / klass parsers yield string_view — not attested_bytes (text path gap).
static void test_klass_string_view_unattested() {
  const char text[] = "abc123";
  nm::wire_arena arena;
  std::string_view sv{};
  {
    auto r = nm::alphanumeric1(nm::from(reinterpret_cast<const std::byte*>(text), 6, arena));
    CHECK(r);
    sv = r->value;
    CHECK(sv.size() == 6);
    arena.invalidate();
  }
  bool threw = false;
  try {
    (void)sv[0];
  } catch (const nm::generation_exception&) {
    threw = true;
  }
  CHECK(threw);  // WANT: attested text; HAVE: plain string_view
}

int main() {
  std::printf("nanom generation gap tests (expected failures documented)\n");
  test_inplace_mutation_undetected();
  test_cross_arena_bytes_mismatch();
  test_realloc_without_invalidate();
  test_klass_string_view_unattested();
  if (failures) {
    std::printf("%d FAILURE(S) — gap tests document unfixed hazards\n", failures);
    return 1;
  }
  std::printf("all generation gap tests passed (unexpected — hardening may have landed)\n");
  return 0;
}
