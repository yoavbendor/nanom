// Red-team demos: deliberately exercise UB / hangs under sanitizers.
// NOT part of default ctest. Build with:
//   cmake -B build -DNANOM_MEMORY_SAFETY_UB_DEMOS=ON -DNANOM_SANITIZER=address,undefined
//   cmake --build build -j --target nanom_memory_safety_ub_demos
//   ./build/nanom_memory_safety_ub_demos
//
// Each demo is isolated in its own process via fork() so one fault does not
// mask another. Exit code counts how many demos faulted (expected >0 today).

#include <nanom/nanom.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace nm = nanom;

struct vlan_tag {
  nm::ubits<3>     pcp;
  nm::ubits<1>     dei;
  nm::ubits<12>    vid;
  nm::be<uint16_t> ether;
};
NANOM_DESCRIBE(vlan_tag, pcp, dei, vid, ether);

using demo_fn = void (*)();

static int run_isolated(demo_fn fn) {
  fflush(stdout);
  fflush(stderr);
  const pid_t pid = fork();
  if (pid < 0) return 1;
  if (pid == 0) {
    fn();
    std::_Exit(0);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return 1;
  if (WIFSIGNALED(status)) return 1;
  if (WIFEXITED(status) && WEXITSTATUS(status) != 0) return 1;
  return 0;
}

// ------------------------------------------------------------------ demos
static void demo_null_take() {
  auto r = nm::take(4)(nm::from(nullptr, 8));
  std::printf("  null take: %s\n", r ? "succeeded (BAD)" : "failed");
  if (r) {
    volatile std::uint8_t b = std::uint8_t(r->value[0]);
    (void)b;
  }
}

static void demo_advance_oob_read() {
  const char wire[] = "ab";
  nm::input past = nm::from(wire, 2).advance(99);
  auto r = nm::take(8)(past);
  std::printf("  advance+take: %s\n", r ? "succeeded (BAD)" : "failed");
  if (r) {
    volatile std::uint8_t b = std::uint8_t(r->value[0]);
    (void)b;
  }
}

static void demo_index_oob() {
  const char wire[] = "abc";
  nm::input in = nm::from(wire, 3);
  volatile std::uint8_t b = in[99];
  (void)b;
}

static void demo_dangling_tag() {
  auto parser = [&]() {
    std::string pattern = "MAGIC";
    return nm::tag(pattern);
  }();
  const char wire[] = "MAGIC";
  auto r = parser(nm::from(wire, 5));
  std::printf("  dangling tag: %s\n", r ? "matched" : "failed");
}

static void demo_view_uaf() {
  auto buf = std::make_unique<std::array<std::byte, 4>>();
  (*buf)[0] = std::byte{0x60};
  (*buf)[1] = std::byte{0x2a};
  (*buf)[2] = std::byte{0x08};
  (*buf)[3] = std::byte{0x00};
  nm::view<vlan_tag> v{};
  {
    auto r = nm::overlay<vlan_tag>()(nm::from(buf->data(), buf->size()));
    v = r->value;
  }
  buf.reset();
  volatile auto vid = v.get<"vid">();
  (void)vid;
}

static void demo_null_view_get() {
  nm::view<vlan_tag> v{};
  volatile auto pcp = v.get<"pcp">();
  (void)pcp;
}

static void demo_error_render_oob() {
  const char wire[] = "abc";
  nm::error e{};
  e.offset = 1'000'000;
  std::string msg = e.render(nm::from(wire, 3));
  std::printf("  render len=%zu\n", msg.size());
}

static void demo_zero_consume_spin() {
  int ticks = 0;
  auto p = [&](nm::input in) -> nm::result<nm::unit> {
    if (++ticks > 1'000'000) return nm::unexp(nm::error{});
    return nm::done{nm::unit{}, in};
  };
  (void)nm::many0(p)(nm::from("x", 1));
  std::printf("  many0 zero-consume: ticks=%d\n", ticks);
}

struct case_t {
  const char* name;
  demo_fn fn;
};

int main() {
  const case_t cases[] = {
      {"null_pointer_take", demo_null_take},
      {"advance_then_take_oob", demo_advance_oob_read},
      {"operator_index_oob", demo_index_oob},
      {"dangling_tag_pattern", demo_dangling_tag},
      {"view_use_after_free", demo_view_uaf},
      {"null_view_get", demo_null_view_get},
      {"error_render_oob", demo_error_render_oob},
      {"many0_zero_consume", demo_zero_consume_spin},
  };

  int faults = 0;
  std::printf("nanom UB/hang demos (expect sanitizer faults or many0 guard)\n");
  for (const auto& c : cases) {
    std::printf("[%s]\n", c.name);
    if (run_isolated(c.fn)) {
      std::printf("  => fault/timeout/nonzero exit (expected)\n");
      ++faults;
    } else {
      std::printf("  => clean exit (unexpected — hardened?)\n");
    }
  }
  std::printf("%d / %zu demos faulted\n", faults, sizeof cases / sizeof cases[0]);
  return faults == 0 ? 1 : 0;  // invert: success when demos still catch bugs
}
