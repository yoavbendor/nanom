// fuzz_protobuf — robustness + round-trip fuzzing of the protobuf codec (nanom/protobuf.hpp,
// nanom/protobuf_encode.hpp) through the Lance metadata model (nanom/formats/lance_protobuf.hpp).
//
// Properties checked on every input:
//   1. decoding Manifest / FileDescriptor / ColumnMetadata / Metadata / IndexMetadata never crashes, reads out of
//      bounds, recurses unboundedly or allocates from an unchecked count (run under ASan/UBSan);
//   2. canonical round trip: whatever decodes re-encodes (protobuf_size agrees with the bytes
//      written), decodes back to the same value, and encode(decode(encode(m))) == encode(m).
//      Unknown fields are dropped and varints normalized, so the INPUT is not reproduced — the
//      codec's own output must be a fixed point.
//
// The standalone driver also GENERATES inputs (tests/protobuf_gen.hpp): random messages built by
// reflection are encoded, must decode back to themselves, and are then mutated — structurally
// valid bytes reach far deeper into the decoder than noise does.
//
// libFuzzer:  clang++ -fsanitize=fuzzer,address,undefined -std=c++23 -I include fuzz/fuzz_protobuf.cpp
// standalone: -DNANOM_FUZZ_STANDALONE, then ./nm_protobuf_fuzz [iterations] [seed]
#include <nanom/formats/lance_protobuf.hpp>
#include <nanom/protobuf_encode.hpp>

#include "../tests/protobuf_gen.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace nm = nanom;
namespace lance = nanom_formats::lance;

namespace {

std::uint64_t g_decoded = 0;    // inputs that decoded (round trip exercised)
std::uint64_t g_generated = 0;  // generated messages that decoded back to themselves

[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "fuzz_protobuf: %s\n", what);
  __builtin_trap();
}

nm::input in_of(const std::byte* d, std::size_t n) { return nm::from(std::span<const std::byte>(d, n)); }

template <class M>
void round_trip(const M& m) {
  std::vector<std::byte> a, b;
  auto n = nm::protobuf_encode(m, a);
  if (!n || *n != a.size()) die("encoding a decoded message failed");
  auto size = nm::protobuf_size(m);
  if (!size || *size != a.size()) die("protobuf_size disagrees with the bytes written");
  auto r = nm::protobuf<M>()(in_of(a.data(), a.size()));
  if (!r) die("re-decode of the codec's own encoding failed");
  if (!nanom_test::pb::same(m, r->value)) die("decode(encode(m)) != m");
  if (!nm::protobuf_encode(r->value, b)) die("re-encode failed");
  if (a != b) die("encode(decode(encode(m))) != encode(m)");
}

template <class M>
void one(nm::input in) {
  if (auto m = nm::protobuf<M>()(in)) {
    ++g_decoded;
    round_trip(m->value);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const nm::input in = in_of(reinterpret_cast<const std::byte*>(data), size);
  one<lance::Manifest>(in);
  one<lance::FileDescriptor>(in);
  one<lance::ColumnMetadata>(in);
  one<lance::Metadata>(in);
  one<lance::IndexMetadata>(in);
  return 0;
}

#ifdef NANOM_FUZZ_STANDALONE
namespace {
struct Rng {
  std::uint64_t s;
  std::uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
};

template <class M>
std::vector<std::uint8_t> generated(std::mt19937_64& g) {
  nanom_test::pb::arena ar;
  const auto m = nanom_test::pb::gen<M>(g, ar, 0);
  std::vector<std::byte> enc;
  if (!nm::protobuf_encode(m, enc)) die("a generated message does not encode");
  auto r = nm::protobuf<M>()(in_of(enc.data(), enc.size()));
  if (!r || !nanom_test::pb::same(m, r->value)) die("a generated message does not decode back to itself");
  ++g_generated;
  return std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(enc.data()),
                                   reinterpret_cast<const std::uint8_t*>(enc.data()) + enc.size());
}
}  // namespace

int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 20000;
  Rng rng{argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x9E3779B97F4A7C15ull};
  std::vector<std::uint8_t> buf;
  for (int i = 0; i < iters; ++i) {
    std::mt19937_64 g(rng.next());
    switch (g() % 5) {
      case 0: buf = generated<lance::Manifest>(g); break;
      case 1: buf = generated<lance::FileDescriptor>(g); break;
      case 2: buf = generated<lance::ColumnMetadata>(g); break;
      case 3: buf = generated<lance::IndexMetadata>(g); break;
      default: buf = generated<lance::Metadata>(g); break;
    }
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
    switch (rng.next() % 5) {
      case 0:  // pure noise
        buf.resize(1 + rng.next() % 512);
        for (auto& x : buf) x = std::uint8_t(rng.next() >> 24);
        break;
      case 1:  // truncate
        buf.resize(rng.next() % (buf.size() + 1));
        break;
      default: {  // a few byte flips / inserts / deletes
        const int edits = 1 + int(rng.next() % 4);
        for (int e = 0; e < edits && !buf.empty(); ++e) {
          const std::size_t at = rng.next() % buf.size();
          switch (rng.next() % 3) {
            case 0: buf[at] = std::uint8_t(rng.next() >> 24); break;
            case 1: buf.insert(buf.begin() + std::ptrdiff_t(at), std::uint8_t(rng.next() >> 24)); break;
            default: buf.erase(buf.begin() + std::ptrdiff_t(at)); break;
          }
        }
      }
    }
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  std::printf("nm_protobuf_fuzz: %d iterations OK (%llu decoded and round-tripped, %llu generated)\n", iters,
              static_cast<unsigned long long>(g_decoded), static_cast<unsigned long long>(g_generated));
  return 0;
}
#endif
