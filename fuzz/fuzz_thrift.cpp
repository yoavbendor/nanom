// fuzz_thrift — robustness + round-trip fuzzing of the reflected Thrift compact codec
// (nanom/tagged.hpp) through the Parquet metadata model (nanom/formats/parquet_thrift.hpp).
//
// Properties checked on every input:
//   1. decoding FileMetaData / PageHeader / ColumnIndex / OffsetIndex never crashes, reads out of
//      bounds, recurses unboundedly or allocates from an unchecked count (run under ASan/UBSan);
//   2. a successful FileMetaData decode can be walked completely (every lazy list, every lazy
//      element) without crashing — element errors are allowed, crashes are not;
//   3. canonical round trip: once decoded, encode(decode(encode(m))) == encode(m). Decoding drops
//      unknown top-level fields and normalizes varints, so the INPUT is not reproduced — but the
//      codec's own output must be a fixed point; thrift_compact_size agrees with the bytes written.
//
// The standalone driver also GENERATES inputs (tests/tagged_gen.hpp): random FileMetaData /
// PageHeader values built by reflection are encoded, must decode back to the same value, and are
// then mutated — structurally valid bytes reach far deeper into the decoder than noise does.
//
// libFuzzer:  clang++ -fsanitize=fuzzer,address,undefined -std=c++23 -I include fuzz/fuzz_thrift.cpp
// standalone: -DNANOM_FUZZ_STANDALONE, then ./nm_thrift_fuzz [iterations] [seed] — mutates a valid
//             seed footer (bit flips, truncation, byte insertion, splices) and feeds pure noise.
#include <nanom/formats/parquet_thrift.hpp>
#include <nanom/tagged_encode.hpp>

#include "../tests/tagged_gen.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace nm = nanom;
namespace pq = nanom_formats::parquet;

namespace {

std::uint64_t g_decoded = 0;    // inputs that decoded as FileMetaData (round trip exercised)
std::uint64_t g_generated = 0;  // generated messages that decoded back to themselves

[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "fuzz_thrift: %s\n", what);
  __builtin_trap();
}

nm::input in_of(const std::uint8_t* d, std::size_t n) {
  return nm::from(std::span<const std::byte>(reinterpret_cast<const std::byte*>(d), n));
}

void walk(const pq::FileMetaData& m) {
  (void)m.schema->for_each([](const pq::SchemaElement& e) { (void)e.name->size(); });
  if (m.key_value_metadata->has_value())
    (void)(*m.key_value_metadata)->for_each([](const pq::KeyValue& kv) { (void)kv.key->size(); });
  (void)m.row_groups->for_each([](const pq::RowGroup& rg) {
    (void)rg.columns->for_each([](const pq::ColumnChunk& cc) {
      if (!cc.meta_data->has_value()) return;
      const auto& c = **cc.meta_data;
      (void)c.path_in_schema->for_each([](std::string_view) {});
      (void)c.encodings->for_each([](pq::Encoding) {});
      if (c.encoding_stats->has_value()) (void)(*c.encoding_stats)->for_each([](const pq::PageEncodingStats&) {});
    });
  });
}

void round_trip(const pq::FileMetaData& m) {
  std::vector<std::byte> a, b;
  auto n = nm::thrift_compact_encode(m, a);
  if (!n || *n != a.size()) die("encoding a decoded footer failed");
  auto size = nm::thrift_compact_size(m);
  if (!size || *size != a.size()) die("thrift_compact_size disagrees with the bytes written");
  auto r = nm::thrift_compact<pq::FileMetaData>()(nm::from(std::span<const std::byte>(a)));
  if (!r) die("re-decode of the codec's own encoding failed");
  if (!r->rest.empty()) die("re-decode did not consume the whole encoding");
  if (!nm::thrift_compact_encode(r->value, b)) die("re-encode failed");
  if (a != b) die("encode(decode(encode(m))) != encode(m)");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const nm::input in = in_of(data, size);
  if (auto m = nm::thrift_compact<pq::FileMetaData>()(in)) {
    ++g_decoded;
    walk(m->value);
    round_trip(m->value);
  }
  (void)nm::thrift_compact<pq::PageHeader>()(in);
  (void)nm::thrift_compact<pq::ColumnIndex>()(in);
  if (auto oi = nm::thrift_compact<pq::OffsetIndex>()(in))
    (void)oi->value.page_locations->for_each([](const pq::PageLocation&) {});
  (void)pq::read_file_metadata(in);
  (void)nm::thrift_compact_skip(in);
  return 0;
}

#ifdef NANOM_FUZZ_STANDALONE
// ---- seed: a footer composed through the model itself (lists from the caller's elements) -------
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

std::vector<std::uint8_t> make_seed() {
  pq::SchemaElement root, a, b;
  root.name = std::string_view("schema");
  root.num_children = 2;
  a.name = std::string_view("id");
  a.type = pq::Type::INT64;
  a.repetition_type = pq::FieldRepetitionType::REQUIRED;
  b.name = std::string_view("ts");
  b.type = pq::Type::INT64;
  pq::LogicalType lt;
  lt.TIMESTAMP = pq::TimestampType{true, pq::TimeUnit{std::nullopt, nm::empty_struct{}, std::nullopt}};
  b.logicalType = lt;

  pq::Statistics st;
  st.null_count = 3;
  const std::byte lo[8]{}, hi[8]{std::byte{0xff}};
  st.min_value = nm::bytes(std::span<const std::byte>(lo));
  st.max_value = nm::bytes(std::span<const std::byte>(hi));

  const pq::Encoding encs[] = {pq::Encoding::PLAIN, pq::Encoding::RLE};
  const std::string_view path[] = {"id"};
  pq::ColumnMetaData c;
  c.type = pq::Type::INT64;
  c.encodings = nm::list<pq::Encoding>::of(encs);
  c.path_in_schema = nm::list<std::string_view>::of(path);
  c.codec = pq::CompressionCodec::SNAPPY;
  c.num_values = 1000;
  c.total_uncompressed_size = 8000;
  c.total_compressed_size = 4000;
  c.data_page_offset = 4;
  c.statistics = st;
  pq::ColumnChunk c1, c2;
  c1.file_offset = 4;
  c1.meta_data = c;
  c2.file_offset = 4004;
  c2.meta_data = c;
  const pq::ColumnChunk chunks[] = {c1, c2};
  pq::RowGroup rg;
  rg.columns = nm::list<pq::ColumnChunk>::of(chunks);
  rg.total_byte_size = 16000;
  rg.num_rows = 1000;
  const pq::RowGroup rgs[] = {rg, rg};
  const pq::SchemaElement schema[] = {root, a, b};
  const pq::KeyValue kv[] = {pq::KeyValue{std::string_view("k"), std::optional<std::string_view>("v")}};
  pq::FileMetaData f;
  f.version = 2;
  f.schema = nm::list<pq::SchemaElement>::of(schema);
  f.num_rows = 1000;
  f.row_groups = nm::list<pq::RowGroup>::of(rgs);
  f.key_value_metadata = nm::list<pq::KeyValue>::of(kv);
  f.created_by = std::string_view("nanom fuzz seed");

  std::vector<std::byte> enc;
  if (!nm::thrift_compact_encode(f, enc)) die("seed does not encode");
  auto r = nm::thrift_compact<pq::FileMetaData>()(nm::from(std::span<const std::byte>(enc)));
  if (!r || *r->value.num_rows != 1000 || r->value.row_groups->size() != 2) die("seed does not decode");
  std::vector<std::uint8_t> out(enc.size());
  for (std::size_t i = 0; i < enc.size(); ++i) out[i] = std::uint8_t(enc[i]);
  return out;
}
}  // namespace

int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 20000;
  Rng rng{argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x9E3779B97F4A7C15ull};
  const std::vector<std::uint8_t> seed = make_seed();
  LLVMFuzzerTestOneInput(seed.data(), seed.size());
  std::vector<std::uint8_t> buf;
  for (int i = 0; i < iters; ++i) {
    buf = seed;
    if (rng.next() % 3 == 0) {
      // generated: a random message must decode back to itself, then its bytes get mutated below
      std::mt19937_64 g(rng.next());
      nanom_test::arena ar;
      std::vector<std::byte> enc;
      bool ok = false;
      if (g() & 1) {
        const auto m = nanom_test::gen<pq::FileMetaData>(g, ar, 0);
        if (!nm::thrift_compact_encode(m, enc)) die("generated FileMetaData does not encode");
        auto r = nm::thrift_compact<pq::FileMetaData>()(nm::from(std::span<const std::byte>(enc)));
        ok = r && r->rest.empty() && nanom_test::same(m, r->value);
      } else {
        const auto m = nanom_test::gen<pq::PageHeader>(g, ar, 0);
        if (!nm::thrift_compact_encode(m, enc)) die("generated PageHeader does not encode");
        auto r = nm::thrift_compact<pq::PageHeader>()(nm::from(std::span<const std::byte>(enc)));
        ok = r && r->rest.empty() && nanom_test::same(m, r->value);
      }
      if (!ok) die("a generated message does not decode back to itself");
      ++g_generated;
      buf.assign(reinterpret_cast<const std::uint8_t*>(enc.data()),
                 reinterpret_cast<const std::uint8_t*>(enc.data()) + enc.size());
      LLVMFuzzerTestOneInput(buf.data(), buf.size());
    }
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
  std::printf("nm_thrift_fuzz: %d iterations OK (%llu decoded and round-tripped, %llu generated)\n", iters,
              static_cast<unsigned long long>(g_decoded), static_cast<unsigned long long>(g_generated));
  return 0;
}
#endif
