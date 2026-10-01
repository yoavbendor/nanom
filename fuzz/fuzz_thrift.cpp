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
//      codec's own output must be a fixed point.
//
// libFuzzer:  clang++ -fsanitize=fuzzer,address,undefined -std=c++23 -I include fuzz/fuzz_thrift.cpp
// standalone: -DNANOM_FUZZ_STANDALONE, then ./nm_thrift_fuzz [iterations] [seed] — mutates a valid
//             seed footer (bit flips, truncation, byte insertion, splices) and feeds pure noise.
#include <nanom/formats/parquet_thrift.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace nm = nanom;
namespace pq = nanom_formats::parquet;

namespace {

std::uint64_t g_decoded = 0;  // inputs that decoded as FileMetaData (round trip exercised)

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
  nm::thrift_compact_encode(m, a);
  auto r = nm::thrift_compact<pq::FileMetaData>()(nm::from(std::span<const std::byte>(a)));
  if (!r) die("re-decode of the codec's own encoding failed");
  if (!r->rest.empty()) die("re-decode did not consume the whole encoding");
  nm::thrift_compact_encode(r->value, b);
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
// ---- seed: an owning "writer-side" mirror of the footer, encoded with the same codec ------------
// These mirror structs use std::vector where the reader model uses lazy nm::list views: the same
// field ids, so the writer's output is the reader's input — the nanoarrow2parquet /
// parquet2nanoarrow pairing in miniature.
struct ColMetaW {
  nm::field<1, pq::Type>                       type;
  nm::field<2, std::vector<pq::Encoding>>      encodings;
  nm::field<3, std::vector<std::string_view>>  path;
  nm::field<4, pq::CompressionCodec>           codec;
  nm::field<5, std::int64_t>                   num_values;
  nm::field<6, std::int64_t>                   uncompressed;
  nm::field<7, std::int64_t>                   compressed;
  nm::field<9, std::int64_t>                   data_page_offset;
  nm::field<12, std::optional<pq::Statistics>> stats;
};
struct ChunkW {
  nm::field<2, std::int64_t> file_offset;
  nm::field<3, ColMetaW>     meta;
};
struct RowGroupW {
  nm::field<1, std::vector<ChunkW>> columns;
  nm::field<2, std::int64_t>        bytes;
  nm::field<3, std::int64_t>        rows;
};
struct FooterW {
  nm::field<1, std::int32_t>                     version;
  nm::field<2, std::vector<pq::SchemaElement>>   schema;
  nm::field<3, std::int64_t>                     rows;
  nm::field<4, std::vector<RowGroupW>>           row_groups;
  nm::field<5, std::vector<pq::KeyValue>>        kv;
  nm::field<6, std::string_view>                 created_by;
};
NANOM_DESCRIBE(ColMetaW, type, encodings, path, codec, num_values, uncompressed, compressed,
               data_page_offset, stats);
NANOM_DESCRIBE(ChunkW, file_offset, meta);
NANOM_DESCRIBE(RowGroupW, columns, bytes, rows);
NANOM_DESCRIBE(FooterW, version, schema, rows, row_groups, kv, created_by);

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

  ColMetaW c;
  c.type = pq::Type::INT64;
  c.encodings = std::vector<pq::Encoding>{pq::Encoding::PLAIN, pq::Encoding::RLE};
  c.path = std::vector<std::string_view>{"id"};
  c.codec = pq::CompressionCodec::SNAPPY;
  c.num_values = 1000;
  c.uncompressed = 8000;
  c.compressed = 4000;
  c.data_page_offset = 4;
  c.stats = st;
  RowGroupW rg;
  rg.columns = std::vector<ChunkW>{ChunkW{4, c}, ChunkW{4004, c}};
  rg.bytes = 16000;
  rg.rows = 1000;
  FooterW f;
  f.version = 2;
  f.schema = std::vector<pq::SchemaElement>{root, a, b};
  f.rows = 1000;
  f.row_groups = std::vector<RowGroupW>{rg, rg};
  f.kv = std::vector<pq::KeyValue>{pq::KeyValue{std::string_view("k"), std::optional<std::string_view>("v")}};
  f.created_by = std::string_view("nanom fuzz seed");

  std::vector<std::byte> enc;
  nm::thrift_compact_encode(f, enc);
  // the writer mirror's bytes must decode through the zero-copy reader model
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
  std::printf("nm_thrift_fuzz: %d iterations OK (%llu decoded and round-tripped)\n", iters,
              static_cast<unsigned long long>(g_decoded));
  return 0;
}
#endif
