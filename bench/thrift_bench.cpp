// thrift_bench — Parquet footer decode cost through nanom's reflected Thrift compact codec.
//
// Builds a synthetic wide footer (R row groups x C columns, each column chunk with statistics and a
// path) with the same codec, then times three access patterns on it:
//   validate : thrift_compact<FileMetaData> — structural pass; row groups stay lazy (no allocation)
//   full     : validate + decode every row group, column chunk, path and encoding list
//   one_rg   : validate + decode a single row group from the middle (what a split reader does)
//   eager    : decode into an owning mirror (std::vector members): one pass, allocating
//
//   nm_thrift_bench [row_groups=1000] [columns=50] [reps=20]
//   nm_thrift_bench file.parquet [reps=20]      — the same patterns on a real file's footer
#include <nanom/formats/parquet_thrift.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace nm = nanom;
namespace pq = nanom_formats::parquet;

struct ColMetaW {
  nm::field<1, pq::Type>                      type;
  nm::field<2, std::vector<pq::Encoding>>     encodings;
  nm::field<3, std::vector<std::string_view>> path;
  nm::field<4, pq::CompressionCodec>          codec;
  nm::field<5, std::int64_t>                  num_values;
  nm::field<6, std::int64_t>                  uncompressed;
  nm::field<7, std::int64_t>                  compressed;
  nm::field<9, std::int64_t>                  data_page_offset;
  nm::field<12, pq::Statistics>               stats;
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
  nm::field<1, std::int32_t>                   version;
  nm::field<2, std::vector<pq::SchemaElement>> schema;
  nm::field<3, std::int64_t>                   rows;
  nm::field<4, std::vector<RowGroupW>>         row_groups;
};
NANOM_DESCRIBE(ColMetaW, type, encodings, path, codec, num_values, uncompressed, compressed,
               data_page_offset, stats);
NANOM_DESCRIBE(ChunkW, file_offset, meta);
NANOM_DESCRIBE(RowGroupW, columns, bytes, rows);
NANOM_DESCRIBE(FooterW, version, schema, rows, row_groups);

template <class F>
static double best_ns(int reps, F&& f) {
  double best = 1e30;
  for (int i = 0; i < reps; ++i) {
    const auto t0 = std::chrono::steady_clock::now();
    f();
    const auto t1 = std::chrono::steady_clock::now();
    best = std::min(best, std::chrono::duration<double, std::nano>(t1 - t0).count());
  }
  return best;
}

/// Decode every member reachable from a FileMetaData (the "full" pattern), accumulating into sink.
static bool walk_all(const pq::FileMetaData& m, std::int64_t& sink) {
  auto st = m.row_groups->for_each([&](const pq::RowGroup& rg) {
    (void)rg.columns->for_each([&](const pq::ColumnChunk& cc) {
      if (!cc.meta_data->has_value()) return;
      const auto& c = **cc.meta_data;
      sink += *c.num_values;
      if (c.statistics->has_value() && (**c.statistics).null_count->has_value())
        sink += **(**c.statistics).null_count;
      (void)c.path_in_schema->for_each([&](std::string_view p) { sink += std::int64_t(p.size()); });
      (void)c.encodings->for_each([&](pq::Encoding e) { sink += int(e); });
      if (c.encoding_stats->has_value())
        (void)(*c.encoding_stats)->for_each([&](const pq::PageEncodingStats& s) { sink += *s.count; });
    });
  });
  return bool(st);
}

static int bench_file(const char* path, int reps) {
  std::ifstream f(path, std::ios::binary);
  if (!f) { std::fprintf(stderr, "cannot open %s\n", path); return 1; }
  const std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  const nm::input file = nm::from(std::string_view(raw.data(), raw.size()));
  auto probe = pq::read_file_metadata(file);
  if (!probe) { std::fprintf(stderr, "%s\n", probe.error().render(file).c_str()); return 1; }
  std::int64_t chunks = 0;
  (void)probe->value.row_groups->for_each([&](const pq::RowGroup& rg) { chunks += std::int64_t(rg.columns->size()); });
  const auto loc = pq::locate_footer(file, file.size());
  const double mb = double(loc->value.metadata_length) / 1e6;
  std::int64_t sink = 0;
  const double validate = best_ns(reps, [&] {
    auto r = pq::read_file_metadata(file);
    if (!r) std::abort();
    sink += *r->value.num_rows;
  });
  const double full = best_ns(reps, [&] {
    auto r = pq::read_file_metadata(file);
    if (!r || !walk_all(r->value, sink)) std::abort();
  });
  const std::size_t n_rg = probe->value.row_groups->size();
  const double one = best_ns(reps, [&] {
    auto r = pq::read_file_metadata(file);
    if (!r) std::abort();
    auto rg = r->value.row_groups->at(n_rg / 2);
    if (!rg) std::abort();
    sink += *rg->num_rows;
  });
  std::printf("%s: %zu row groups, %lld column chunks, %.2f MB footer\n", path, n_rg,
              static_cast<long long>(chunks), mb);
  std::printf("  validate : %9.3f ms  %7.0f MB/s\n", validate / 1e6, mb / (validate / 1e9));
  std::printf("  full     : %9.3f ms  %7.0f MB/s  %6.1f ns/column chunk\n", full / 1e6,
              mb / (full / 1e9), full / double(chunks));
  std::printf("  one_rg   : %9.3f ms\n", one / 1e6);
  return sink == 42 ? 1 : 0;
}

int main(int argc, char** argv) {
  if (argc > 1 && std::string_view(argv[1]).find('.') != std::string_view::npos)
    return bench_file(argv[1], argc > 2 ? std::atoi(argv[2]) : 20);
  const int R = argc > 1 ? std::atoi(argv[1]) : 1000;
  const int C = argc > 2 ? std::atoi(argv[2]) : 50;
  const int reps = argc > 3 ? std::atoi(argv[3]) : 20;

  std::vector<std::string> names;
  for (int c = 0; c < C; ++c) names.push_back("column_" + std::to_string(c));
  const std::byte lo[8]{}, hi[8]{std::byte{0x7f}, std::byte{0x01}};
  FooterW f;
  f.version = 2;
  std::vector<pq::SchemaElement> schema(std::size_t(C) + 1);
  schema[0].name = std::string_view("schema");
  schema[0].num_children = C;
  for (int c = 0; c < C; ++c) {
    schema[std::size_t(c) + 1].name = std::string_view(names[std::size_t(c)]);
    schema[std::size_t(c) + 1].type = pq::Type::INT64;
  }
  f.schema = std::move(schema);
  f.rows = std::int64_t(R) * 100000;
  std::vector<RowGroupW> rgs(static_cast<std::size_t>(R));
  std::int64_t off = 4;
  for (auto& rg : rgs) {
    std::vector<ChunkW> cols(static_cast<std::size_t>(C));
    for (int c = 0; c < C; ++c) {
      ColMetaW m;
      m.type = pq::Type::INT64;
      m.encodings = std::vector<pq::Encoding>{pq::Encoding::PLAIN, pq::Encoding::RLE, pq::Encoding::RLE_DICTIONARY};
      m.path = std::vector<std::string_view>{names[std::size_t(c)]};
      m.codec = pq::CompressionCodec::ZSTD;
      m.num_values = 100000;
      m.uncompressed = 800000;
      m.compressed = 300000;
      m.data_page_offset = off;
      pq::Statistics st;
      st.null_count = 17;
      st.min_value = nm::bytes(std::span<const std::byte>(lo));
      st.max_value = nm::bytes(std::span<const std::byte>(hi));
      m.stats = st;
      cols[std::size_t(c)] = ChunkW{off, m};
      off += 300000;
    }
    rg.columns = std::move(cols);
    rg.bytes = std::int64_t(C) * 800000;
    rg.rows = 100000;
  }
  f.row_groups = std::move(rgs);
  std::vector<std::byte> wire;
  nm::thrift_compact_encode(f, wire);
  const nm::input in = nm::from(std::span<const std::byte>(wire));

  std::int64_t sink = 0;
  const double validate = best_ns(reps, [&] {
    auto r = nm::thrift_compact<pq::FileMetaData>()(in);
    if (!r) std::abort();
    sink += *r->value.num_rows;
  });
  const double full = best_ns(reps, [&] {
    auto r = nm::thrift_compact<pq::FileMetaData>()(in);
    if (!r) std::abort();
    auto st = r->value.row_groups->for_each([&](const pq::RowGroup& rg) {
      (void)rg.columns->for_each([&](const pq::ColumnChunk& cc) {
        const auto& m = **cc.meta_data;
        sink += *m.num_values + **(**m.statistics).null_count;
        (void)m.path_in_schema->for_each([&](std::string_view p) { sink += std::int64_t(p.size()); });
        (void)m.encodings->for_each([&](pq::Encoding e) { sink += int(e); });
      });
    });
    if (!st) std::abort();
  });
  const double one = best_ns(reps, [&] {
    auto r = nm::thrift_compact<pq::FileMetaData>()(in);
    if (!r) std::abort();
    auto rg = r->value.row_groups->at(std::size_t(R / 2));
    if (!rg) std::abort();
    sink += *rg->num_rows;
  });

  // eager: the owning mirror (std::vector members) decodes everything in ONE pass, allocating
  const double eager = best_ns(reps, [&] {
    auto r = nm::thrift_compact<FooterW>()(in);
    if (!r) std::abort();
    sink += std::int64_t(r->value.row_groups->size());
  });

  const double mb = double(wire.size()) / 1e6;
  const double chunks = double(R) * C;
  std::printf("footer: %d row groups x %d columns, %.2f MB of Thrift compact\n", R, C, mb);
  std::printf("  validate : %9.3f ms  %7.0f MB/s\n", validate / 1e6, mb / (validate / 1e9));
  std::printf("  full     : %9.3f ms  %7.0f MB/s  %6.1f ns/column chunk\n", full / 1e6,
              mb / (full / 1e9), full / chunks);
  std::printf("  one_rg   : %9.3f ms\n", one / 1e6);
  std::printf("  eager    : %9.3f ms  %7.0f MB/s  %6.1f ns/column chunk (std::vector mirror, one pass)\n",
              eager / 1e6, mb / (eager / 1e9), eager / chunks);
  return sink == 42 ? 1 : 0;
}
