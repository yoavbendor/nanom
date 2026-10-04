// parquet_meta — dump a Parquet file's metadata as JSON using nanom's reflected Thrift model.
//
// Decodes the footer (FileMetaData), then for every column chunk walks the page headers from the
// first page to the end of the chunk, and decodes the OffsetIndex when the file has one. This is
// the differential-test driver for tests/parquet_differential.py (which checks it against pyarrow),
// and a compact example of the zero-copy model: every string below is a view into the file buffer,
// every repeated member a lazy list decoded while it is printed.
//
//   parquet_meta file.parquet
#include <nanom/formats/parquet_thrift.hpp>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace nm = nanom;
namespace pq = nanom_formats::parquet;

static std::string jstr(std::string_view s) {
  std::string o = "\"";
  for (char c : s) {
    const auto u = static_cast<unsigned char>(c);
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if (u < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", u); o += b; }
    else o += c;
  }
  return o + "\"";
}
static std::string hex(nm::bytes b) {
  static constexpr char d[] = "0123456789abcdef";
  std::string o = "\"";
  for (std::size_t i = 0; i < b.size(); ++i) {
    const auto u = std::uint8_t(b.data()[i]);
    o += d[u >> 4];
    o += d[u & 15];
  }
  return o + "\"";
}
template <class T> static std::string num(const std::optional<T>& v) {
  return v ? std::to_string(static_cast<long long>(*v)) : "null";
}

static const char* logical_kind(const pq::LogicalType& l) {
  if (l.STRING->has_value()) return "STRING";
  if (l.MAP->has_value()) return "MAP";
  if (l.LIST->has_value()) return "LIST";
  if (l.ENUM->has_value()) return "ENUM";
  if (l.DECIMAL->has_value()) return "DECIMAL";
  if (l.DATE->has_value()) return "DATE";
  if (l.TIME->has_value()) return "TIME";
  if (l.TIMESTAMP->has_value()) return "TIMESTAMP";
  if (l.INTEGER->has_value()) return "INTEGER";
  if (l.UNKNOWN->has_value()) return "UNKNOWN";
  if (l.JSON->has_value()) return "JSON";
  if (l.BSON->has_value()) return "BSON";
  if (l.UUID->has_value()) return "UUID";
  if (l.FLOAT16->has_value()) return "FLOAT16";
  return "OTHER";
}

static int fail(const nm::error& e, nm::input whole, const char* what) {
  std::fprintf(stderr, "parquet_meta: %s\n%s\n", what, e.render(whole).c_str());
  return 1;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: parquet_meta file.parquet\n");
    return 2;
  }
  std::ifstream f(argv[1], std::ios::binary);
  if (!f) {
    std::fprintf(stderr, "parquet_meta: cannot open %s\n", argv[1]);
    return 1;
  }
  const std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  const nm::input file = nm::from(std::string_view(raw.data(), raw.size()));

  auto md = pq::read_file_metadata(file);
  if (!md) return fail(md.error(), file, "footer");
  const pq::FileMetaData& m = md->value;

  std::string out = "{";
  out += "\"version\":" + std::to_string(*m.version);
  out += ",\"num_rows\":" + std::to_string(*m.num_rows);
  out += ",\"created_by\":" + (m.created_by->has_value() ? jstr(**m.created_by) : std::string("null"));

  out += ",\"key_value_metadata\":{";
  if (m.key_value_metadata->has_value()) {
    bool first = true;
    auto st = (*m.key_value_metadata)->for_each([&](const pq::KeyValue& kv) {
      out += (first ? "" : ",") + jstr(*kv.key) + ":" + (kv.value->has_value() ? jstr(**kv.value) : "null");
      first = false;
    });
    if (!st) return fail(st.error(), file, "key_value_metadata");
  }
  out += "}";

  out += ",\"schema\":[";
  bool first = true;
  auto st = m.schema->for_each([&](const pq::SchemaElement& e) {
    out += first ? "{" : ",{";
    first = false;
    out += "\"name\":" + jstr(*e.name);
    out += ",\"type\":" + num(*e.type);
    out += ",\"type_length\":" + num(*e.type_length);
    out += ",\"repetition\":" + num(*e.repetition_type);
    out += ",\"num_children\":" + num(*e.num_children);
    out += ",\"converted_type\":" + num(*e.converted_type);
    out += ",\"logical\":" + (e.logicalType->has_value() ? jstr(logical_kind(**e.logicalType)) : std::string("null"));
    out += "}";
  });
  if (!st) return fail(st.error(), file, "schema");
  out += "]";

  out += ",\"row_groups\":[";
  first = true;
  std::optional<nm::error> err;
  st = m.row_groups->for_each([&](const pq::RowGroup& rg) -> bool {
    out += first ? "{" : ",{";
    first = false;
    out += "\"num_rows\":" + std::to_string(*rg.num_rows);
    out += ",\"total_byte_size\":" + std::to_string(*rg.total_byte_size);
    out += ",\"columns\":[";
    bool cfirst = true;
    auto cst = rg.columns->for_each([&](const pq::ColumnChunk& cc) -> bool {
      out += cfirst ? "{" : ",{";
      cfirst = false;
      if (!cc.meta_data->has_value()) { out += "}"; return true; }
      const pq::ColumnMetaData& c = **cc.meta_data;
      out += "\"path\":[";
      bool pf = true;
      (void)c.path_in_schema->for_each([&](std::string_view p) { out += (pf ? "" : ",") + jstr(p); pf = false; });
      out += "],\"type\":" + std::to_string(int(*c.type));
      out += ",\"codec\":" + std::to_string(int(*c.codec));
      out += ",\"num_values\":" + std::to_string(*c.num_values);
      out += ",\"total_compressed_size\":" + std::to_string(*c.total_compressed_size);
      out += ",\"total_uncompressed_size\":" + std::to_string(*c.total_uncompressed_size);
      out += ",\"data_page_offset\":" + std::to_string(*c.data_page_offset);
      out += ",\"dictionary_page_offset\":" + num(*c.dictionary_page_offset);
      out += ",\"encodings\":[";
      bool ef = true;
      (void)c.encodings->for_each([&](pq::Encoding e) { out += (ef ? "" : ",") + std::to_string(int(e)); ef = false; });
      out += "]";
      if (c.statistics->has_value()) {
        const pq::Statistics& s = **c.statistics;
        out += ",\"stats\":{\"null_count\":" + num(*s.null_count);
        out += ",\"min_value\":" + (s.min_value->has_value() ? hex(**s.min_value) : std::string("null"));
        out += ",\"max_value\":" + (s.max_value->has_value() ? hex(**s.max_value) : std::string("null"));
        out += "}";
      }

      // walk the chunk's pages: header, skip the page body, repeat until the chunk is consumed
      const std::int64_t start = c.dictionary_page_offset->has_value() &&
                                         **c.dictionary_page_offset > 0
                                     ? **c.dictionary_page_offset
                                     : *c.data_page_offset;
      const std::int64_t end = start + *c.total_compressed_size;
      if (start < 0 || end < start || std::uint64_t(end) > file.size()) {
        err = nm::make_err(file, "column chunk inside the file").error();
        return false;
      }
      nm::input cur = file.advance(std::size_t(start));
      cur = cur.with_range(cur.first, file.first + end);
      std::int64_t values = 0, data_pages = 0, dict_pages = 0;
      while (!cur.empty()) {
        auto ph = nm::thrift_compact<pq::PageHeader>()(cur);
        if (!ph) { err = ph.error(); return false; }
        const pq::PageHeader& h = ph->value;
        const auto body = std::size_t(*h.compressed_page_size);
        if (*h.compressed_page_size < 0 || ph->rest.size() < body) {
          err = nm::make_err(ph->rest, "page body inside the column chunk").error();
          return false;
        }
        if (h.data_page_header->has_value()) { values += *(**h.data_page_header).num_values; ++data_pages; }
        if (h.data_page_header_v2->has_value()) { values += *(**h.data_page_header_v2).num_values; ++data_pages; }
        if (h.dictionary_page_header->has_value()) ++dict_pages;
        cur = ph->rest.advance(body);
      }
      out += ",\"pages\":{\"values\":" + std::to_string(values) + ",\"data\":" + std::to_string(data_pages) +
             ",\"dictionary\":" + std::to_string(dict_pages) + "}";

      if (cc.offset_index_offset->has_value() && cc.offset_index_length->has_value()) {
        const auto off = std::size_t(**cc.offset_index_offset), len = std::size_t(**cc.offset_index_length);
        if (off > file.size() || len > file.size() - off) {
          err = nm::make_err(file, "offset index inside the file").error();
          return false;
        }
        const nm::input oi_in = file.advance(off).with_range(file.first + off, file.first + off + len);
        auto oi = nm::thrift_compact<pq::OffsetIndex>()(oi_in);
        if (!oi) { err = oi.error(); return false; }
        out += ",\"offset_index_pages\":" + std::to_string(oi->value.page_locations->size());
      }
      out += "}";
      return true;
    });
    if (!cst) { err = cst.error(); return false; }
    if (err) return false;
    out += "]}";
    return true;
  });
  if (!st) return fail(st.error(), file, "row_groups");
  if (err) return fail(*err, file, "column chunk");
  out += "]}";
  std::puts(out.c_str());
  return 0;
}
