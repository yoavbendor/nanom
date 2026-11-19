// SPDX-License-Identifier: Apache-2.0
// The two ways to turn a JSON-described raw file into Arrow columns (docs/LAYOUT_GUIDE.md):
//
//   Flavor A, "all fields":  decode every scalar of every record -> one Arrow column each.
//   Flavor B, "pick fields": decode only the scalars you name; the rest of each record is never read.
//
// Both end in export_arrow(): a struct of flat columns named with '/' between the name components,
// enum columns as dictionary<intN, utf8> so the names travel with the data (into Lance, Parquet...).
// This file is built and run by ctest (example_layout_to_arrow), so the guide's code stays true.
#include <nanom/layout.hpp>

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace lay = nanom::layout;

// In real use these come from files: lay::load_description(path) / lay::load_enums(path).
static constexpr std::string_view kDescription = R"(
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.grab_index","bit_offset":0,"bit_width":32,"type":"UInt"}
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.slow_index","bit_offset":32,"bit_width":32,"type":"UInt"}
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.tapi_index","bit_offset":64,"bit_width":32,"type":"UInt"}
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.brain_type","bit_offset":96,"bit_width":32,"type":"Enum ref = 1"}
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.BlackDummy","bit_offset":128,"bit_width":8,"type":"Logical*1"}
)";
static constexpr std::string_view kEnums = R"({"/dev/vdiZ/pacemaker/gfi.raw": {"Enum ref = 1":
  {"-1": "UNDEF", "0": "IMG1", "1": "IMG2", "2": "IMG3", "3": "IMG4", "4": "IMG5", "5": "IMG6"}}})";
static constexpr std::string_view kRawFile = "/dev/vdiZ/pacemaker/gfi.raw";

static int failures = 0;
#define CHECK(c)                                                    \
  do {                                                              \
    if (!(c)) {                                                     \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);      \
      ++failures;                                                   \
    }                                                               \
  } while (0)

// Stand-in for the raw file: 1000 GFI records of 20 bytes (17 used, aligned to 4).
static std::vector<std::byte> make_records(std::size_t n) {
  std::vector<std::byte> b(n * 20);
  for (std::size_t r = 0; r < n; ++r) {
    const std::uint32_t grab = std::uint32_t(r), slow = std::uint32_t(r * 2), tapi = 7;
    const std::int32_t brain = std::int32_t(r % 7) - 1;  // -1 .. 5
    std::memcpy(&b[r * 20 + 0], &grab, 4);
    std::memcpy(&b[r * 20 + 4], &slow, 4);
    std::memcpy(&b[r * 20 + 8], &tapi, 4);
    std::memcpy(&b[r * 20 + 12], &brain, 4);
    b[r * 20 + 16] = std::byte(r & 1);
  }
  return b;
}

// What a consumer (nanoarrow, nanolance's nano_lance_write_batch, pyarrow...) would receive.
static void show(const char* title, const ArrowSchema& s, const ArrowArray& a) {
  std::printf("%s: %lld rows, %lld columns\n", title, (long long)a.length, (long long)s.n_children);
  for (std::int64_t c = 0; c < s.n_children; ++c)
    std::printf("  %-24s format=%-3s%s\n", s.children[c]->name, s.children[c]->format,
                s.children[c]->dictionary ? "  (dictionary of utf8 names)" : "");
}

int main() {
  // 1. Load the description and the enum names, compile a plan for one raw_file. -----------------
  //    The plan is everything nanom needs to know: byte offset / shift / mask / sign of every field,
  //    the record size (stride), and the enum tables. Compile once, reuse for every file and batch.
  auto desc = lay::parse_description(kDescription);
  if (!desc) return std::printf("description: %s\n", desc.error().str().c_str()), 1;
  auto enums = lay::parse_enums(kEnums);
  if (!enums) return std::printf("enums: %s\n", enums.error().str().c_str()), 1;
  lay::compile_options co;
  co.stride = 20;  // you know the struct size: say so (see "Alignment" in the guide)
  auto plan = lay::plan::compile(*desc, kRawFile, &*enums, co);
  if (!plan) return std::printf("plan: %s\n", plan.error().str().c_str()), 1;

  const std::vector<std::byte> file = make_records(1000);
  const std::span<const std::byte> bytes(file);  // in real use: mmap the file, or read a chunk

  // 2. Flavor A: every field. ------------------------------------------------------------------
  {
    lay::decode_options o;  // o.first / o.count decode a slice of records (chunk big files)
    auto table = lay::decode(*plan, bytes, o);
    if (!table) return std::printf("decode: %s\n", table.error().str().c_str()), 1;
    ArrowSchema schema;
    ArrowArray array;
    lay::export_arrow(std::move(*table), &schema, &array);  // separator "/", enums as dictionary
    show("all fields", schema, array);
    CHECK(array.length == 1000 && schema.n_children == 5);
    CHECK(std::string_view(schema.children[3]->name) == "GFI/brain_type");
    CHECK(schema.children[3]->dictionary != nullptr);  // dictionary<int8, utf8>
    // ... hand (&array, &schema) to the consumer here, e.g. nano_lance_write_batch(&w, &array, &schema)
    array.release(&array);
    schema.release(&schema);
  }

  // 3. Flavor B: only the fields you need. -----------------------------------------------------
  {
    auto pick = plan->select({"GFI.grab_index", "GFI.brain_type"});  // exact names, subtrees, globs
    if (!pick) return std::printf("select: %s\n", pick.error().str().c_str()), 1;
    auto table = lay::decode(*plan, bytes, *pick);
    if (!table) return std::printf("decode: %s\n", table.error().str().c_str()), 1;
    CHECK(table->column<std::uint32_t>("GFI.grab_index")[999] == 999);  // canonical '.' names here
    lay::arrow_options ao;
    ao.separator = "/";  // the default; any string without '[' ']'; "." keeps the dotted names
    ArrowSchema schema;
    ArrowArray array;
    lay::export_arrow(std::move(*table), &schema, &array, ao);
    show("picked fields", schema, array);
    CHECK(schema.n_children == 2 && std::string_view(schema.children[0]->name) == "GFI/grab_index");
    array.release(&array);
    schema.release(&schema);
  }

  // 4. No Arrow at all: a few fields read in your own loop (handles are precomputed; no strings).
  {
    auto brain = plan->find("GFI.brain_type");
    std::size_t undef = 0;
    for (auto rec : plan->records(bytes))
      if (rec.get<int>(*brain) == -1) ++undef;
    CHECK(undef == 143);  // r % 7 == 0 for r < 1000
  }

  if (failures) return std::printf("%d failure(s)\n", failures), 1;
  std::printf("layout_to_arrow: all checks passed\n");
  return 0;
}
