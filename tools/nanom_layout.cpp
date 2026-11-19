// SPDX-License-Identifier: Apache-2.0
// nanom-layout — decode raw record files described by a JSON Lines layout.
//
//   nanom-layout --layout desc.jsonl [--enums enums.json] [--raw-file-name NAME] --input file.raw
//                [--stride N] [--stride-for NAME=N] [--select PATTERN]... [--records A:B]
//                [--format jsonl|csv|summary|fields|arrow-schema] [--enums-as dictionary|integer|both]
//                [--name-separator S]
//                [--big-endian] [--lenient] [--allow-partial] [--via-columns]
//                [--strategy auto|field|record] [-o OUT]
//
// arrow-schema decodes the records and prints the schema export_arrow produces (one JSON line per
// Arrow column: name, format, dictionary values, field metadata); --enums-as picks how enum
// columns with an enum table are exported (see docs/LAYOUT.md).
// The raw_file in the description is a logical name; the bytes come from --input. --raw-file-name
// may be omitted when the description has a single raw_file. --list prints the raw_files.
#include <nanom/layout.hpp>

#include <cstdio>
#include <cstdlib>

#if __has_include(<sys/mman.h>)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#define NANOM_LAYOUT_MMAP 1
#endif

namespace lay = nanom::layout;

namespace {

int usage(const char* why) {
  if (why) std::fprintf(stderr, "nanom-layout: %s\n", why);
  std::fputs(
      "usage: nanom-layout --layout DESC.jsonl [--enums ENUMS.json] [--raw-file-name NAME]\n"
      "                    --input FILE.raw [--stride N] [--stride-for NAME=N]\n"
      "                    [--select PATTERN]... [--records A:B]\n"
      "                    [--format jsonl|csv|summary|fields|arrow-schema]\n"
      "                    [--enums-as dictionary|integer|both] (Arrow export of enum columns)\n"
      "                    [--name-separator S] (Arrow column names: '.' -> S, default '/')\n"
      "                    [--big-endian] [--lenient] [--allow-partial] [--via-columns]\n"
      "                    [--strategy auto|field|record] [-o OUT]\n"
      "       nanom-layout --layout DESC.jsonl --list\n"
      "PATTERN: exact name, subtree (\"A.b\" selects A.b.*), prefix ending in '.' or '::', or glob (* ?)\n",
      stderr);
  return 2;
}

/// The input bytes: mmap'ed when possible (zero-copy), else read.
struct mapped {
  std::span<const std::byte> bytes;
  std::vector<std::byte> owned;
#if NANOM_LAYOUT_MMAP
  void* map = nullptr;
  std::size_t len = 0;
  ~mapped() { if (map) munmap(map, len); }
#endif
};

bool open_input(const std::string& path, mapped& m) {
#if NANOM_LAYOUT_MMAP
  const int fd = ::open(path.c_str(), O_RDONLY);
  if (fd >= 0) {
    struct stat st{};
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
      m.len = std::size_t(st.st_size);
      if (m.len == 0) { ::close(fd); return true; }
      void* p = mmap(nullptr, m.len, PROT_READ, MAP_PRIVATE, fd, 0);
      ::close(fd);
      if (p != MAP_FAILED) {
        m.map = p;
        m.bytes = {static_cast<const std::byte*>(p), m.len};
        return true;
      }
    } else ::close(fd);
  }
#endif
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) return false;
  std::byte buf[1 << 16];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) m.owned.insert(m.owned.end(), buf, buf + n);
  std::fclose(f);
  m.bytes = m.owned;
  return true;
}

std::optional<std::uint64_t> to_u64(std::string_view s) {
  std::uint64_t v;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc{} || p != s.data() + s.size()) return std::nullopt;
  return v;
}

}  // namespace

int main(int argc, char** argv) {
  std::string layout_path, enums_path, raw_name, input_path, out_path, format = "jsonl";
  std::vector<std::string> selects;
  lay::compile_options co;
  lay::load_options lo;
  lay::decode_options dopt;
  lay::arrow_options aopt;
  bool list = false, via_columns = false;
  std::optional<std::pair<std::uint64_t, std::optional<std::uint64_t>>> range;

  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    const char* v = nullptr;
    if (a == "-h" || a == "--help") return usage(nullptr), 0;
    else if (a == "--list") list = true;
    else if (a == "--lenient") { lo.strict = false; co.strict = false; }
    else if (a == "--big-endian") co.order = std::endian::big;
    else if (a == "--allow-partial") dopt.allow_partial = true;
    else if (a == "--via-columns") via_columns = true;
    else if (!(v = next())) return usage(("missing value after " + std::string(a)).c_str());
    else if (a == "--layout") layout_path = v;
    else if (a == "--enums") enums_path = v;
    else if (a == "--raw-file-name") raw_name = v;
    else if (a == "--input") input_path = v;
    else if (a == "-o" || a == "--output") out_path = v;
    else if (a == "--format") format = v;
    else if (a == "--select") selects.emplace_back(v);
    else if (a == "--name-separator") {
      if (!*v || std::string_view(v).find_first_of("[]") != std::string_view::npos)
        return usage("--name-separator needs a non-empty string without '[' or ']'");
      aopt.separator = v;
    }
    else if (a == "--enums-as") {
      const std::string_view s = v;
      if (s == "dictionary") aopt.enums = lay::enum_mode::dictionary;
      else if (s == "integer") aopt.enums = lay::enum_mode::integer;
      else if (s == "both") aopt.enums = lay::enum_mode::both;
      else return usage("--enums-as is dictionary, integer or both");
    }
    else if (a == "--strategy") {
      const std::string_view s = v;
      dopt.strat = s == "field" ? lay::strategy::field_major
                 : s == "record" ? lay::strategy::record_major
                 : s == "auto" ? lay::strategy::automatic
                 : (usage("--strategy is auto, field or record"), std::exit(2), lay::strategy::automatic);
    } else if (a == "--stride") {
      auto n = to_u64(v);
      if (!n || !*n) return usage("--stride needs a positive integer");
      co.stride = *n;
    } else if (a == "--stride-for") {
      const std::string_view s = v;
      const auto eq = s.rfind('=');
      auto n = eq == std::string_view::npos ? std::nullopt : to_u64(s.substr(eq + 1));
      if (!n || !*n) return usage("--stride-for needs NAME=N");
      co.stride_by_file[std::string(s.substr(0, eq))] = *n;
    } else if (a == "--records") {
      const std::string_view s = v;
      const auto c = s.find(':');
      auto lo_ = to_u64(s.substr(0, c));
      std::optional<std::uint64_t> hi;
      if (c != std::string_view::npos && c + 1 < s.size()) {
        hi = to_u64(s.substr(c + 1));
        if (!hi) return usage("--records is A:B, A: or A");
      } else if (c == std::string_view::npos && lo_) hi = *lo_ + 1;
      if (!lo_) return usage("--records is A:B, A: or A");
      range = {*lo_, hi};
    } else return usage(("unknown option " + std::string(a)).c_str());
  }
  if (layout_path.empty()) return usage("--layout is required");

  auto desc = lay::load_description(layout_path, lo);
  if (!desc) { std::fprintf(stderr, "nanom-layout: %s\n", desc.error().str().c_str()); return 1; }
  for (const auto& w : desc->warnings) std::fprintf(stderr, "nanom-layout: warning: %s\n", w.c_str());
  if (list) {
    for (const auto& f : desc->raw_files) std::printf("%s\t%zu scalars\n", f.c_str(), desc->of(f).size());
    return 0;
  }
  if (raw_name.empty()) {
    if (desc->raw_files.size() != 1) {
      std::fprintf(stderr, "nanom-layout: the description has %zu raw_files; pick one with --raw-file-name:\n",
                   desc->raw_files.size());
      for (const auto& f : desc->raw_files) std::fprintf(stderr, "  %s\n", f.c_str());
      return 2;
    }
    raw_name = desc->raw_files[0];
  }
  std::optional<lay::enum_catalog> enums;
  if (!enums_path.empty()) {
    auto e = lay::load_enums(enums_path);
    if (!e) { std::fprintf(stderr, "nanom-layout: %s\n", e.error().str().c_str()); return 1; }
    enums = std::move(*e);
  }
  auto plan = lay::plan::compile(*desc, raw_name, enums ? &*enums : nullptr, co);
  if (!plan) { std::fprintf(stderr, "nanom-layout: %s\n", plan.error().str().c_str()); return 1; }
  for (const auto& w : plan->warnings()) std::fprintf(stderr, "nanom-layout: warning: %s\n", w.c_str());

  lay::selection sel = plan->all();
  if (!selects.empty()) {
    auto s = plan->select(std::span<const std::string>(selects));
    if (!s) { std::fprintf(stderr, "nanom-layout: %s\n", s.error().str().c_str()); return 1; }
    sel = std::move(*s);
  }

  std::FILE* out = stdout;
  if (!out_path.empty() && out_path != "-") {
    out = std::fopen(out_path.c_str(), "wb");
    if (!out) { std::fprintf(stderr, "nanom-layout: cannot write %s\n", out_path.c_str()); return 1; }
  }
  auto sink = [out](std::string_view s) { std::fwrite(s.data(), 1, s.size(), out); };

  if (format == "fields") {  // the compiled plan, one line per field
    std::string buf = "column\tbit_offset\tbit_width\ttype\tfamily\tstorage\tbyte\tshift\n";
    for (auto i : sel.fields) {
      const auto& f = plan->fields()[i];
      buf += f.column + '\t' + std::to_string(f.bit_offset) + '\t' + std::to_string(f.bit_width) +
             '\t' + f.type + '\t' + lay::family_name(f.fam) + '\t' + lay::storage_name(f.st) + '\t' +
             std::to_string(f.bit_offset / 8) + '\t' + std::to_string(f.bit_offset % 8) + '\n';
    }
    sink(buf);
    return 0;
  }

  if (input_path.empty()) return usage("--input is required");
  mapped in;
  if (!open_input(input_path, in)) { std::fprintf(stderr, "nanom-layout: cannot read %s\n", input_path.c_str()); return 1; }
  const auto recs = plan->records(in.bytes);
  if (recs.tail_bytes()) {
    std::fprintf(stderr, "nanom-layout: %s: %zu whole record(s) of %zu bytes + %zu trailing byte(s)%s\n",
                 input_path.c_str(), recs.size(), plan->stride(), recs.tail_bytes(),
                 dopt.allow_partial ? " (ignored)" : " — wrong --stride? (--allow-partial ignores them)");
    if (!dopt.allow_partial) return 1;
  }
  if (range) {
    dopt.first = std::size_t(range->first);
    if (range->second) {
      if (*range->second < range->first) return usage("--records A:B needs A <= B");
      dopt.count = std::size_t(*range->second - range->first);
    }
  }

  lay::lresult<std::size_t> n = std::size_t(0);
  if (format == "jsonl" && via_columns) {
    auto t = lay::decode(*plan, in.bytes, sel, dopt);
    if (!t) n = nanom::unexpected<lay::layout_error>(t.error());
    else {
      const lay::jsonl_writer w(*plan, sel);
      const auto cols = w.bind(*t);
      std::string buf;
      for (std::size_t r = 0; r < t->rows(); ++r) {
        w.write(buf, *t, r, cols);
        if (buf.size() > (1u << 20)) { sink(buf); buf.clear(); }
      }
      sink(buf);
      n = t->rows();
    }
  } else if (format == "jsonl") {
    n = lay::export_jsonl(*plan, in.bytes, sink, sel, dopt);
  } else if (format == "arrow-schema") {
    auto t = lay::decode(*plan, in.bytes, sel, dopt);
    if (!t) n = nanom::unexpected<lay::layout_error>(t.error());
    else {
      n = t->rows();
      ArrowSchema s{};
      ArrowArray a{};
      lay::export_arrow(std::move(*t), &s, &a, aopt);
      std::string buf;
      for (std::int64_t c = 0; c < s.n_children; ++c) {
        const ArrowSchema* cs = s.children[c];
        const ArrowArray* ca = a.children[c];
        buf += "{\"name\":";
        lay::append_json_string(buf, cs->name);
        buf += ",\"format\":";
        lay::append_json_string(buf, cs->format);
        if (cs->dictionary) {
          buf += ",\"dictionary\":{\"format\":";
          lay::append_json_string(buf, cs->dictionary->format);
          buf += ",\"values\":[";
          const auto* off = static_cast<const std::int32_t*>(ca->dictionary->buffers[1]);
          const auto* ch = static_cast<const char*>(ca->dictionary->buffers[2]);
          for (std::int64_t i = 0; i < ca->dictionary->length; ++i) {
            if (i) buf += ',';
            lay::append_json_string(buf, std::string_view(ch + off[i], std::size_t(off[i + 1] - off[i])));
          }
          buf += "]}";
        }
        const auto md = lay::arrow_metadata(cs->metadata);
        if (!md.empty()) {
          buf += ",\"metadata\":{";
          for (std::size_t i = 0; i < md.size(); ++i) {
            if (i) buf += ',';
            lay::append_json_string(buf, md[i].first);
            buf += ':';
            lay::append_json_string(buf, md[i].second);
          }
          buf += '}';
        }
        buf += "}\n";
      }
      a.release(&a);
      s.release(&s);
      sink(buf);
    }
  } else if (format == "csv") {
    n = lay::export_csv(*plan, in.bytes, sink, sel, dopt);
  } else if (format == "summary") {
    std::size_t fam[7] = {}, bitfields = 0;
    for (auto i : sel.fields) {
      ++fam[std::size_t(plan->fields()[i].fam)];
      bitfields += plan->fields()[i].bitfield();
    }
    std::string s;
    s += "raw_file     " + plan->raw_file() + "\n";
    s += "input        " + input_path + " (" + std::to_string(in.bytes.size()) + " bytes)\n";
    s += "stride       " + std::to_string(plan->stride()) + " bytes (fields cover " +
         std::to_string(plan->used_bytes()) + ", alignment " + std::to_string(plan->alignment()) +
         (plan->order() == std::endian::big ? ", big-endian)\n" : ", little-endian)\n");
    s += "records      " + std::to_string(recs.size()) + (recs.tail_bytes() ? " + " + std::to_string(recs.tail_bytes()) + " trailing bytes\n" : "\n");
    s += "fields       " + std::to_string(sel.fields.size()) + " of " + std::to_string(plan->size()) +
         " (" + std::to_string(bitfields) + " bit-fields)\n";
    for (int k = 0; k < 7; ++k)
      if (fam[k]) s += "  " + std::string(lay::family_name(lay::family(k))) + std::string(10 - std::strlen(lay::family_name(lay::family(k))), ' ') + std::to_string(fam[k]) + "\n";
    if (recs.size()) {
      s += "first record ";
      const lay::jsonl_writer w(*plan, sel);
      std::string line;
      w.write(line, recs[std::min<std::size_t>(dopt.first, recs.size() - 1)]);
      if (line.size() > 400) line = line.substr(0, 400) + "...\n";
      s += line;
    }
    sink(s);
    n = recs.size();
  } else {
    return usage("--format is jsonl, csv, summary, fields or arrow-schema");
  }
  if (!n) { std::fprintf(stderr, "nanom-layout: %s\n", n.error().str().c_str()); return 1; }
  if (out != stdout) std::fclose(out);
  else std::fflush(stdout);
  return 0;
}
