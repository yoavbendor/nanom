// SPDX-License-Identifier: Apache-2.0
// nanom-layout — decode raw record files described by a JSON Lines layout.
//
//   nanom-layout --layout desc.jsonl [--enums enums.json] [--raw-file-name NAME] --input file.raw
//                [--stride N] [--stride-for NAME=N] [--select PATTERN]... [--records A:B]
//                [--format jsonl|csv|summary|fields|arrow-schema] [--enums-as dictionary|integer|both]
//                [--name-separator S]
//                [--big-endian] [--lenient] [--allow-partial] [--via-columns]
//                [--strategy auto|field|record] [-o OUT]
//                [--physical] [--no-nulls] [--signals-as raw|physical|both]      (AUTOSAR signals)
//                [--e2e P --data-id N | --data-id-list HEX32] [--e2e-offset BITS]
//                [--e2e-mode both|alt|low|nibble] [--e2e-max-delta N]
//   nanom-layout --layout desc.jsonl --encode VALUES.jsonl [--raw-values] [--pdu-template HEX]
//                [--e2e ...] -o OUT.raw
//
// AUTOSAR: --physical prints raw * factor + offset for scaled signals (JSON/CSV) and adds physical
// columns (Arrow, --signals-as); multiplexed / update-bit signals print null unless --no-nulls.
// --encode reads one JSON object per line ({"Signal": value, ...}, physical values unless
// --raw-values), writes one PDU per line (stride bytes, starting from --pdu-template or zeros) and,
// with --e2e, protects each PDU (counter 0, 1, ...). --format e2e-check checks the input PDUs
// with the same --e2e options and prints one status per PDU.
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
      "                    [--physical] [--no-nulls] [--signals-as raw|physical|both]\n"
      "                    [--e2e p01|p02|p04|p05|p06|p07|p11|p22 --data-id N | --data-id-list HEX32]\n"
      "                    [--e2e-offset BITS] [--e2e-mode both|alt|low|nibble] [--e2e-max-delta N]\n"
      "                    [--format ...|e2e-check]\n"
      "       nanom-layout --layout DESC.jsonl --encode VALUES.jsonl [--raw-values]\n"
      "                    [--pdu-template HEX] [--e2e ...] -o OUT.raw\n"
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
  bool list = false, via_columns = false, raw_values = false;
  lay::text_options topt;
  std::string encode_path, pdu_template;
  std::optional<lay::e2e::config> e2e;
  lay::e2e::config ec;
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
    else if (a == "--physical") { topt.physical = true; dopt.physical = true; }
    else if (a == "--no-nulls") { topt.nulls = false; dopt.validity = false; }
    else if (a == "--raw-values") raw_values = true;
    else if (!(v = next())) return usage(("missing value after " + std::string(a)).c_str());
    else if (a == "--layout") layout_path = v;
    else if (a == "--enums") enums_path = v;
    else if (a == "--raw-file-name") raw_name = v;
    else if (a == "--input") input_path = v;
    else if (a == "-o" || a == "--output") out_path = v;
    else if (a == "--format") format = v;
    else if (a == "--select") selects.emplace_back(v);
    else if (a == "--encode") encode_path = v;
    else if (a == "--pdu-template") pdu_template = v;
    else if (a == "--signals-as") {
      const std::string_view s = v;
      if (s == "raw") aopt.signals = lay::signal_mode::raw;
      else if (s == "physical") aopt.signals = lay::signal_mode::physical;
      else if (s == "both") aopt.signals = lay::signal_mode::both;
      else return usage("--signals-as is raw, physical or both");
    }
    else if (a == "--e2e") {
      static constexpr std::pair<std::string_view, lay::e2e::profile> ps[] = {
          {"p01", lay::e2e::profile::p01}, {"p02", lay::e2e::profile::p02}, {"p04", lay::e2e::profile::p04},
          {"p05", lay::e2e::profile::p05}, {"p06", lay::e2e::profile::p06}, {"p07", lay::e2e::profile::p07},
          {"p11", lay::e2e::profile::p11}, {"p22", lay::e2e::profile::p22}};
      bool ok = false;
      for (auto [n, pr] : ps) if (n == v) { ec.prof = pr; ok = true; }
      if (!ok) return usage("--e2e is p01, p02, p04, p05, p06, p07, p11 or p22");
      e2e = ec;
    }
    else if (a == "--data-id") {
      auto n = to_u64(v);
      if (!n || *n > 0xFFFFFFFFu) return usage("--data-id needs a 32-bit integer");
      ec.data_id = std::uint32_t(*n);
    }
    else if (a == "--data-id-list") {
      const std::string_view s = v;
      if (s.size() != 32) return usage("--data-id-list needs 32 hex digits (16 bytes)");
      for (std::size_t k = 0; k < 16; ++k) {
        unsigned b = 0;
        auto r = std::from_chars(s.data() + 2 * k, s.data() + 2 * k + 2, b, 16);
        if (r.ec != std::errc{} || r.ptr != s.data() + 2 * k + 2) return usage("--data-id-list needs 32 hex digits");
        ec.data_id_list[k] = std::uint8_t(b);
      }
    }
    else if (a == "--e2e-offset") {
      auto n = to_u64(v);
      if (!n || *n > 0xFFFFFFFFu) return usage("--e2e-offset needs a bit offset");
      ec.offset = std::uint32_t(*n);
    }
    else if (a == "--e2e-max-delta") {
      auto n = to_u64(v);
      if (!n || *n > 0xFFFFFFFFu) return usage("--e2e-max-delta needs an integer");
      ec.max_delta_counter = std::uint32_t(*n);
    }
    else if (a == "--e2e-mode") {
      const std::string_view s = v;
      if (s == "both") ec.id_mode = lay::e2e::data_id_mode::both;
      else if (s == "alt") ec.id_mode = lay::e2e::data_id_mode::alt;
      else if (s == "low") ec.id_mode = lay::e2e::data_id_mode::low;
      else if (s == "nibble") ec.id_mode = lay::e2e::data_id_mode::nibble;
      else return usage("--e2e-mode is both, alt, low or nibble");
    }
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
  if (e2e) {  // options may come in any order: take the final values
    const auto prof = e2e->prof;
    e2e = ec;
    e2e->prof = prof;
  }

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

  if (!encode_path.empty()) {
    auto text = lay::read_text_file(encode_path);
    if (!text) { std::fprintf(stderr, "nanom-layout: %s\n", text.error().str().c_str()); return 1; }
    std::vector<std::byte> tmpl(plan->stride());
    if (!pdu_template.empty()) {
      if (pdu_template.size() != 2 * plan->stride()) return usage("--pdu-template needs 2 * stride hex digits");
      for (std::size_t k = 0; k < plan->stride(); ++k) {
        unsigned b = 0;
        auto r = std::from_chars(pdu_template.data() + 2 * k, pdu_template.data() + 2 * k + 2, b, 16);
        if (r.ec != std::errc{} || r.ptr != pdu_template.data() + 2 * k + 2) return usage("--pdu-template: bad hex");
        tmpl[k] = std::byte(b);
      }
    }
    std::optional<lay::e2e::protector> tx;
    if (e2e) tx.emplace(*e2e);
    std::vector<std::byte> pdu;
    std::vector<lay::plan::signal_value> vals;
    std::string_view t = *text;
    std::size_t line = 0, count = 0;
    while (!t.empty()) {
      const auto nl = t.find('\n');
      std::string_view ln = t.substr(0, nl);
      t = nl == std::string_view::npos ? std::string_view{} : t.substr(nl + 1);
      ++line;
      if (ln.find_first_not_of(" \t\r") == std::string_view::npos) continue;
      auto j = lay::parse_json(ln);
      auto fail = [&](const std::string& m) {
        std::fprintf(stderr, "nanom-layout: %s:%zu: %s\n", encode_path.c_str(), line, m.c_str());
        return 1;
      };
      if (!j) return fail(j.error().what);
      if (!j->is_object()) return fail("each line must be an object of signal: value");
      vals.clear();
      for (const auto& m : j->members) {
        auto h = plan->find(m.key);
        if (!h) return fail("no signal \"" + m.key + "\"");
        if (!m.value.is_int() && m.value.t != lay::json::type::real) return fail("\"" + m.key + "\" needs a number");
        vals.push_back(lay::plan::signal_value{*h, m.value.d, raw_values});
      }
      pdu = tmpl;
      auto r = plan->encode(vals, pdu);
      if (!r) return fail(r.error().str());
      if (tx && !tx->protect(pdu)) return fail("E2E configuration does not fit the PDU");
      sink(std::string_view(reinterpret_cast<const char*>(pdu.data()), pdu.size()));
      ++count;
    }
    if (out != stdout) std::fclose(out);
    std::fprintf(stderr, "nanom-layout: encoded %zu PDU(s) of %zu bytes\n", count, plan->stride());
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
      const lay::jsonl_writer w(*plan, sel, topt);
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
    n = lay::export_jsonl(*plan, in.bytes, sink, sel, dopt, topt);
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
    n = lay::export_csv(*plan, in.bytes, sink, sel, dopt, topt);
  } else if (format == "e2e-check") {
    if (!e2e) return usage("--format e2e-check needs --e2e");
    lay::e2e::checker rx(*e2e);
    std::string buf;
    for (std::size_t i = 0; i < recs.size(); ++i) {
      buf += lay::e2e::status_name(rx.check(recs[i].bytes()));
      buf += '\n';
    }
    sink(buf);
    n = recs.size();
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
