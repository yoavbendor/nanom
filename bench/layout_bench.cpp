// layout_bench — how fast does nanom decode JSON-described raw records?
//
// Two layouts, both defined ONCE as constexpr tables below, from which the bench (a) writes the
// JSON Lines description nanom loads at run time, and (b) instantiates a hand-written-equivalent
// static decoder (every offset, shift, mask, type and column a compile-time constant — what a code
// generator emitting a C++ struct + loads would produce). That static decoder is the upper bound.
//
//   gfi      the user's sample: 2 x GFI (5 fields) per 40-byte record, millions of records
//   devices  a ~59 KB record with ~8000 scalars (3% bit-fields), 2000 records, nested names
//
// Contenders per layout, best of N runs (the machine is shared; take the best):
//   static (record-major / field-major)   compile-time decoder — the ceiling
//   naive interpreter                     per record, per field: switch on the type, generic bits
//   nanom field-major / record-major / auto
//   nanom projection (~1% of the fields)
//   nanom JSON Lines export
//   memcpy of the input                    the memory-bandwidth yardstick
//
// usage: layout_bench [scale=1.0] [reps=7] [--only static_rm|static_fm|naive|field|record|auto|projection|jsonl]   (scale shrinks record counts; the
// smoke test runs scale 0.002). --only runs one contender, silently (for callgrind: run it with
// reps 1 and reps 11, the difference / 10 is one run; see docs/LAYOUT.md).
#include <nanom/layout.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>

namespace lay = nanom::layout;

// ------------------------------------------------------------------ layouts as constexpr tables
enum kind : std::uint8_t { K_U, K_I, K_F, K_BOOL, K_PTR, K_ENUM };
struct spec {
  std::uint32_t bit_off;
  std::uint8_t width;
  kind k;
};

constexpr spec GFI[] = {
    {0, 32, K_U},   {32, 32, K_U},  {64, 32, K_U},  {96, 32, K_ENUM},  {128, 8, K_BOOL},
    {160, 32, K_U}, {192, 32, K_U}, {224, 32, K_U}, {256, 32, K_ENUM}, {288, 8, K_BOOL},
};

#ifndef LAYOUT_BENCH_NDEV
#define LAYOUT_BENCH_NDEV 8000  // -DLAYOUT_BENCH_NDEV=2000 builds ~4x faster (multiple of 200)
#endif
constexpr std::size_t NDEV = LAYOUT_BENCH_NDEV;
constexpr std::array<spec, NDEV> make_dev() {
  std::array<spec, NDEV> a{};
  std::uint64_t s = 0x9E3779B97F4A7C15ull;
  std::uint32_t cur = 0;
  auto rnd = [&s]() { s = s * 6364136223846793005ull + 1442695040888963407ull; return std::uint32_t(s >> 33); };
  for (std::size_t i = 0; i < NDEV; ++i) {
    const std::uint32_t r = rnd() % 100;
    if (r >= 94) cur += 8 * (rnd() % 128);  // unlisted members / padding
    if (r < 3) {                            // bit-field in a 32-bit unit
      const std::uint8_t w = std::uint8_t(1 + rnd() % 12);
      if ((cur % 32) + w > 32) cur = (cur + 31) / 32 * 32;
      a[i] = spec{cur, w, (r & 1) ? K_I : K_U};
      cur += w;
      continue;
    }
    const std::uint32_t z = rnd() % 100;
    const std::uint8_t bytes = z < 20 ? 1 : z < 30 ? 2 : z < 75 ? 4 : 8;
    const std::uint32_t t = rnd() % 100;
    kind k = t < 45 ? K_U : t < 75 ? K_I : t < 85 ? K_F : t < 92 ? K_BOOL : t < 96 ? K_ENUM : K_PTR;
    if (k == K_F && bytes < 4) k = K_U;
    if (k == K_ENUM && bytes != 4) k = K_I;
    if (k == K_PTR && bytes != 8) k = K_U;
    cur = (cur + 8u * bytes - 1) / (8u * bytes) * (8u * bytes);
    a[i] = spec{cur, std::uint8_t(8 * bytes), k};
    cur += 8u * bytes;
  }
  return a;
}
constexpr auto DEV = make_dev();

template <const auto& L>
constexpr std::size_t stride_of() {
  std::uint64_t end = 0, al = 1;
  for (const spec& s : L) {
    end = std::max<std::uint64_t>(end, s.bit_off + s.width);
    const bool nat = s.bit_off % 8 == 0 && (s.width == 8 || s.width == 16 || s.width == 32 || s.width == 64);
    al = std::max<std::uint64_t>(al, nat ? s.width / 8 : 4);
  }
  return std::size_t(((end + 7) / 8 + al - 1) / al * al);
}

// evaluated once per layout (clang re-evaluates a constexpr call at every use: 16000 uses x 8000
// fields made the build take > 10 minutes)
template <const auto& L>
inline constexpr std::size_t stride_v = stride_of<L>();

constexpr bool natural(const spec& s) {
  return s.bit_off % 8 == 0 && (s.width == 8 || s.width == 16 || s.width == 32 || s.width == 64);
}
constexpr std::size_t col_size(const spec& s) {
  if (s.k == K_BOOL) return 1;
  const unsigned b = (s.width + 7) / 8;
  return b <= 1 ? 1 : b <= 2 ? 2 : b <= 4 ? 4 : 8;
}

static std::string type_name(const spec& s) {
  switch (s.k) {
    case K_U: return natural(s) ? (s.width == 8 ? "UChar" : s.width == 16 ? "UShort" : s.width == 32 ? "UInt" : "ULongLong") : "UInt";
    case K_I: return natural(s) ? (s.width == 8 ? "Char" : s.width == 16 ? "Short" : s.width == 32 ? "Int" : "LongLong") : "Int";
    case K_F: return s.width == 32 ? "Float" : "Double";
    case K_BOOL: return "Logical*" + std::to_string(s.width / 8);
    case K_PTR: return "*Void";
    default: return "Enum ref = 5";
  }
}

static std::string describe_gfi() {
  static const char* names[] = {"grab_index", "slow_index", "tapi_index", "brain_type", "BlackDummy"};
  std::string d;
  for (std::size_t i = 0; i < std::size(GFI); ++i)
    d += "{\"raw_file\":\"/dev/vdiZ/pacemaker/gfi.raw\",\"scalar_name\":\"GFI." + std::string(names[i % 5]) +
         "\",\"bit_offset\":" + std::to_string(GFI[i].bit_off) + ",\"bit_width\":" +
         std::to_string(GFI[i].width) + ",\"type\":\"" + type_name(GFI[i]) + "\"}\n";
  return d;
}
static std::string dev_name(std::size_t i) {
  const std::size_t g = i / 100;
  if (g < NDEV / 200) return "MEIO::IOAppDevices._uartWrite.array_item_" + std::to_string(g) + "._cnt" + std::to_string(i % 7) + "._f" + std::to_string(i);
  return "MEIO::IOAppDevices._dev" + std::to_string(g) + ".Diagnostics::DeviceStatus._f" + std::to_string(i);
}
static std::string describe_dev() {
  std::string d;
  for (std::size_t i = 0; i < NDEV; ++i)
    d += "{\"raw_file\":\"/proc/app/devices.raw\",\"scalar_name\":\"" + dev_name(i) + "\",\"bit_offset\":" +
         std::to_string(DEV[i].bit_off) + ",\"bit_width\":" + std::to_string(DEV[i].width) +
         ",\"type\":\"" + type_name(DEV[i]) + "\"}\n";
  return d;
}

// ------------------------------------------------------------------ the static (generated) decoder
template <class T>
inline T ld(const std::byte* p) { T v; std::memcpy(&v, p, sizeof v); return v; }

template <const auto& L, std::size_t I>
inline void st_field(const std::byte* rec, std::size_t r, void* col) {
  constexpr spec s = L[I];
  constexpr std::size_t STRIDE = stride_v<L>;
  if constexpr (natural(s)) {
    using T = std::conditional_t<s.width == 8, std::uint8_t, std::conditional_t<s.width == 16, std::uint16_t,
              std::conditional_t<s.width == 32, std::uint32_t, std::uint64_t>>>;
    const T v = ld<T>(rec + s.bit_off / 8);
    if constexpr (s.k == K_BOOL) static_cast<std::uint8_t*>(col)[r] = v != 0;
    else static_cast<T*>(col)[r] = v;
  } else {
    constexpr std::size_t byte = s.bit_off / 8;
    constexpr std::size_t off = byte + 8 <= STRIDE ? byte : STRIDE - 8;
    constexpr unsigned sh = unsigned(s.bit_off - 8 * off);
    std::uint64_t v = ld<std::uint64_t>(rec + off) << (64 - sh - s.width);
    v = s.k == K_I ? std::uint64_t(std::int64_t(v) >> (64 - s.width)) : v >> (64 - s.width);
    using T = std::conditional_t<(s.width > 8), std::uint16_t, std::uint8_t>;
    static_cast<T*>(col)[r] = T(v);
  }
}
template <const auto& L, std::size_t... I>
void static_record_major(const std::byte* src, std::size_t n, void* const* cols, std::index_sequence<I...>) {
  constexpr std::size_t STRIDE = stride_v<L>;
  if constexpr (sizeof...(I) <= 32) {
    void* c[] = {cols[I]...};  // few columns: keep the pointers in registers
    for (std::size_t r = 0; r < n; ++r) {
      const std::byte* rec = src + r * STRIDE;
      (st_field<L, I>(rec, r, c[I]), ...);
    }
  } else {
    for (std::size_t r = 0; r < n; ++r) {
      const std::byte* rec = src + r * STRIDE;
      (st_field<L, I>(rec, r, cols[I]), ...);
    }
  }
}
template <const auto& L, std::size_t I>
inline void static_column(const std::byte* src, std::size_t n, void* col) {
  constexpr std::size_t STRIDE = stride_v<L>;
  for (std::size_t r = 0; r < n; ++r) st_field<L, I>(src + r * STRIDE, r, col);
}
template <const auto& L, std::size_t... I>
void static_field_major(const std::byte* src, std::size_t n, void* const* cols, std::index_sequence<I...>) {
  constexpr std::size_t STRIDE = stride_v<L>;
  constexpr std::size_t B = std::min<std::size_t>(16384, std::max<std::size_t>(32, (std::size_t(1) << 20) / STRIDE));
  for (std::size_t r0 = 0; r0 < n; r0 += B) {
    const std::size_t nb = std::min(B, n - r0);
    (static_column<L, I>(src + r0 * STRIDE, nb,
                         static_cast<std::byte*>(cols[I]) + r0 * col_size(L[I])), ...);
  }
}
// devices: 8000-term folds are split into chunks of 200 (clang caps fold nesting at 256)
constexpr std::size_t CHUNK = 200;
template <std::size_t Base, std::size_t... I>
void dev_rm_chunk(const std::byte* rec, std::size_t r, void* const* cols, std::index_sequence<I...>) {
  (st_field<DEV, Base + I>(rec, r, cols[Base + I]), ...);
}
template <std::size_t... C>
void dev_static_record_major(const std::byte* src, std::size_t n, void* const* cols, std::index_sequence<C...>) {
  constexpr std::size_t STRIDE = stride_v<DEV>;
  for (std::size_t r = 0; r < n; ++r) {
    const std::byte* rec = src + r * STRIDE;
    (dev_rm_chunk<C * CHUNK>(rec, r, cols, std::make_index_sequence<CHUNK>{}), ...);
  }
}
template <std::size_t Base, std::size_t... I>
void dev_fm_chunk(const std::byte* blk, std::size_t nb, std::size_t r0, void* const* cols, std::index_sequence<I...>) {
  (static_column<DEV, Base + I>(blk, nb, static_cast<std::byte*>(cols[Base + I]) + r0 * col_size(DEV[Base + I])), ...);
}
template <std::size_t... C>
void dev_static_field_major(const std::byte* src, std::size_t n, void* const* cols, std::index_sequence<C...>) {
  constexpr std::size_t STRIDE = stride_v<DEV>;
  constexpr std::size_t B = std::max<std::size_t>(32, (std::size_t(1) << 20) / STRIDE);
  for (std::size_t r0 = 0; r0 < n; r0 += B) {
    const std::size_t nb = std::min(B, n - r0);
    (dev_fm_chunk<C * CHUNK>(src + r0 * STRIDE, nb, r0, cols, std::make_index_sequence<CHUNK>{}), ...);
  }
}
static_assert(NDEV % CHUNK == 0);

// ------------------------------------------------------------------ naive interpreter
struct nfield {
  std::uint32_t bit_off;
  std::uint8_t width, col_bytes;
  kind k;
};
__attribute__((noinline)) void naive_decode(const std::byte* src, std::size_t n, std::size_t stride,
                                            const std::vector<nfield>& fs, void* const* cols) {
  for (std::size_t r = 0; r < n; ++r) {
    const std::byte* rec = src + r * stride;
    for (std::size_t f = 0; f < fs.size(); ++f) {
      const nfield& d = fs[f];
      std::uint64_t v = 0;
      const std::size_t byte = d.bit_off / 8;
      switch (d.width) {  // switch per field per record
        case 8: if (d.bit_off % 8 == 0) { v = ld<std::uint8_t>(rec + byte); break; } [[fallthrough]];
        case 16: if (d.width == 16 && d.bit_off % 8 == 0) { v = ld<std::uint16_t>(rec + byte); break; } [[fallthrough]];
        case 32: if (d.width == 32 && d.bit_off % 8 == 0) { v = ld<std::uint32_t>(rec + byte); break; } [[fallthrough]];
        case 64: if (d.width == 64 && d.bit_off % 8 == 0) { v = ld<std::uint64_t>(rec + byte); break; } [[fallthrough]];
        default: {
          const unsigned sh = d.bit_off % 8, span = (sh + d.width + 7) / 8;
          for (unsigned i = 0; i < span && i < 8; ++i) v |= std::uint64_t(std::uint8_t(rec[byte + i])) << (8 * i);
          v >>= sh;
          if (d.width < 64) v &= (std::uint64_t(1) << d.width) - 1;
          if (d.k == K_I && d.width < 64 && (v >> (d.width - 1)) & 1) v |= ~std::uint64_t(0) << d.width;
        }
      }
      if (d.k == K_BOOL) v = v != 0;
      std::byte* out = static_cast<std::byte*>(cols[f]) + r * d.col_bytes;
      switch (d.col_bytes) {
        case 1: { auto x = std::uint8_t(v); std::memcpy(out, &x, 1); break; }
        case 2: { auto x = std::uint16_t(v); std::memcpy(out, &x, 2); break; }
        case 4: { auto x = std::uint32_t(v); std::memcpy(out, &x, 4); break; }
        default: std::memcpy(out, &v, 8);
      }
    }
  }
}

// ------------------------------------------------------------------ harness
static double best_of(int reps, const std::function<void()>& f) {
  double best = 1e100;
  for (int i = 0; i < reps; ++i) {
    const auto t0 = std::chrono::steady_clock::now();
    f();
    const auto t1 = std::chrono::steady_clock::now();
    best = std::min(best, std::chrono::duration<double>(t1 - t0).count());
  }
  return best;
}

struct columns {
  std::vector<std::vector<std::uint64_t>> store;
  std::vector<void*> ptr;
  std::vector<lay::column_out> outs;
  columns(const lay::plan& p, const lay::selection& s, std::size_t n) {
    for (auto i : s.fields) {
      const std::size_t bytes = n * lay::storage_size(p.fields()[i].st);
      store.emplace_back((bytes + 7) / 8 + 1, 0);  // touch every page now, not in the timed loop
      ptr.push_back(store.back().data());
      outs.push_back({reinterpret_cast<std::byte*>(store.back().data()), bytes});
    }
  }
};

static std::string only;
static int reps = 7;

static void row(const char* layout, const char* what, double sec, std::size_t nrec, std::size_t stride,
                std::size_t nvalues, double ref = 0) {
  const double gb = double(nrec) * double(stride) / sec / 1e9;
  std::printf("%-8s %-32s %9.3f ms  %7.2f GB/s  %10.0f rec/s  %6.3f ns/value%s", layout, what, sec * 1e3, gb,
              double(nrec) / sec, sec * 1e9 / double(nrec * nvalues), "");
  if (ref > 0) std::printf("  %5.2fx static", sec / ref);
  std::printf("\n");
}

static bool want(const char* name) { return only.empty() || only == name; }

template <const auto& L>
static void run_layout(const char* tag, const std::string& desc_text, const char* raw, std::size_t nrec,
                       const char* proj) {
  constexpr std::size_t STRIDE = stride_v<L>;
  constexpr std::size_t NF = std::size(L);
  constexpr bool IS_DEV = std::is_same_v<std::remove_cvref_t<decltype(L)>, std::remove_cvref_t<decltype(DEV)>>;
  const auto tp0 = std::chrono::steady_clock::now();
  auto desc = lay::parse_description(desc_text);
  if (!desc) { std::printf("%s\n", desc.error().str().c_str()); std::exit(1); }
  auto plan = lay::plan::compile(*desc, raw);
  if (!plan) { std::printf("%s\n", plan.error().str().c_str()); std::exit(1); }
  const auto tp1 = std::chrono::steady_clock::now();
  if (plan->stride() != STRIDE) { std::printf("stride mismatch %zu vs %zu\n", plan->stride(), STRIDE); std::exit(1); }
  if (only.empty())
    std::printf("\n== %s: %zu fields, %zu-byte records, %zu records (%.1f MB); description %.1f KB parsed+compiled in %.2f ms\n",
                tag, NF, STRIDE, nrec, double(nrec * STRIDE) / 1e6, double(desc_text.size()) / 1e3,
                std::chrono::duration<double>(tp1 - tp0).count() * 1e3);

  std::vector<std::byte> data(nrec * STRIDE);
  std::uint64_t s = 42;
  for (std::size_t i = 0; i < data.size(); i += 8) {
    s = s * 6364136223846793005ull + 1;
    const std::uint64_t v = s >> 11;
    std::memcpy(data.data() + i, &v, std::min<std::size_t>(8, data.size() - i));
  }
  const auto all = plan->all();
  columns ref_cols(*plan, all, nrec), cols(*plan, all, nrec);
  const int R = reps;

  double t_static = 0;
  {
    double a = 0, b = 0;
    if (want("static_rm")) {
      if constexpr (IS_DEV)
        a = best_of(R, [&] { dev_static_record_major(data.data(), nrec, ref_cols.ptr.data(), std::make_index_sequence<NDEV / CHUNK>{}); });
      else
        a = best_of(R, [&] { static_record_major<L>(data.data(), nrec, ref_cols.ptr.data(), std::make_index_sequence<NF>{}); });
    }
    if (want("static_fm")) {
      if constexpr (IS_DEV)
        b = best_of(R, [&] { dev_static_field_major(data.data(), nrec, ref_cols.ptr.data(), std::make_index_sequence<NDEV / CHUNK>{}); });
      else
        b = best_of(R, [&] { static_field_major<L>(data.data(), nrec, ref_cols.ptr.data(), std::make_index_sequence<NF>{}); });
    }
    if (only.empty()) {
      t_static = std::min(a, b);
      row(tag, "static decoder, record-major", a, nrec, STRIDE, NF);
      row(tag, "static decoder, field-major", b, nrec, STRIDE, NF);
    }
  }
  auto check = [&](const char* what) {
    if (!only.empty() || t_static == 0) return;
    for (std::size_t c = 0; c < NF; ++c)
      if (std::memcmp(ref_cols.ptr[c], cols.ptr[c], cols.outs[c].bytes) != 0) {
        std::printf("MISMATCH %s column %zu (%s)\n", what, c, plan->fields()[c].column.c_str());
        std::exit(1);
      }
  };
  if (want("naive")) {
    std::vector<nfield> nf;
    for (const spec& sp : L) nf.push_back({sp.bit_off, sp.width, std::uint8_t(col_size(sp)), sp.k});
    const double t = best_of(R, [&] { naive_decode(data.data(), nrec, STRIDE, nf, cols.ptr.data()); });
    check("naive");
    if (only.empty()) row(tag, "naive interpreter", t, nrec, STRIDE, NF, t_static);
  }
  lay::decoder dec(*plan, all);
  if (const char* bb = std::getenv("LAYOUT_BENCH_BLOCK_KB")) dec.block_bytes(std::size_t(std::atoi(bb)) << 10);
  for (auto [name, st, label] : {std::tuple{"field", lay::strategy::field_major, "nanom field-major"},
                                 std::tuple{"record", lay::strategy::record_major, "nanom record-major"},
                                 std::tuple{"auto", lay::strategy::automatic, "nanom automatic"}}) {
    if (!want(name)) continue;
    std::memset(cols.ptr[0], 0, cols.outs[0].bytes);
    const double t = best_of(R, [&, st = st] { dec.run_unchecked(data.data(), nrec, cols.outs, st); });
    check(label);
    if (only.empty()) row(tag, label, t, nrec, STRIDE, NF, t_static);
  }
  if (want("decode") && only.empty()) {  // library-owned table: includes allocation + first touch
    const double t = best_of(R, [&] { auto tb = lay::decode(*plan, data); if (!tb) std::exit(1); });
    row(tag, "nanom decode() (allocates)", t, nrec, STRIDE, NF, t_static);
  }
  if (want("projection")) {
    auto sel = plan->select({proj});
    if (!sel) { std::printf("%s\n", sel.error().str().c_str()); std::exit(1); }
    const lay::decoder pd(*plan, *sel);
    columns pc(*plan, *sel, nrec);
    const double t = best_of(R, [&] { pd.run_unchecked(data.data(), nrec, pc.outs); });
    if (only.empty()) {
      char what[96];
      std::snprintf(what, sizeof what, "nanom projection %zu/%zu fields", sel->fields.size(), NF);
      row(tag, what, t, nrec, STRIDE, sel->fields.size());
    }
  }
  if (want("jsonl")) {
    const std::size_t nj = std::max<std::size_t>(1, std::min<std::size_t>(nrec, IS_DEV ? 100 : 200000));
    const lay::jsonl_writer w(*plan);
    std::string out;
    out.reserve(std::size_t(1) << 26);
    const auto recs = plan->records(data);
    std::size_t bytes = 0;
    const double t = best_of(R, [&] {
      bytes = 0;
      for (std::size_t r = 0; r < nj; ++r) {
        w.write(out, recs[r]);
        if (out.size() > (std::size_t(1) << 24)) { bytes += out.size(); out.clear(); }
      }
      bytes += out.size();
      out.clear();
    });
    if (only.empty()) {
      row(tag, "nanom JSON Lines export", t, nj, STRIDE, NF);
      std::printf("%-8s %-32s %9s     %7.2f GB/s of JSON text (%.0f bytes/record)\n", tag, "", "",
                  double(bytes) / t / 1e9, double(bytes) / double(nj));
    }
  }
  if (want("memcpy") && only.empty()) {
    std::vector<std::byte> dst(data.size());
    const double t = best_of(R, [&] { std::memcpy(dst.data(), data.data(), data.size()); });
    row(tag, "memcpy of the input (bandwidth)", t, nrec, STRIDE, NF);
  }
}

int main(int argc, char** argv) {
  double scale = 1.0;
  int pos = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    if (a == "--only" && i + 1 < argc) only = argv[++i];
    else if (pos == 0) { scale = std::atof(argv[i]); ++pos; }
    else if (pos == 1) { reps = std::max(1, std::atoi(argv[i])); ++pos; }
  }
  std::string which = "both";
  if (const char* w = std::getenv("LAYOUT_BENCH_ONLY_LAYOUT")) which = w;
  const auto gfi_n = std::max<std::size_t>(16, std::size_t(4'000'000 * scale));
  const auto dev_n = std::max<std::size_t>(2, std::size_t(2000 * scale));
  if (which != "devices") run_layout<GFI>("gfi", describe_gfi(), "/dev/vdiZ/pacemaker/gfi.raw", gfi_n, "GFI[1].grab_index");
  if (which != "gfi") run_layout<DEV>("devices", describe_dev(), "/proc/app/devices.raw", dev_n,
                                     ("MEIO::IOAppDevices._dev" + std::to_string(NDEV / 200 + NDEV / 800)).c_str());
  return 0;
}
