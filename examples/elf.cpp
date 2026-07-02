// nanom example: ELF header + program headers.
// Shows: tag() magic, runtime endianness selection (the same structs parse
// big- and little-endian files — nom has no equivalent), strct<T>(endian),
// count(), absolute-offset seeking, and cut() for committed errors.
#include <nanom/nanom.hpp>

#include <cstdio>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t;
using u32 = std::uint32_t; using u64 = std::uint64_t;

// Plain integral fields take their endianness from strct<T>(order) at parse
// time — exactly what ELF needs, since EI_DATA in the ident block decides.
struct elf64_hdr {
  u16 type; u16 machine; u32 version;
  u64 entry; u64 phoff; u64 shoff;
  u32 flags;
  u16 ehsize; u16 phentsize; u16 phnum;
  u16 shentsize; u16 shnum; u16 shstrndx;
};
NANOM_DESCRIBE(elf64_hdr, type, machine, version, entry, phoff, shoff, flags,
               ehsize, phentsize, phnum, shentsize, shnum, shstrndx);

struct elf64_phdr {
  u32 type; u32 flags;
  u64 offset; u64 vaddr; u64 paddr;
  u64 filesz; u64 memsz; u64 align;
};
NANOM_DESCRIBE(elf64_phdr, type, flags, offset, vaddr, paddr, filesz, memsz, align);

struct elf_file {
  std::endian              order;
  elf64_hdr                hdr;
  std::vector<elf64_phdr>  phdrs;
};

nm::result<elf_file> parse_elf(nm::input whole) {
  // e_ident: magic, class (1=32/2=64), data (1=LE/2=BE), version, pad
  auto ident = nm::context("elf ident",
      nm::seq(nm::tag("\x7f" "ELF"), nm::u8, nm::u8, nm::u8, nm::take(9)))(whole);
  if (!ident) return nm::unexp(ident.error());
  auto [magic, cls, data, ver, pad] = ident->value;

  if (cls != 2) return nm::make_err(whole.advance(4), "ELFCLASS64 (this demo is 64-bit only)");
  const std::endian order = data == 2 ? std::endian::big : std::endian::little;

  // after the ident block, everything is in the file's declared byte order —
  // one parser handles both, cut() commits (a bad header is not an "alt" case)
  auto hdr = nm::context("elf header", nm::cut(nm::strct<elf64_hdr>(order)))(ident->rest);
  if (!hdr) return nm::unexp(hdr.error());

  // seek to phoff (absolute) and read phnum program headers
  const u64 phoff = hdr->value.phoff;
  if (phoff > whole.size()) return nm::make_err(whole, "phoff inside file");
  nm::input at_ph = whole.advance(std::size_t(phoff));
  auto phdrs = nm::context("program headers",
      nm::cut(nm::count(nm::strct<elf64_phdr>(order), hdr->value.phnum)))(at_ph);
  if (!phdrs) return nm::unexp(phdrs.error());

  return nm::done{elf_file{order, hdr->value, std::move(phdrs->value)}, phdrs->rest};
}

int main() {
  // minimal synthetic big-endian ELF64 with one PT_LOAD program header
  std::vector<u8> f(0x40 + 0x38, 0);
  const u8 ident[] = {0x7f, 'E', 'L', 'F', 2 /*64*/, 2 /*BE*/, 1, 0};
  std::copy(std::begin(ident), std::end(ident), f.begin());
  auto put16 = [&](std::size_t o, u16 v) { f[o] = u8(v >> 8); f[o + 1] = u8(v); };
  auto put64 = [&](std::size_t o, u64 v) {
    for (int i = 0; i < 8; ++i) f[o + std::size_t(i)] = u8(v >> (8 * (7 - i)));
  };
  put16(0x10, 2);        // e_type = EXEC
  put16(0x12, 0x14);     // e_machine = PPC
  put64(0x18, 0x10000);  // e_entry
  put64(0x20, 0x40);     // e_phoff
  put16(0x36, 0x38);     // e_phentsize
  put16(0x38, 1);        // e_phnum
  put64(0x40 + 0x00, 0x00000001'00000005ull);  // p_type=LOAD, p_flags=R+X (BE)
  put64(0x40 + 0x10, 0x10000);                 // p_vaddr

  nm::input in = nm::from(f.data(), f.size());
  auto r = parse_elf(in);
  if (!r) { std::puts(r.error().render(in).c_str()); return 1; }
  std::printf("%s-endian ELF64  entry=0x%llx  phnum=%u\n",
              r->value.order == std::endian::big ? "big" : "little",
              (unsigned long long)r->value.hdr.entry, r->value.hdr.phnum);
  for (const auto& ph : r->value.phdrs)
    std::printf("  phdr type=%u flags=%u vaddr=0x%llx\n", ph.type, ph.flags,
                (unsigned long long)ph.vaddr);

  // truncated file → localized failure inside "program headers"
  nm::input cut_in = nm::from(f.data(), 0x50);
  auto bad = parse_elf(cut_in);
  if (!bad) std::printf("--- expected failure demo ---\n%s\n",
                        bad.error().render(cut_in).c_str());
  return 0;
}
