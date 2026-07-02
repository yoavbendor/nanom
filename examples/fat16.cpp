// nanom example: FAT16 boot sector + root directory entries.
// Shows: overlay<T>/view<T> zero-copy access with get<"name">(), le<> wire
// integers, lsb0 bit flags, fixed 32-byte records with many0 + verify
// filters, and CSV/JSON debug dumps of parsed rows.
#include <nanom/nanom.hpp>

#include <cstdio>
#include <cstring>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t; using u32 = std::uint32_t;

// Boot sector (BPB). Everything is little-endian and byte-packed on disk —
// note the misaligned u16s at odd offsets that a raw C struct cast would
// break on: le<> fields have alignment 1, so the layout just works.
struct fat16_bpb {
  std::array<u8, 3> jmp;
  std::array<u8, 8> oem;
  nm::le<u16>       bytes_per_sector;
  u8                sectors_per_cluster;
  nm::le<u16>       reserved_sectors;
  u8                num_fats;
  nm::le<u16>       root_entries;
  nm::le<u16>       total_sectors16;
  u8                media;
  nm::le<u16>       fat_size16;
  nm::le<u16>       sectors_per_track;
  nm::le<u16>       num_heads;
  nm::le<u32>       hidden_sectors;
  nm::le<u32>       total_sectors32;
};
NANOM_DESCRIBE(fat16_bpb, jmp, oem, bytes_per_sector, sectors_per_cluster,
               reserved_sectors, num_fats, root_entries, total_sectors16,
               media, fat_size16, sectors_per_track, num_heads, hidden_sectors,
               total_sectors32);

// 8.3 directory entry. The attribute byte is a little-endian bit field —
// bit 0 = read-only … bit 5 = archive, so lsb0 order matches the spec text.
struct fat_dirent {
  std::array<u8, 8> name;
  std::array<u8, 3> ext;
  nm::ubits<1, nm::bit_order::lsb0> read_only;
  nm::ubits<1, nm::bit_order::lsb0> hidden;
  nm::ubits<1, nm::bit_order::lsb0> system;
  nm::ubits<1, nm::bit_order::lsb0> volume_id;
  nm::ubits<1, nm::bit_order::lsb0> directory;
  nm::ubits<1, nm::bit_order::lsb0> archive;
  nm::ubits<2, nm::bit_order::lsb0> attr_rsvd;
  u8                                nt_rsvd;
  u8                                ctime_tenths;
  nm::le<u16>                       ctime;
  nm::le<u16>                       cdate;
  nm::le<u16>                       adate;
  nm::le<u16>                       cluster_hi;
  nm::le<u16>                       mtime;
  nm::le<u16>                       mdate;
  nm::le<u16>                       cluster_lo;
  nm::le<u32>                       size;
};
NANOM_DESCRIBE(fat_dirent, name, ext, read_only, hidden, system, volume_id,
               directory, archive, attr_rsvd, nt_rsvd, ctime_tenths, ctime,
               cdate, adate, cluster_hi, mtime, mdate, cluster_lo, size);
static_assert(nm::wire_size_v<fat_dirent> == 32);
static_assert(nm::wire_size_v<fat16_bpb> == 36);

int main() {
  // --- synthetic boot sector + 3 root entries -------------------------------
  std::vector<u8> disk(512 + 3 * 32, 0);
  const u8 bpb_bytes[] = {0xeb, 0x3c, 0x90, 'M','S','D','O','S','5','.','0',
                          0x00, 0x02,        // 512 bytes/sector
                          4,                 // sectors/cluster
                          0x01, 0x00,        // reserved
                          2,                 // FATs
                          0x00, 0x02,        // 512 root entries
                          0x00, 0x50,        // 20480 sectors
                          0xf8, 0x40, 0x00}; // media, fat_size=64
  std::memcpy(disk.data(), bpb_bytes, sizeof bpb_bytes);

  auto put_dirent = [&](std::size_t i, const char* n, const char* e, u8 attr, u32 sz) {
    u8* d = disk.data() + 512 + i * 32;
    std::memset(d, ' ', 11);
    std::memcpy(d, n, std::strlen(n));
    std::memcpy(d + 8, e, std::strlen(e));
    d[11] = attr;
    d[26] = 0x05;                                  // cluster_lo = 5
    d[28] = u8(sz); d[29] = u8(sz >> 8);
  };
  put_dirent(0, "README", "TXT", 0x01 | 0x20, 1234);  // read-only + archive
  put_dirent(1, "SRC", "", 0x10, 0);                  // directory
  disk[512 + 2 * 32] = 0x00;                          // end-of-directory marker

  nm::input in = nm::from(disk.data(), disk.size());

  // --- boot sector: zero-copy view, decode on access ------------------------
  auto boot = nm::context("boot sector", nm::overlay<fat16_bpb>())(in);
  if (!boot) { std::puts(boot.error().render(in).c_str()); return 1; }
  auto bpb = boot->value;
  std::printf("oem=%.*s  %u B/sector  %u sectors/cluster  %u root entries\n",
              8, reinterpret_cast<const char*>(bpb.get<"oem">().data()),
              unsigned(bpb.get<"bytes_per_sector">()),
              unsigned(bpb.get<"sectors_per_cluster">()),
              unsigned(bpb.get<"root_entries">()));

  // --- root directory: fixed records until the 0x00 end marker --------------
  nm::input root = in.advance(512);
  auto live = nm::verify(nm::strct<fat_dirent>(),
                         [](const fat_dirent& d) { return d.name[0] != 0x00; });
  auto ents = nm::many0(live)(root);
  if (!ents) { std::puts(ents.error().render(in).c_str()); return 1; }

  std::printf("%s\n", nm::csv_header<fat_dirent>().c_str());
  for (const auto& d : ents->value) {
    std::printf("%s\n", nm::csv_row(d).c_str());
    std::printf("  %.8s.%.3s  %s%s size=%u cluster=%u\n",
                d.name.data(), d.ext.data(),
                d.directory ? "<dir> " : "", d.read_only ? "<ro> " : "",
                u32(d.size), u16(d.cluster_lo));
  }

  // columnar dump of the directory table
  nm::soa<fat_dirent> table;
  for (const auto& d : ents->value) table.push(d);
  std::printf("soa: %zu rows x %zu columns; avro=%zu chars\n", table.rows(),
              table.columns().size(), nm::avro_schema<fat_dirent>().size());
  return 0;
}
