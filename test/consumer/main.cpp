// Minimal downstream user: include both headers, parse something, use bulk.
#include <nanom/nanom.hpp>
#include <nanom/bulk.hpp>
#include <cstdio>
namespace nm = nanom;
struct rec { nm::be<std::uint16_t> a; nm::ubits<4> hi; nm::ubits<4> lo; };
NANOM_DESCRIBE(rec, a, hi, lo);
int main() {
  const unsigned char b[] = {0x12, 0x34, 0xAB};
  auto r = nm::strct<rec>()(nm::from(b, sizeof b));
  if (!r || std::uint16_t(r->value.a) != 0x1234 || r->value.hi != 0xA) return 1;
  nm::soa<rec> t; t.push(r->value);
  std::printf("consumer ok: a=%04x hi=%u cols=%zu\n",
              unsigned(std::uint16_t(r->value.a)), unsigned(r->value.hi), t.columns().size());
  return 0;
}
