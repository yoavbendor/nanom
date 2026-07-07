// Negative compile test: the raw (pointer, length) from() entry is removed under
// NANOM_STRICT. Callers must pass a sized span/array/string_view. EXPECTED TO
// FAIL to compile; ctest marks it WILL_FAIL.
#include <nanom/nanom.hpp>
int main() {
  const char* p = "abcd";
  auto in = nanom::from(p, 4);  // no such overload in strict
  (void)in;
}
