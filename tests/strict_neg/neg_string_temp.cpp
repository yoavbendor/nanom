// Negative compile test: parsing an owning std::string temporary would leave a
// dangling view; NANOM_STRICT deletes that overload. EXPECTED TO FAIL to
// compile; ctest marks it WILL_FAIL.
#include <nanom/nanom.hpp>
#include <string>
int main() {
  auto in = nanom::from(std::string("temporary"));  // deleted in strict
  (void)in;
}
