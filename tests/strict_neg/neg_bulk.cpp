// Negative compile test: including <nanom/bulk.hpp> under NANOM_STRICT must be a
// hard error (GPU/bulk raw-pointer scatter is outside the bounds-checked model).
// This TU is EXPECTED TO FAIL to compile; ctest marks it WILL_FAIL.
#include <nanom/bulk.hpp>
int main() {}
