#include "recomp_runtime.hpp"
#include <cstdio>
#include <cmath>
using namespace recomp;
int main() {
  struct Case { float value; std::uint16_t expected; const char* name; };
  // The half-precision encodings of these values are fixed by IEEE-754 and are the whole
  // point of checking: a conversion that is merely plausible gets the edge cases wrong.
  const Case cases[] = {
    {0.0f, 0x0000, "0"}, {-0.0f, 0x8000, "-0"}, {1.0f, 0x3c00, "1"}, {-1.0f, 0xbc00, "-1"},
    {2.0f, 0x4000, "2"}, {0.5f, 0x3800, "0.5"}, {65504.0f, 0x7bff, "max half"},
    {65520.0f, 0x7c00, "overflow -> inf"}, {-65520.0f, 0xfc00, "-overflow -> -inf"},
    {1e-8f, 0x0000, "underflow -> 0"}, {5.96e-8f, 0x0001, "smallest subnormal"},
    {std::numeric_limits<float>::infinity(), 0x7c00, "inf"},
    {-std::numeric_limits<float>::infinity(), 0xfc00, "-inf"},
  };
  int failures = 0;
  for (const auto& c : cases) {
    const auto got = float_to_half(c.value, HalfRounding::nearest_even);
    if (got != c.expected) {
      std::printf("FAIL %-22s got 0x%04x want 0x%04x\n", c.name, got, c.expected);
      ++failures;
    }
  }
  // NaN must stay a NaN rather than becoming an infinity, whatever the payload.
  const auto nan = float_to_half(std::numeric_limits<float>::quiet_NaN(), HalfRounding::nearest_even);
  if ((nan & 0x7c00u) != 0x7c00u || (nan & 0x03ffu) == 0) {
    std::printf("FAIL NaN became 0x%04x, which is not a NaN\n", nan); ++failures;
  }
  // Rounding modes must actually differ. 1.0009765625 is exactly one step above 1.0 in
  // half precision; halfway between 1.0 and the next value is the case that separates them.
  const float between = 1.0f + 1.0f / 2048.0f;
  const auto down = float_to_half(between, HalfRounding::down);
  const auto up = float_to_half(between, HalfRounding::up);
  if (down != 0x3c00 || up != 0x3c01) {
    std::printf("FAIL rounding modes: down 0x%04x (want 0x3c00), up 0x%04x (want 0x3c01)\n", down, up);
    ++failures;
  }
  if (failures == 0) std::printf("PASS: %zu half-precision conversions and 3 rounding checks\n",
                                 sizeof(cases) / sizeof(cases[0]));
  return failures == 0 ? 0 : 1;
}
