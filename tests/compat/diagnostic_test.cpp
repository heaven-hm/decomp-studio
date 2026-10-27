#include "core/common/diagnostic.hpp"

#include <string>

int main() {
  const std::string input{"nul\0 esc\x1b del\x1f", 14};
  const auto encoded = recomp::common::quote_json(input);
  return encoded == "\"nul\\u0000 esc\\u001b del\\u001f\"" ? 0 : 1;
}
