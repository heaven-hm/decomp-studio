#include "core/common/diagnostic.hpp"

#include <array>

namespace recomp::common {

std::string quote_json(const std::string& value) {
  std::string quoted{"\""};
  for (const char character : value) {
    switch (character) {
      case '\\': quoted += "\\\\"; break;
      case '\"': quoted += "\\\""; break;
      case '\n': quoted += "\\n"; break;
      case '\r': quoted += "\\r"; break;
      case '\t': quoted += "\\t"; break;
      default:
        if (static_cast<unsigned char>(character) < 0x20) {
          static constexpr std::array<char, 16> hex = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
          const auto byte = static_cast<unsigned char>(character);
          quoted += "\\u00";
          quoted.push_back(hex[byte >> 4]);
          quoted.push_back(hex[byte & 0x0f]);
        } else {
          quoted += character;
        }
        break;
    }
  }
  quoted += "\"";
  return quoted;
}

std::string to_json(const Diagnostic& diagnostic) {
  return "{\"status\":" + quote_json(diagnostic.status) +
         ",\"message\":" + quote_json(diagnostic.message) + "}";
}

}  // namespace recomp::common
