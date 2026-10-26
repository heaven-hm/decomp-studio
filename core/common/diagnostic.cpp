#include "core/common/diagnostic.hpp"

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
      default: quoted += character; break;
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
