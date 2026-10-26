#pragma once

#include <string>

namespace recomp::common {

struct Diagnostic {
  std::string status;
  std::string message;
  int exit_code;
};

std::string to_json(const Diagnostic& diagnostic);
std::string quote_json(const std::string& value);

}  // namespace recomp::common
