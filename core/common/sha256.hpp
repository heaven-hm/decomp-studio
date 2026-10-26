#pragma once

#include <span>
#include <string>

namespace recomp::common {

std::string sha256(std::span<const unsigned char> data);

}  // namespace recomp::common
