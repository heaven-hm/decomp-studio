#pragma once

#include "core/discovery/analyze.hpp"

#include <string>
#include <vector>

namespace recomp::ir {

struct Operation { std::string opcode; unsigned width; unsigned source_rva; };
std::vector<Operation> lift(const discovery::Analysis& analysis);

}  // namespace recomp::ir
