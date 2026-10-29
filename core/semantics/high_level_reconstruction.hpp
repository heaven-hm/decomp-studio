#pragma once

#include "core/discovery/function_discovery.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace recomp::semantics {

// A deliberately narrow, evidence-backed reconstruction. The recognizer only
// accepts a function whose complete body is a constant return followed by RET;
// everything else remains in the machine-level fallback.
struct ConstantReturnFunction {
  std::uint64_t address{};
  std::uint64_t value{};
  int width_bytes{};
};

std::optional<ConstantReturnFunction> recognize_constant_return(
    const discovery::RecoveredFunction& function);

std::string render_constant_return(const ConstantReturnFunction& function,
                                   const std::string& guest_name);

}  // namespace recomp::semantics
