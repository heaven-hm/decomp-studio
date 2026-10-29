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

// A function whose whole body RETURNS ONE OF ITS OWN STACK ARGUMENTS -- an accessor. It is
// the next shape after a constant because the body is still two instructions and the value
// still comes from a place the machine states rather than from a guess: `mov eax, [esp+4]`
// names the first argument, and the offset IS the argument index.
//
// The recognizer reads only the stack offset, so it cannot be wrong about which argument is
// meant. What it does NOT know is the argument's TYPE, which is why the emitted signature is
// a plain 32-bit integer and the provenance comment says so.
struct ArgumentReturnFunction {
  std::uint64_t address{};
  std::uint32_t argument_index{};
  int width_bytes{};
};

std::optional<ArgumentReturnFunction> recognize_argument_return(
    const discovery::RecoveredFunction& function);

std::string render_argument_return(const ArgumentReturnFunction& function,
                                   const std::string& guest_name);

}  // namespace recomp::semantics
