#pragma once

#include "core/discovery/function_discovery.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace recomp::semantics {

// How one recovered function is represented in the delivered source. The
// distinction is the point of the hybrid model: low-level fallback is machine
// translation, not readable reconstruction, and an unresolved function has no
// working body at all.
enum class SourceClass {
  HighLevelVerified,  // typed reconstruction proven from the complete body
  LowLevelFallback,   // lifted machine statements against GuestContext
  Unresolved,         // the lifter cannot translate part of the body
  PolicyOverride,     // replaced by a configured stub or native host function
};

const char* source_class_name(SourceClass classification);

struct FunctionSourceRecord {
  std::uint64_t address{};
  SourceClass classification{SourceClass::LowLevelFallback};
  std::string recognizer;  // empty unless HighLevelVerified
  std::string evidence;    // instruction sequence, override source or blocker
  std::size_t instruction_count{};
  std::size_t byte_count{};
};

struct SourceCensus {
  std::size_t total_functions{};
  std::size_t high_level_verified{};
  std::size_t low_level_fallback{};
  std::size_t unresolved{};
  std::size_t policy_override{};

  // Reported to two decimal places; 100.0 means every function is verified
  // high-level source and anything short of that stays below it.
  double high_level_percent() const;
};

// A whole-body recognizer result. Every accepted form is flag-neutral and
// accounts for every instruction in the function, so the typed reconstruction
// is exact for the recovered body rather than an approximation of a larger one.
struct HighLevelFunction {
  enum class Kind {
    ConstantReturn,          // mov eax/rax, imm
    StackArgumentReturn,     // mov eax, dword ptr [esp + 4]
    RegisterArgumentReturn,  // mov eax/rax, ecx/rcx
  };

  std::uint64_t address{};
  Kind kind{Kind::ConstantReturn};
  std::uint64_t value{};
  int width_bytes{4};
  std::string argument_register;  // "ecx" or "rcx" for RegisterArgumentReturn
  std::string recognizer;
  std::string evidence;
};

std::optional<HighLevelFunction> recognize_high_level(
    const discovery::RecoveredFunction& function);

std::string render_high_level(const HighLevelFunction& function,
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
