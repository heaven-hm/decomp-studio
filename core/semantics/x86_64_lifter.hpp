#pragma once

#include "core/discovery/function_discovery.hpp"

#include <cstdint>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace recomp::semantics {

class LiftError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// One unsupported instruction class, aggregated over the whole recovered program.
struct UnsupportedInstructionClass {
  std::string mnemonic;
  std::uint64_t occurrences{};
  std::uint64_t first_address{};
  std::uint64_t first_function_entry{};
  std::string reason;  // lifter diagnostic for the first occurrence
};

// Result of a non-aborting walk over every recovered instruction. Translation
// stops at the first unsupported instruction, so a real binary reports a single
// line; the census classifies the whole program and yields an accurate,
// complete diagnostic that also ranks the work still to do.
struct CoverageCensus {
  std::uint64_t total_instructions{};
  std::uint64_t lifted_instructions{};
  std::uint64_t unsupported_instructions{};
  std::vector<UnsupportedInstructionClass> unsupported;  // most frequent first

  double coverage_percent() const {
    if (total_instructions == 0) return 100.0;
    return 100.0 * static_cast<double>(lifted_instructions) / static_cast<double>(total_instructions);
  }
};

class X86_64Lifter {
 public:
  explicit X86_64Lifter(const discovery::FunctionDiscovery& discovery) : discovery_(discovery) {}

  // Config-driven overrides: stubbed guest functions emit a no-op, and native
  // overrides replace a guest function with a host-provided implementation.
  void configure_overrides(const std::vector<std::uint64_t>& stubbed_functions,
                           const std::map<std::uint64_t, std::string>& native_overrides) {
    for (const auto address : stubbed_functions) stubbed_functions_.insert(address);
    native_overrides_ = native_overrides;
  }

  std::string lift_all_functions(bool strict) const;
  const std::map<std::string, int>& unsupported_mnemonics() const { return unsupported_mnemonics_; }

  // Classify every recovered instruction without aborting, so that a program the
  // lifter cannot translate still produces a complete, accurate diagnostic.
  CoverageCensus census() const;

 private:
  std::string lift_function(const discovery::RecoveredFunction& function) const;
  void emit_instruction(const discovery::DecodedInstruction& instruction,
                        const discovery::RecoveredFunction& function, std::string& output) const;
  void record_unsupported(const std::string& mnemonic, const discovery::DecodedInstruction& instruction) const;
  std::string guest_function_name(std::uint64_t address) const;

  const discovery::FunctionDiscovery& discovery_;
  std::set<std::uint64_t> stubbed_functions_;
  std::map<std::uint64_t, std::string> native_overrides_;
  mutable std::map<std::string, int> unsupported_mnemonics_;
};

}  // namespace recomp::semantics
