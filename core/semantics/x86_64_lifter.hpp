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
