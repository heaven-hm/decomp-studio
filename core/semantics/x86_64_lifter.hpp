#pragma once

#include "core/discovery/function_discovery.hpp"

#include <map>
#include <stdexcept>
#include <string>

namespace recomp::semantics {

class LiftError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class X86_64Lifter {
 public:
  explicit X86_64Lifter(const discovery::FunctionDiscovery& discovery) : discovery_(discovery) {}

  std::string lift_all_functions(bool strict) const;
  const std::map<std::string, int>& unsupported_mnemonics() const { return unsupported_mnemonics_; }

 private:
  std::string lift_function(const discovery::RecoveredFunction& function) const;
  void emit_instruction(const discovery::DecodedInstruction& instruction,
                        const discovery::RecoveredFunction& function, std::string& output) const;
  void record_unsupported(const std::string& mnemonic, const discovery::DecodedInstruction& instruction) const;
  std::string guest_function_name(std::uint64_t address) const;

  const discovery::FunctionDiscovery& discovery_;
  mutable std::map<std::string, int> unsupported_mnemonics_;
};

}  // namespace recomp::semantics
