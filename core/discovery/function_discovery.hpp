#pragma once

#include "core/binary/pe.hpp"

#include <capstone/capstone.h>

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace recomp::discovery {

struct Operand {
  enum class Kind { Register, Immediate, Memory };

  Kind kind{Kind::Register};
  int size_in_bytes{};
  std::string register_name;
  std::int64_t immediate_value{};
  std::string segment_register_name;
  std::string base_register_name;
  std::string index_register_name;
  int scale{1};
  std::int64_t displacement{};
};

struct DecodedInstruction {
  std::uint64_t address{};
  std::size_t size{};
  std::string mnemonic;
  std::string text;
  std::vector<Operand> operands;
  std::array<std::uint8_t, 16> raw_bytes{};
};

struct RecoveredFunction {
  std::uint64_t entry{};
  std::map<std::uint64_t, DecodedInstruction> instructions;
  std::set<std::uint64_t> block_starts;
  std::set<std::uint64_t> tail_call_targets;
};

class FunctionDiscovery {
 public:
  explicit FunctionDiscovery(const binary::PortableExecutable& executable);

  void discover();
  DecodedInstruction decode(std::uint32_t rva) const;

  const binary::PortableExecutable& executable() const { return executable_; }
  std::uint64_t image_base() const { return executable_.image_base; }
  const std::map<std::uint64_t, RecoveredFunction>& functions() const { return functions_; }
  bool contains_code(std::uint32_t rva) const;
  const binary::ImportedSymbol* import_for_slot(std::uint32_t slot_rva) const;

 private:
  std::optional<std::uint64_t> direct_branch_target(const DecodedInstruction& instruction) const;

  const binary::PortableExecutable& executable_;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> executable_ranges_;
  std::map<std::uint32_t, const binary::ImportedSymbol*> import_slots_;
  std::map<std::uint64_t, RecoveredFunction> functions_;
  mutable csh capstone_handle_{};
};

}  // namespace recomp::discovery
