#include "core/semantics/high_level_reconstruction.hpp"

#include <cassert>
#include <string>

using recomp::discovery::DecodedInstruction;
using recomp::discovery::Operand;
using recomp::discovery::RecoveredFunction;

namespace {

DecodedInstruction instruction(const char* mnemonic) {
  DecodedInstruction result;
  result.mnemonic = mnemonic;
  return result;
}

}  // namespace

int main() {
  RecoveredFunction leaf;
  leaf.entry = 0x401000;
  auto move = instruction("mov");
  Operand destination;
  destination.kind = Operand::Kind::Register;
  destination.register_name = "eax";
  Operand immediate;
  immediate.kind = Operand::Kind::Immediate;
  immediate.immediate_value = 42;
  move.operands = {destination, immediate};
  leaf.instructions.emplace(leaf.entry, move);
  leaf.instructions.emplace(leaf.entry + 5, instruction("retq"));

  const auto result = recomp::semantics::recognize_constant_return(leaf);
  assert(result.has_value());
  assert(result->value == 42);
  assert(result->width_bytes == 4);
  const auto source = recomp::semantics::render_constant_return(*result, "guest_function_401000");
  assert(source.find("High-level reconstruction") != std::string::npos);
  assert(source.find("std::uint32_t") != std::string::npos);
  assert(source.find("context->registers[0]") != std::string::npos);
  assert(source.find("return_from_guest_function(context, 0)") != std::string::npos);

  auto xor_instruction = instruction("xor");
  xor_instruction.operands = {destination, destination};
  leaf.instructions[leaf.entry] = xor_instruction;
  assert(!recomp::semantics::recognize_constant_return(leaf).has_value());
  leaf.instructions[leaf.entry] = move;

  leaf.instructions.emplace(leaf.entry + 6, instruction("nop"));
  assert(recomp::semantics::recognize_constant_return(leaf).has_value());

  leaf.instructions.emplace(leaf.entry + 7, instruction("inc"));
  assert(!recomp::semantics::recognize_constant_return(leaf).has_value());
  return 0;
}
