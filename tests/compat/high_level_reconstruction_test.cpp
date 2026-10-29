#include "core/semantics/high_level_reconstruction.hpp"

#include <cassert>
#include <string>

using recomp::discovery::DecodedInstruction;
using recomp::discovery::Operand;
using recomp::discovery::RecoveredFunction;
using recomp::semantics::HighLevelFunction;
using recomp::semantics::SourceClass;
using recomp::semantics::SourceCensus;

namespace {

DecodedInstruction instruction(std::uint64_t address, const char* mnemonic) {
  DecodedInstruction result;
  result.address = address;
  result.mnemonic = mnemonic;
  result.text = mnemonic;
  return result;
}

Operand reg(const char* name) {
  Operand operand;
  operand.kind = Operand::Kind::Register;
  operand.register_name = name;
  return operand;
}

Operand immediate(std::int64_t value) {
  Operand operand;
  operand.kind = Operand::Kind::Immediate;
  operand.immediate_value = value;
  return operand;
}

Operand memory(const char* base, int size, std::int64_t displacement) {
  Operand operand;
  operand.kind = Operand::Kind::Memory;
  operand.base_register_name = base;
  operand.size_in_bytes = size;
  operand.displacement = displacement;
  return operand;
}

RecoveredFunction function(std::uint64_t entry, DecodedInstruction first) {
  RecoveredFunction recovered;
  recovered.entry = entry;
  recovered.instructions.emplace(entry, first);
  recovered.instructions.emplace(entry + 5, instruction(entry + 5, "ret"));
  return recovered;
}

}  // namespace

int main() {
  // --- constant return: mov eax, 42; ret
  auto move = instruction(0x401000, "mov");
  move.operands = {reg("eax"), immediate(42)};
  const auto constant = recomp::semantics::recognize_high_level(function(0x401000, move));
  assert(constant.has_value());
  assert(constant->kind == HighLevelFunction::Kind::ConstantReturn);
  assert(constant->value == 42);
  assert(constant->width_bytes == 4);
  assert(constant->recognizer == "constant-return");
  assert(constant->evidence.find("0x401000 mov") != std::string::npos);

  const auto constant_source =
      recomp::semantics::render_high_level(*constant, "guest_function_401000");
  assert(constant_source.find("Source classification: high-level verified") != std::string::npos);
  assert(constant_source.find("Recognizer: constant-return") != std::string::npos);
  assert(constant_source.find("std::uint32_t") != std::string::npos);
  assert(constant_source.find("context->registers[0]") != std::string::npos);
  assert(constant_source.find("return_from_guest_function(context, 0)") != std::string::npos);

  // 64-bit destination widens the recovered type.
  auto wide = instruction(0x401010, "mov");
  wide.operands = {reg("rax"), immediate(-2)};
  const auto wide_constant = recomp::semantics::recognize_high_level(function(0x401010, wide));
  assert(wide_constant.has_value());
  assert(wide_constant->width_bytes == 8);
  assert(wide_constant->value == static_cast<std::uint64_t>(-2));

  // --- stack argument return: mov eax, dword ptr [esp + 4]; ret
  auto stack_load = instruction(0x401020, "mov");
  stack_load.operands = {reg("eax"), memory("esp", 4, 4)};
  const auto stack_argument = recomp::semantics::recognize_high_level(function(0x401020, stack_load));
  assert(stack_argument.has_value());
  assert(stack_argument->kind == HighLevelFunction::Kind::StackArgumentReturn);
  assert(stack_argument->recognizer == "stack-argument-return");
  const auto stack_source = recomp::semantics::render_high_level(*stack_argument, "guest_function_401020");
  assert(stack_source.find("first_stack_argument") != std::string::npos);
  assert(stack_source.find("context->registers[4] + 4") != std::string::npos);

  // A different displacement is a different argument slot, not this shape.
  auto wrong_slot = instruction(0x401030, "mov");
  wrong_slot.operands = {reg("eax"), memory("esp", 4, 8)};
  assert(!recomp::semantics::recognize_high_level(function(0x401030, wrong_slot)).has_value());

  // An index register makes "first argument" unsupported by the body.
  auto indexed = instruction(0x401040, "mov");
  auto indexed_memory = memory("esp", 4, 4);
  indexed_memory.index_register_name = "ebx";
  indexed.operands = {reg("eax"), indexed_memory};
  assert(!recomp::semantics::recognize_high_level(function(0x401040, indexed)).has_value());

  // Wrong width: a 2-byte load is not the 32-bit argument shape.
  auto narrow = instruction(0x401050, "mov");
  narrow.operands = {reg("eax"), memory("esp", 2, 4)};
  assert(!recomp::semantics::recognize_high_level(function(0x401050, narrow)).has_value());

  // --- register argument return: mov eax, ecx; ret
  auto register_copy = instruction(0x401060, "mov");
  register_copy.operands = {reg("eax"), reg("ecx")};
  const auto register_argument =
      recomp::semantics::recognize_high_level(function(0x401060, register_copy));
  assert(register_argument.has_value());
  assert(register_argument->kind == HighLevelFunction::Kind::RegisterArgumentReturn);
  assert(register_argument->argument_register == "ecx");
  assert(register_argument->width_bytes == 4);
  const auto register_source =
      recomp::semantics::render_high_level(*register_argument, "guest_function_401060");
  assert(register_source.find("first_register_argument") != std::string::npos);
  assert(register_source.find("context->registers[1]") != std::string::npos);

  auto wide_copy = instruction(0x401070, "mov");
  wide_copy.operands = {reg("rax"), reg("rcx")};
  const auto wide_argument = recomp::semantics::recognize_high_level(function(0x401070, wide_copy));
  assert(wide_argument.has_value());
  assert(wide_argument->width_bytes == 8);

  // A copy between registers that is not the first-argument pair stays fallback.
  auto other_copy = instruction(0x401080, "mov");
  other_copy.operands = {reg("eax"), reg("edx")};
  assert(!recomp::semantics::recognize_high_level(function(0x401080, other_copy)).has_value());

  // --- whole-body rule: every instruction must be accounted for
  // A body with an extra operation is not this shape, even if the last mov
  // matches; a partial reading presented as a typed function would be invented.
  auto body = function(0x401090, move);
  body.instructions.emplace(0x401095, instruction(0x401095, "inc"));
  body.instructions.emplace(0x401096, instruction(0x401096, "ret"));
  assert(!recomp::semantics::recognize_high_level(body).has_value());

  // NOP padding is ignorable and does not change the classification.
  auto padded = function(0x4010a0, move);
  padded.instructions.emplace(0x4010a5, instruction(0x4010a5, "nop"));
  assert(recomp::semantics::recognize_high_level(padded).has_value());

  // A non-return terminator leaves the function unrecognized.
  RecoveredFunction unterminated;
  unterminated.entry = 0x4010b0;
  unterminated.instructions.emplace(0x4010b0, move);
  unterminated.instructions.emplace(0x4010b5, instruction(0x4010b5, "jmp"));
  assert(!recomp::semantics::recognize_high_level(unterminated).has_value());

  // Wrong destination register: not a return value.
  auto edx_move = instruction(0x4010c0, "mov");
  edx_move.operands = {reg("edx"), immediate(1)};
  assert(!recomp::semantics::recognize_high_level(function(0x4010c0, edx_move)).has_value());

  // --- census arithmetic and naming
  SourceCensus census;
  census.total_functions = 4;
  census.high_level_verified = 1;
  census.low_level_fallback = 2;
  census.unresolved = 1;
  assert(census.high_level_percent() == 25.0);
  census.high_level_verified = 4;
  census.low_level_fallback = 0;
  census.unresolved = 0;
  assert(census.high_level_percent() == 100.0);
  census.high_level_verified = 3;
  census.low_level_fallback = 1;
  assert(census.high_level_percent() < 100.0);
  assert(SourceCensus{}.high_level_percent() == 0.0);

  assert(std::string{recomp::semantics::source_class_name(SourceClass::HighLevelVerified)} ==
         "high-level verified");
  assert(std::string{recomp::semantics::source_class_name(SourceClass::LowLevelFallback)} ==
         "low-level fallback");
  assert(std::string{recomp::semantics::source_class_name(SourceClass::Unresolved)} == "unresolved");
  assert(std::string{recomp::semantics::source_class_name(SourceClass::PolicyOverride)} ==
         "policy override");

  return 0;
}
