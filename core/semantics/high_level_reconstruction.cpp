#include "core/semantics/high_level_reconstruction.hpp"

#include <sstream>

namespace recomp::semantics {
namespace {

bool ignorable(const discovery::DecodedInstruction& instruction) {
  return instruction.mnemonic == "nop" || instruction.mnemonic == "endbr64" ||
         instruction.mnemonic == "endbr32";
}

std::string integer_type(int width) {
  return width == 8 ? "std::uint64_t" : "std::uint32_t";
}

}  // namespace

std::optional<ConstantReturnFunction> recognize_constant_return(
    const discovery::RecoveredFunction& function) {
  std::vector<const discovery::DecodedInstruction*> body;
  for (const auto& [address, instruction] : function.instructions) {
    (void)address;
    if (!ignorable(instruction)) body.push_back(&instruction);
  }
  if (body.size() != 2 ||
      (body.back()->mnemonic != "ret" && body.back()->mnemonic != "retq") ||
      !body.back()->operands.empty())
    return std::nullopt;

  const auto& move = *body.front();
  if (move.mnemonic == "mov" && move.operands.size() == 2 &&
      move.operands[0].kind == discovery::Operand::Kind::Register &&
      move.operands[1].kind == discovery::Operand::Kind::Immediate &&
      (move.operands[0].register_name == "eax" || move.operands[0].register_name == "rax")) {
    const int width = move.operands[0].register_name == "rax" ? 8 : 4;
    return ConstantReturnFunction{function.entry,
                                  static_cast<std::uint64_t>(move.operands[1].immediate_value), width};
  }
  return std::nullopt;
}

std::string render_constant_return(const ConstantReturnFunction& function,
                                   const std::string& guest_name) {
  std::ostringstream output;
  const auto type = integer_type(function.width_bytes);
  output << "// High-level reconstruction: exact constant-return leaf; provenance 0x"
         << std::hex << function.address << std::dec << "\n";
  output << "static " << type << " high_level_" << std::hex << function.address << std::dec
         << "() { return static_cast<" << type << ">(0x" << std::hex << function.value << std::dec
         << "ull); }\n";
  output << "static void " << guest_name << "(GuestContext* context) {\n"
         << "  context->registers[0] = high_level_" << std::hex << function.address << std::dec
         << "();\n"
         << "  return_from_guest_function(context, 0);\n"
         << "  return;\n}\n";
  return output.str();
}

std::optional<ArgumentReturnFunction> recognize_argument_return(
    const discovery::RecoveredFunction& function) {
  std::vector<const discovery::DecodedInstruction*> body;
  for (const auto& [address, instruction] : function.instructions) {
    (void)address;
    if (!ignorable(instruction)) body.push_back(&instruction);
  }
  if (body.size() != 2 ||
      (body.back()->mnemonic != "ret" && body.back()->mnemonic != "retq") ||
      !body.back()->operands.empty())
    return std::nullopt;

  const auto& move = *body.front();
  if (move.mnemonic != "mov" || move.operands.size() != 2) return std::nullopt;
  const auto& destination = move.operands[0];
  const auto& source = move.operands[1];
  if (destination.kind != discovery::Operand::Kind::Register ||
      (destination.register_name != "eax" && destination.register_name != "rax"))
    return std::nullopt;
  if (source.kind != discovery::Operand::Kind::Memory) return std::nullopt;
  // A bare `[esp+4]` or `[ebp+8]` -- one base register, no index. Anything more complex is a
  // different shape and stays in the fallback rather than being approximated.
  if (source.base_register_name.empty() || !source.index_register_name.empty()) return std::nullopt;
  const bool from_stack_pointer = source.base_register_name == "esp" || source.base_register_name == "rsp";
  const bool from_frame_pointer = source.base_register_name == "ebp" || source.base_register_name == "rbp";
  if (!from_stack_pointer && !from_frame_pointer) return std::nullopt;
  // The first argument sits at [esp+4] with no frame, and at [ebp+8] with one. Both are the
  // same number of bytes past the return address, and the recognizer uses the OFFSET rather
  // than assuming which prologue the compiler chose.
  const std::int64_t first_argument_offset = from_frame_pointer ? 8 : 4;
  if (source.displacement < first_argument_offset) return std::nullopt;
  const auto index = static_cast<std::uint32_t>((source.displacement - first_argument_offset) / 4);
  const int width = destination.register_name == "rax" ? 8 : 4;
  return ArgumentReturnFunction{function.entry, index, width};
}

std::string render_argument_return(const ArgumentReturnFunction& function,
                                   const std::string& guest_name) {
  std::ostringstream output;
  const auto type = integer_type(function.width_bytes);
  output << "// High-level reconstruction: returns stack argument " << function.argument_index
         << "; provenance 0x" << std::hex << function.address << std::dec
         << ". The argument's TYPE is not recovered, so it is a plain integer.\n";
  output << "static " << type << " high_level_" << std::hex << function.address << std::dec
         << "(const " << type << " arg" << function.argument_index << ") { return arg"
         << function.argument_index << "; }\n";
  // The caller reads the SAME stack slot the original did, so the readable function is fed
  // from the guest stack rather than from a value invented to make it compile.
  const auto offset = 4 + function.argument_index * 4;
  output << "static void " << guest_name << "(GuestContext* context) {\n"
         << "  context->registers[0] = high_level_" << std::hex << function.address << std::dec
         << "(static_cast<" << type << ">(load_guest_memory(context, context->registers[4] + "
         << std::dec << offset << ", " << function.width_bytes << ")));\n"
         << "  return_from_guest_function(context, 0);\n"
         << "  return;\n}\n";
  return output.str();
}

}  // namespace recomp::semantics
