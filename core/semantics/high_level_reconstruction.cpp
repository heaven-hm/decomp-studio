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

}  // namespace recomp::semantics
