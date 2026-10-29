#include "core/semantics/high_level_reconstruction.hpp"

#include <iomanip>
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

std::string hex_address(std::uint64_t value) {
  std::ostringstream stream;
  stream << std::hex << value;
  return stream.str();
}

// The evidence is the exact body the recognizer consumed. Writing it into the
// generated source keeps the claim checkable against the original image without
// re-running the analysis.
std::string describe_body(
    const std::vector<const discovery::DecodedInstruction*>& body) {
  std::ostringstream text;
  for (std::size_t index = 0; index < body.size(); ++index) {
    if (index != 0) text << "; ";
    text << "0x" << std::hex << body[index]->address << std::dec << " "
         << body[index]->text;
  }
  return text.str();
}

bool is_return(const discovery::DecodedInstruction& instruction) {
  return (instruction.mnemonic == "ret" || instruction.mnemonic == "retq") &&
         instruction.operands.empty();
}

}  // namespace

const char* source_class_name(SourceClass classification) {
  switch (classification) {
    case SourceClass::HighLevelVerified: return "high-level verified";
    case SourceClass::LowLevelFallback: return "low-level fallback";
    case SourceClass::Unresolved: return "unresolved";
    case SourceClass::PolicyOverride: return "policy override";
  }
  return "unknown";
}

double SourceCensus::high_level_percent() const {
  if (total_functions == 0) return 0.0;
  const double exact = 100.0 * static_cast<double>(high_level_verified) /
                       static_cast<double>(total_functions);
  if (high_level_verified != total_functions && exact > 99.99) return 99.99;
  return exact;
}

std::optional<HighLevelFunction> recognize_high_level(
    const discovery::RecoveredFunction& function) {
  std::vector<const discovery::DecodedInstruction*> body;
  for (const auto& [address, instruction] : function.instructions) {
    (void)address;
    if (!ignorable(instruction)) body.push_back(&instruction);
  }
  // Every accepted shape is a complete body: one operation followed by RET.
  // Anything larger stays in the machine-level fallback, because a partial
  // reading presented as a typed function would be an invented answer.
  if (body.size() != 2 || !is_return(*body[1])) return std::nullopt;

  const auto& operation = *body[0];
  if (operation.mnemonic != "mov" || operation.operands.size() != 2)
    return std::nullopt;

  const auto& destination = operation.operands[0];
  const auto& source = operation.operands[1];
  if (destination.kind != discovery::Operand::Kind::Register ||
      (destination.register_name != "eax" && destination.register_name != "rax"))
    return std::nullopt;

  HighLevelFunction result;
  result.address = function.entry;
  result.evidence = describe_body(body);

  if (source.kind == discovery::Operand::Kind::Immediate) {
    result.kind = HighLevelFunction::Kind::ConstantReturn;
    result.width_bytes = destination.register_name == "rax" ? 8 : 4;
    result.value = static_cast<std::uint64_t>(source.immediate_value);
    result.recognizer = "constant-return";
    return result;
  }

  // `mov eax, dword ptr [esp + 4]` is an identity on the cdecl first stack
  // argument. The operand must be exactly that slot: an index register, segment
  // override or different displacement would make "first argument" a claim the
  // body does not support.
  if (source.kind == discovery::Operand::Kind::Memory &&
      destination.register_name == "eax" && source.size_in_bytes == 4 &&
      source.base_register_name == "esp" && source.index_register_name.empty() &&
      source.segment_register_name.empty() && source.displacement == 4) {
    result.kind = HighLevelFunction::Kind::StackArgumentReturn;
    result.width_bytes = 4;
    result.recognizer = "stack-argument-return";
    return result;
  }

  // `mov eax, ecx` / `mov rax, rcx` returns the first integer argument as the
  // Windows x64, thiscall and fastcall conventions pass it. The body only
  // proves a register copy; the wrapper reproduces exactly that copy, so the
  // ABI interpretation can be wrong without making the translation wrong.
  if (source.kind == discovery::Operand::Kind::Register &&
      ((destination.register_name == "eax" && source.register_name == "ecx") ||
       (destination.register_name == "rax" && source.register_name == "rcx"))) {
    result.kind = HighLevelFunction::Kind::RegisterArgumentReturn;
    result.width_bytes = destination.register_name == "rax" ? 8 : 4;
    result.argument_register = source.register_name;
    result.recognizer = "register-argument-return";
    return result;
  }

  return std::nullopt;
}

std::string render_high_level(const HighLevelFunction& function,
                              const std::string& guest_name) {
  const auto type = integer_type(function.width_bytes);
  const auto address = hex_address(function.address);
  std::ostringstream output;
  output << "// Function 0x" << address << "\n"
         << "// Source classification: " << source_class_name(SourceClass::HighLevelVerified) << "\n"
         << "// Recognizer: " << function.recognizer << "\n"
         << "// Evidence: " << function.evidence << "\n"
         << "// Confidence: exact for the recorded body; every instruction is accounted "
            "for and none defines state beyond the return register.\n";

  switch (function.kind) {
    case HighLevelFunction::Kind::ConstantReturn:
      output << "static " << type << " high_level_" << address << "_constant() {\n"
             << "  return static_cast<" << type << ">(0x" << std::hex << function.value
             << std::dec << "ull);\n"
             << "}\n"
             << "static void " << guest_name << "(GuestContext* context) {\n"
             << "  context->registers[0] = static_cast<std::uint64_t>(high_level_"
             << address << "_constant());\n"
             << "  return_from_guest_function(context, 0);\n"
             << "  return;\n}\n";
      return output.str();

    case HighLevelFunction::Kind::StackArgumentReturn:
      output << "static std::uint32_t high_level_" << address
             << "_first_stack_argument(std::uint32_t first_argument) {\n"
             << "  return first_argument;\n"
             << "}\n"
             << "static void " << guest_name << "(GuestContext* context) {\n"
             << "  // cdecl first argument: [esp] is the return address on entry.\n"
             << "  const auto first_argument = static_cast<std::uint32_t>(load_guest_memory(\n"
             << "      context, mask_guest_address(context->registers[4] + 4), 4));\n"
             << "  context->registers[0] = static_cast<std::uint64_t>(high_level_" << address
             << "_first_stack_argument(first_argument));\n"
             << "  return_from_guest_function(context, 0);\n"
             << "  return;\n}\n";
      return output.str();

    case HighLevelFunction::Kind::RegisterArgumentReturn: {
      // register 1 is ECX/RCX in the guest register file.
      output << "static " << type << " high_level_" << address
             << "_first_register_argument(" << type << " first_argument) {\n"
             << "  return first_argument;\n"
             << "}\n"
             << "static void " << guest_name << "(GuestContext* context) {\n"
             << "  const auto first_argument = static_cast<" << type
             << ">(context->registers[1]);\n"
             << "  context->registers[0] = static_cast<std::uint64_t>(high_level_" << address
             << "_first_register_argument(first_argument));\n"
             << "  return_from_guest_function(context, 0);\n"
             << "  return;\n}\n";
      return output.str();
    }
  }
  return {};
}

}  // namespace recomp::semantics
