#include "core/semantics/x86_64_lifter.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <optional>
#include <sstream>

namespace recomp::semantics {
namespace {

using discovery::DecodedInstruction;
using discovery::Operand;
using discovery::RecoveredFunction;

struct RegisterDescriptor {
  int index{};
  int width_in_bytes{};
  int high_byte_offset{};
};

const std::map<std::string, RegisterDescriptor>& register_descriptors() {
  static const std::map<std::string, RegisterDescriptor> descriptors = {
      {"rax", {0, 8, 0}}, {"rcx", {1, 8, 0}}, {"rdx", {2, 8, 0}}, {"rbx", {3, 8, 0}},
      {"rsp", {4, 8, 0}}, {"rbp", {5, 8, 0}}, {"rsi", {6, 8, 0}}, {"rdi", {7, 8, 0}},
      {"r8", {8, 8, 0}},  {"r9", {9, 8, 0}},  {"r10", {10, 8, 0}}, {"r11", {11, 8, 0}},
      {"r12", {12, 8, 0}}, {"r13", {13, 8, 0}}, {"r14", {14, 8, 0}}, {"r15", {15, 8, 0}},
      {"eax", {0, 4, 0}}, {"ecx", {1, 4, 0}}, {"edx", {2, 4, 0}}, {"ebx", {3, 4, 0}},
      {"esp", {4, 4, 0}}, {"ebp", {5, 4, 0}}, {"esi", {6, 4, 0}}, {"edi", {7, 4, 0}},
      {"r8d", {8, 4, 0}}, {"r9d", {9, 4, 0}}, {"r10d", {10, 4, 0}}, {"r11d", {11, 4, 0}},
      {"r12d", {12, 4, 0}}, {"r13d", {13, 4, 0}}, {"r14d", {14, 4, 0}}, {"r15d", {15, 4, 0}},
      {"ax", {0, 2, 0}}, {"cx", {1, 2, 0}}, {"dx", {2, 2, 0}}, {"bx", {3, 2, 0}},
      {"sp", {4, 2, 0}}, {"bp", {5, 2, 0}}, {"si", {6, 2, 0}}, {"di", {7, 2, 0}},
      {"r8w", {8, 2, 0}}, {"r9w", {9, 2, 0}}, {"r10w", {10, 2, 0}}, {"r11w", {11, 2, 0}},
      {"r12w", {12, 2, 0}}, {"r13w", {13, 2, 0}}, {"r14w", {14, 2, 0}}, {"r15w", {15, 2, 0}},
      {"al", {0, 1, 0}}, {"cl", {1, 1, 0}}, {"dl", {2, 1, 0}}, {"bl", {3, 1, 0}},
      {"spl", {4, 1, 0}}, {"bpl", {5, 1, 0}}, {"sil", {6, 1, 0}}, {"dil", {7, 1, 0}},
      {"r8b", {8, 1, 0}}, {"r9b", {9, 1, 0}}, {"r10b", {10, 1, 0}}, {"r11b", {11, 1, 0}},
      {"r12b", {12, 1, 0}}, {"r13b", {13, 1, 0}}, {"r14b", {14, 1, 0}}, {"r15b", {15, 1, 0}},
      {"ah", {0, 1, 8}}, {"ch", {1, 1, 8}}, {"dh", {2, 1, 8}}, {"bh", {3, 1, 8}},
  };
  return descriptors;
}

constexpr int kRegisterRax = 0;
constexpr int kRegisterRdx = 2;
constexpr int kRegisterRsp = 4;
constexpr int kRegisterRbp = 5;

const std::map<std::string, std::string>& condition_codes() {
  static const std::map<std::string, std::string> codes = {
      {"o", "ConditionCodeOverflow"},       {"no", "ConditionCodeNotOverflow"},
      {"b", "ConditionCodeBelow"},          {"c", "ConditionCodeBelow"},
      {"nae", "ConditionCodeBelow"},        {"ae", "ConditionCodeAboveOrEqual"},
      {"nb", "ConditionCodeAboveOrEqual"},  {"nc", "ConditionCodeAboveOrEqual"},
      {"e", "ConditionCodeEqual"},          {"z", "ConditionCodeEqual"},
      {"ne", "ConditionCodeNotEqual"},      {"nz", "ConditionCodeNotEqual"},
      {"be", "ConditionCodeBelowOrEqual"},  {"na", "ConditionCodeBelowOrEqual"},
      {"a", "ConditionCodeAbove"},          {"nbe", "ConditionCodeAbove"},
      {"s", "ConditionCodeSign"},           {"ns", "ConditionCodeNotSign"},
      {"p", "ConditionCodeParity"},         {"pe", "ConditionCodeParity"},
      {"np", "ConditionCodeNotParity"},     {"po", "ConditionCodeNotParity"},
      {"l", "ConditionCodeLess"},           {"nge", "ConditionCodeLess"},
      {"ge", "ConditionCodeGreaterOrEqual"},{"nl", "ConditionCodeGreaterOrEqual"},
      {"le", "ConditionCodeLessOrEqual"},   {"ng", "ConditionCodeLessOrEqual"},
      {"g", "ConditionCodeGreater"},        {"nle", "ConditionCodeGreater"},
  };
  return codes;
}

const std::map<std::string, std::string>& arithmetic_helpers() {
  static const std::map<std::string, std::string> helpers = {
      {"add", "add_with_flags"}, {"sub", "subtract_with_flags"},
      {"adc", "add_with_carry"}, {"sbb", "subtract_with_borrow"},
      {"and", "bitwise_and"},    {"or", "bitwise_or"}, {"xor", "bitwise_xor"},
  };
  return helpers;
}

const std::map<std::string, std::string>& shift_helpers() {
  static const std::map<std::string, std::string> helpers = {
      {"shl", "shift_left"},  {"sal", "shift_left"},  {"shr", "shift_right_logical"},
      {"sar", "shift_right_arithmetic"}, {"rol", "rotate_left"}, {"ror", "rotate_right"},
      {"rcl", "rotate_left_through_carry"}, {"rcr", "rotate_right_through_carry"},
  };
  return helpers;
}

const std::set<std::string> kConditionalBranches = {
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
    "jp", "jnp", "jl", "jge", "jle", "jg"};

const std::map<std::string, int>& string_operation_sizes() {
  static const std::map<std::string, int> sizes = {
      {"movsb", 1}, {"movsw", 2}, {"movsd", 4}, {"movsq", 8},
      {"stosb", 1}, {"stosw", 2}, {"stosd", 4}, {"stosq", 8},
      {"lodsb", 1}, {"lodsw", 2}, {"lodsd", 4}, {"lodsq", 8},
      {"scasb", 1}, {"scasw", 2}, {"scasd", 4}, {"scasq", 8},
      {"cmpsb", 1}, {"cmpsw", 2}, {"cmpsd", 4}, {"cmpsq", 8}};
  return sizes;
}

const std::map<std::string, std::string>& vector_bitwise_helpers() {
  static const std::map<std::string, std::string> helpers = {
      {"xorps", "vector_bitwise_xor"}, {"xorpd", "vector_bitwise_xor"}, {"pxor", "vector_bitwise_xor"},
      {"andps", "vector_bitwise_and"}, {"andpd", "vector_bitwise_and"}, {"pand", "vector_bitwise_and"},
      {"orps", "vector_bitwise_or"},   {"orpd", "vector_bitwise_or"},   {"por", "vector_bitwise_or"}};
  return helpers;
}

int vector_register_index(const std::string& name) {
  if (name.size() > 3 && name.compare(0, 3, "xmm") == 0) {
    try { return std::stoi(name.substr(3)); } catch (...) { return -1; }
  }
  return -1;
}

std::string format_hex(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << value << "ull";
  return stream.str();
}

std::string format_immediate(std::int64_t value, int width_in_bytes) {
  const auto mask = width_in_bytes >= 8 ? ~0ull : ((1ull << (width_in_bytes * 8)) - 1);
  return format_hex(static_cast<std::uint64_t>(value) & mask);
}

bool has_segment_prefix(const DecodedInstruction& instruction, std::uint8_t prefix) {
  for (std::size_t index = 0; index < instruction.size; ++index) {
    const auto byte = instruction.raw_bytes[index];
    if (byte == prefix) return true;
    if (byte == 0x66 || byte == 0x67 || byte == 0xf0 || byte == 0xf2 || byte == 0xf3 ||
        byte == 0x2e || byte == 0x36 || byte == 0x3e || byte == 0x26)
      continue;
    break;
  }
  return false;
}

}  // namespace

std::string X86_64Lifter::guest_function_name(std::uint64_t address) const {
  std::ostringstream stream;
  stream << "guest_function_" << std::hex << address;
  return stream.str();
}

std::string register_read_expression(const std::string& name) {
  const auto iterator = register_descriptors().find(name);
  if (iterator == register_descriptors().end()) return {};
  const auto& descriptor = iterator->second;
  if (descriptor.width_in_bytes == 8) return "context->registers[" + std::to_string(descriptor.index) + "]";
  if (descriptor.width_in_bytes == 4)
    return "static_cast<std::uint32_t>(context->registers[" + std::to_string(descriptor.index) + "])";
  if (descriptor.width_in_bytes == 2)
    return "static_cast<std::uint16_t>(context->registers[" + std::to_string(descriptor.index) + "])";
  if (descriptor.high_byte_offset != 0)
    return "static_cast<std::uint8_t>(context->registers[" + std::to_string(descriptor.index) + "] >> 8)";
  return "static_cast<std::uint8_t>(context->registers[" + std::to_string(descriptor.index) + "])";
}

std::string register_write_statement(const std::string& name, const std::string& value) {
  const auto iterator = register_descriptors().find(name);
  const auto& descriptor = iterator->second;
  const auto index = std::to_string(descriptor.index);
  if (descriptor.width_in_bytes == 8) return "context->registers[" + index + "] = (" + value + ");";
  if (descriptor.width_in_bytes == 4)
    return "context->registers[" + index + "] = static_cast<std::uint32_t>(" + value + ");";
  if (descriptor.width_in_bytes == 2)
    return "context->registers[" + index + "] = (context->registers[" + index +
           "] & ~0xffffull) | static_cast<std::uint16_t>(" + value + ");";
  if (descriptor.high_byte_offset != 0)
    return "context->registers[" + index + "] = (context->registers[" + index +
           "] & ~0xff00ull) | ((static_cast<std::uint64_t>(static_cast<std::uint8_t>(" + value + "))) << 8);";
  return "context->registers[" + index + "] = (context->registers[" + index +
         "] & ~0xffull) | static_cast<std::uint8_t>(" + value + ");";
}

std::string effective_address_expression(const DecodedInstruction& instruction, const Operand& operand) {
  if (operand.base_register_name == "rip") {
    const auto address = instruction.address + instruction.size + operand.displacement;
    return format_hex(static_cast<std::uint64_t>(address));
  }
  if (operand.base_register_name.empty() && operand.index_register_name.empty())
    return "mask_guest_address(" + format_hex(static_cast<std::uint64_t>(operand.displacement)) + ")";
  std::string expression;
  if (has_segment_prefix(instruction, 0x64)) {
    expression = "context->fs_base";
  } else if (has_segment_prefix(instruction, 0x65)) {
    expression = "context->gs_base";
  }
  const auto append = [&expression](const std::string& term) {
    expression += expression.empty() ? term : " + " + term;
  };
  if (!operand.base_register_name.empty()) append(register_read_expression(operand.base_register_name));
  if (!operand.index_register_name.empty()) {
    const auto index = register_read_expression(operand.index_register_name);
    append(operand.scale != 1 ? "(" + index + " * " + std::to_string(operand.scale) + ")" : index);
  }
  if (expression.empty()) expression = "0";
  if (operand.displacement != 0) {
    expression += operand.displacement < 0 ? " - " + std::to_string(-operand.displacement)
                                           : " + " + std::to_string(operand.displacement);
  }
  return "mask_guest_address(" + expression + ")";
}

std::string operand_read_expression(const DecodedInstruction& instruction, const Operand& operand,
                                    int width_in_bytes) {
  if (operand.kind == Operand::Kind::Register) return register_read_expression(operand.register_name);
  if (operand.kind == Operand::Kind::Immediate) return format_immediate(operand.immediate_value, width_in_bytes);
  return "load_guest_memory(context, " + effective_address_expression(instruction, operand) + ", " +
         std::to_string(width_in_bytes) + ")";
}

std::string operand_write_statement(const DecodedInstruction& instruction, const Operand& operand,
                                    const std::string& value, int width_in_bytes) {
  if (operand.kind == Operand::Kind::Register) return register_write_statement(operand.register_name, value);
  return "store_guest_memory(context, " + effective_address_expression(instruction, operand) + ", " + value +
         ", " + std::to_string(width_in_bytes) + ");";
}

int operand_width(const Operand& operand, int fallback) {
  return operand.size_in_bytes != 0 ? operand.size_in_bytes : fallback;
}

const binary::ImportedSymbol* import_for_instruction(const discovery::FunctionDiscovery& discovery,
                                                     const DecodedInstruction& instruction) {
  if (instruction.operands.empty()) return nullptr;
  const auto& operand = instruction.operands.front();
  if (operand.kind != Operand::Kind::Memory) return nullptr;
  std::uint64_t address = 0;
  if (operand.base_register_name == "rip") {
    address = instruction.address + instruction.size + operand.displacement;
  } else if (operand.base_register_name.empty() && operand.index_register_name.empty()) {
    address = static_cast<std::uint64_t>(operand.displacement);  // 32-bit absolute addressing
  } else {
    return nullptr;
  }
  if (address < discovery.image_base()) return nullptr;
  const auto slot_rva = static_cast<std::uint32_t>(address - discovery.image_base());
  return discovery.import_for_slot(slot_rva);
}

void X86_64Lifter::record_unsupported(const std::string& mnemonic, const DecodedInstruction& instruction) const {
  ++unsupported_mnemonics_[mnemonic];
  throw LiftError("unsupported instruction '" + mnemonic + "' at " + format_hex(instruction.address));
}

void X86_64Lifter::emit_instruction(const DecodedInstruction& instruction, const RecoveredFunction& function,
                                    std::string& output) const {
  std::string mnemonic = instruction.mnemonic;
  int repeat_prefix = 0;
  if (mnemonic.compare(0, 4, "rep ") == 0) { mnemonic = mnemonic.substr(4); repeat_prefix = 1; }
  else if (mnemonic.compare(0, 5, "repe ") == 0) { mnemonic = mnemonic.substr(5); repeat_prefix = 1; }
  else if (mnemonic.compare(0, 6, "repne ") == 0) { mnemonic = mnemonic.substr(6); repeat_prefix = 1; }
  if (mnemonic.compare(0, 5, "lock ") == 0) mnemonic = mnemonic.substr(5);
  const auto& operands = instruction.operands;
  const auto emit = [&output](const std::string& line) { output += "  " + line + "\n"; };

  const auto is_vector_register = [](const discovery::Operand& operand) {
    return operand.kind == discovery::Operand::Kind::Register &&
           vector_register_index(operand.register_name) >= 0;
  };
  const auto vector_index = [](const discovery::Operand& operand) {
    return vector_register_index(operand.register_name);
  };
  const auto emit_vector_move = [&](const discovery::Operand& destination, const discovery::Operand& source,
                                    int byte_count) {
    if (is_vector_register(destination) && source.kind == discovery::Operand::Kind::Memory) {
      emit("load_guest_vector(context, " + effective_address_expression(instruction, source) + ", " +
           std::to_string(vector_index(destination)) + ", " + std::to_string(byte_count) + ");");
    } else if (destination.kind == discovery::Operand::Kind::Memory && is_vector_register(source)) {
      emit("store_guest_vector(context, " + effective_address_expression(instruction, destination) + ", " +
           std::to_string(vector_index(source)) + ", " + std::to_string(byte_count) + ");");
    } else if (is_vector_register(destination) && is_vector_register(source)) {
      emit("std::memcpy(context->vector_registers[" + std::to_string(vector_index(destination)) +
           "], context->vector_registers[" + std::to_string(vector_index(source)) + "], 16);");
    } else {
      throw LiftError("unsupported vector move at " + format_hex(instruction.address));
    }
  };

  if (string_operation_sizes().count(mnemonic) != 0 &&
      !((mnemonic == "movsd" || mnemonic == "cmpsd") && !operands.empty() && is_vector_register(operands[0]))) {
    const auto byte_count = string_operation_sizes().at(mnemonic);
    const auto helper = mnemonic.substr(0, 4) == "movs" ? "string_move"
                        : mnemonic.substr(0, 4) == "stos" ? "string_store"
                        : mnemonic.substr(0, 4) == "lods" ? "string_load"
                        : mnemonic.substr(0, 4) == "scas" ? "string_scan"
                                                          : "string_compare";
    emit(std::string(helper) + "(context, " + std::to_string(byte_count) + ", " +
         std::to_string(repeat_prefix) + ");");
    return;
  }

  if ((mnemonic == "movaps" || mnemonic == "movups" || mnemonic == "movdqa" || mnemonic == "movdqu" ||
       mnemonic == "movapd" || mnemonic == "movupd") &&
      operands.size() == 2 && (is_vector_register(operands[0]) || is_vector_register(operands[1]))) {
    emit_vector_move(operands[0], operands[1], 16);
    return;
  }
  if ((mnemonic == "movss" || mnemonic == "movsd") && operands.size() == 2 &&
      (is_vector_register(operands[0]) || is_vector_register(operands[1]))) {
    emit_vector_move(operands[0], operands[1], mnemonic == "movss" ? 4 : 8);
    return;
  }
  if ((mnemonic == "movd" || mnemonic == "movq") && operands.size() == 2 &&
      (is_vector_register(operands[0]) || is_vector_register(operands[1]))) {
    const int byte_count = mnemonic == "movd" ? 4 : 8;
    if (is_vector_register(operands[0])) {
      const auto value = operands[1].kind == discovery::Operand::Kind::Memory
          ? "load_guest_memory(context, " + effective_address_expression(instruction, operands[1]) + ", " +
                std::to_string(byte_count) + ")"
          : operand_read_expression(instruction, operands[1], byte_count);
      emit("vector_set_low(context, " + std::to_string(vector_index(operands[0])) + ", " + value + ", " +
           std::to_string(byte_count) + ");");
    } else {
      emit(operand_write_statement(instruction, operands[0],
           "vector_get_low(context, " + std::to_string(vector_index(operands[1])) + ", " +
               std::to_string(byte_count) + ")", byte_count));
    }
    return;
  }
  if (vector_bitwise_helpers().count(mnemonic) != 0 && operands.size() == 2 && is_vector_register(operands[0])) {
    const auto helper = vector_bitwise_helpers().at(mnemonic);
    if (is_vector_register(operands[1])) {
      emit(helper + "(context, " + std::to_string(vector_index(operands[0])) + ", " +
           std::to_string(vector_index(operands[1])) + ");");
    } else if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit(helper + "_memory(context, " + std::to_string(vector_index(operands[0])) + ", " +
           effective_address_expression(instruction, operands[1]) + ", 16);");
    }
    return;
  }
  if ((mnemonic == "paddd" || mnemonic == "psubd" || mnemonic == "pcmpeqd") && operands.size() == 2 &&
      is_vector_register(operands[0]) && is_vector_register(operands[1])) {
    const std::string helper = mnemonic == "paddd" ? "vector_add_dwords"
                               : mnemonic == "psubd" ? "vector_subtract_dwords"
                                                     : "vector_compare_equal_dwords";
    emit(helper + "(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ");");
    return;
  }
  if (mnemonic == "pshufd" && operands.size() == 3 && is_vector_register(operands[0]) &&
      is_vector_register(operands[1])) {
    emit("vector_shuffle_dwords(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ", " +
         std::to_string(operands[2].immediate_value & 0xff) + ");");
    return;
  }
  if ((mnemonic == "punpckldq" || mnemonic == "punpckhdq" || mnemonic == "punpcklqdq" ||
       mnemonic == "punpckhqdq") && operands.size() == 2 && is_vector_register(operands[0]) &&
      is_vector_register(operands[1])) {
    const auto high = mnemonic.find("h") != std::string::npos;
    const auto helper = (mnemonic.find("qdq") != std::string::npos) ? "vector_unpack_qwords"
                                                                    : "vector_unpack_dwords";
    emit(std::string(helper) + "(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ", " + (high ? "1" : "0") + ");");
    return;
  }

  if (mnemonic == "ldmxcsr") return;
  if (mnemonic == "stmxcsr") {
    if (!operands.empty() && operands[0].kind == discovery::Operand::Kind::Memory)
      emit("store_guest_memory(context, " + effective_address_expression(instruction, operands[0]) + ", 0x1f80ull, 4);");
    return;
  }
  if (mnemonic == "cpuid") { emit("execute_cpuid(context);"); return; }
  if (mnemonic == "prefetchnta" || mnemonic == "prefetcht0" || mnemonic == "prefetcht1" ||
      mnemonic == "prefetcht2" || mnemonic == "prefetchw")
    return;
  if ((mnemonic == "bt" || mnemonic == "bts" || mnemonic == "btr" || mnemonic == "btc") &&
      operands.size() == 2 && is_vector_register(operands[0]) == false &&
      operands[0].kind == discovery::Operand::Kind::Register) {
    const auto width = operand_width(operands[0], 8);
    const auto bits = std::to_string(width * 8);
    const auto value = operand_read_expression(instruction, operands[0], width);
    const auto index = operand_read_expression(instruction, operands[1], 8);
    std::string body = "{ const std::uint64_t bit = (" + index + ") % " + bits + "; const std::uint64_t original = " +
                       value + "; context->carry_flag = (original >> bit) & 1; ";
    if (mnemonic != "bt") {
      const std::string mask = mnemonic == "btc" ? "(1ull << bit)" : "(1ull << bit)";
      const auto updated = mnemonic == "bts" ? "(original | " + mask + ")"
                          : mnemonic == "btr" ? "(original & " + mask + ")"
                                              : "(original ^ " + mask + ")";
      body += operand_write_statement(instruction, operands[0], updated, width) + " }";
    } else {
      body += "}";
    }
    emit(body);
    return;
  }

  if (mnemonic == "nop" || mnemonic.rfind("nop", 0) == 0 || mnemonic == "endbr64" || mnemonic == "endbr32" ||
      mnemonic == "pause")
    return;

  if (mnemonic == "mov" || mnemonic == "movabs") {
    const auto width = operand_width(operands[0], 8);
    emit(operand_write_statement(instruction, operands[0], operand_read_expression(instruction, operands[1], width), width));
    return;
  }
  if (mnemonic == "movzx") {
    const auto destination_width = operand_width(operands[0], 8);
    const auto source_width = operand_width(operands[1], 1);
    const auto source = operand_read_expression(instruction, operands[1], source_width);
    const auto widened = source_width == 1
        ? "static_cast<std::uint64_t>(static_cast<std::uint8_t>(" + source + "))"
        : "static_cast<std::uint64_t>(static_cast<std::uint16_t>(" + source + "))";
    emit(operand_write_statement(instruction, operands[0], widened, destination_width));
    return;
  }
  if (mnemonic == "movsx" || mnemonic == "movsxd") {
    const auto destination_width = operand_width(operands[0], 8);
    const auto source_width = operand_width(operands[1], 4);
    const auto source = operand_read_expression(instruction, operands[1], source_width);
    const auto widened = source_width == 1
        ? "static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int8_t>(" + source + ")))"
        : source_width == 2
            ? "static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int16_t>(" + source + ")))"
            : "static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(" + source + ")))";
    emit(operand_write_statement(instruction, operands[0], widened, destination_width));
    return;
  }
  if (mnemonic == "lea") {
    const auto width = operand_width(operands[0], 8);
    emit(operand_write_statement(instruction, operands[0], effective_address_expression(instruction, operands[1]), width));
    return;
  }
  if (mnemonic == "xchg") {
    const auto width = operand_width(operands[0], 8);
    const auto first = operand_read_expression(instruction, operands[0], width);
    const auto second = operand_read_expression(instruction, operands[1], width);
    emit("{ const std::uint64_t temporary = " + first + "; " +
         operand_write_statement(instruction, operands[0], second, width) + " " +
         operand_write_statement(instruction, operands[1], "temporary", width) + " }");
    return;
  }

  if (arithmetic_helpers().count(mnemonic) != 0 && operands.size() == 2) {
    const auto width = operand_width(operands[1], 8);
    emit(operand_write_statement(
        instruction, operands[0],
        arithmetic_helpers().at(mnemonic) + "(context, " + operand_read_expression(instruction, operands[0], width) +
            ", " + operand_read_expression(instruction, operands[1], width) + ", " + std::to_string(width) + ")",
        width));
    return;
  }
  if (mnemonic == "cmp") {
    const auto width = operand_width(operands[0], 8);
    emit("compare_with_flags(context, " + operand_read_expression(instruction, operands[0], width) + ", " +
         operand_read_expression(instruction, operands[1], width) + ", " + std::to_string(width) + ");");
    return;
  }
  if (mnemonic == "test") {
    const auto width = operand_width(operands[0], 8);
    emit("test_with_flags(context, " + operand_read_expression(instruction, operands[0], width) + ", " +
         operand_read_expression(instruction, operands[1], width) + ", " + std::to_string(width) + ");");
    return;
  }
  if (mnemonic == "inc" || mnemonic == "dec" || mnemonic == "neg" || mnemonic == "not") {
    const auto width = operand_width(operands[0], 8);
    const std::string helper = mnemonic == "inc"   ? "increment_with_flags"
                               : mnemonic == "dec" ? "decrement_with_flags"
                               : mnemonic == "neg" ? "negate_with_flags"
                                                   : "bitwise_not";
    const auto call = mnemonic == "not"
        ? helper + "(" + operand_read_expression(instruction, operands[0], width) + ", " + std::to_string(width) + ")"
        : helper + "(context, " + operand_read_expression(instruction, operands[0], width) + ", " +
              std::to_string(width) + ")";
    emit(operand_write_statement(instruction, operands[0], call, width));
    return;
  }

  if ((mnemonic == "shrd" || mnemonic == "shld") && operands.size() == 3) {
    const auto width = operand_width(operands[0], 8);
    const std::string helper = mnemonic == "shrd" ? "shift_right_double" : "shift_left_double";
    emit(operand_write_statement(instruction, operands[0],
                                 helper + "(context, " + operand_read_expression(instruction, operands[0], width) +
                                     ", " + operand_read_expression(instruction, operands[1], width) + ", " +
                                     operand_read_expression(instruction, operands[2], 1) + ", " +
                                     std::to_string(width) + ")",
                                 width));
    return;
  }
  if (shift_helpers().count(mnemonic) != 0) {
    const auto width = operand_width(operands[0], 8);
    const auto count = operands.size() > 1 ? operand_read_expression(instruction, operands[1], 1) : "1ull";
    emit(operand_write_statement(instruction, operands[0],
                                 shift_helpers().at(mnemonic) + "(context, " +
                                     operand_read_expression(instruction, operands[0], width) + ", " + count + ", " +
                                     std::to_string(width) + ")",
                                 width));
    return;
  }

  if (mnemonic == "imul") {
    if (operands.size() == 1) {
      const auto width = operand_width(operands[0], 8);
      emit("signed_multiply_single(context, " + operand_read_expression(instruction, operands[0], width) + ", " +
           std::to_string(width) + ");");
      return;
    }
    const auto width = operand_width(operands[0], 8);
    if (operands.size() == 2) {
      emit(operand_write_statement(instruction, operands[0],
                                   "signed_multiply_two(context, " +
                                       operand_read_expression(instruction, operands[0], width) + ", " +
                                       operand_read_expression(instruction, operands[1], width) + ", " +
                                       std::to_string(width) + ")",
                                   width));
      return;
    }
    emit(operand_write_statement(instruction, operands[0],
                                 "signed_multiply_two(context, " +
                                     operand_read_expression(instruction, operands[1], width) + ", " +
                                     operand_read_expression(instruction, operands[2], width) + ", " +
                                     std::to_string(width) + ")",
                                 width));
    return;
  }
  if (mnemonic == "mul") {
    const auto width = operand_width(operands[0], 8);
    emit("unsigned_multiply_single(context, " + operand_read_expression(instruction, operands[0], width) + ", " +
         std::to_string(width) + ");");
    return;
  }
  if (mnemonic == "div" || mnemonic == "idiv") {
    const auto width = operand_width(operands[0], 8);
    emit((mnemonic == "div" ? "unsigned_divide(context, " : "signed_divide(context, ") +
         operand_read_expression(instruction, operands[0], width) + ", " + std::to_string(width) + ");");
    return;
  }
  if (mnemonic == "cdq") {
    emit("context->registers[" + std::to_string(kRegisterRdx) + "] = static_cast<std::uint64_t>(static_cast<std::uint32_t>(static_cast<std::int32_t>(context->registers[" + std::to_string(kRegisterRax) + "]) >> 31));");
    return;
  }
  if (mnemonic == "cqo") {
    emit("context->registers[" + std::to_string(kRegisterRdx) + "] = static_cast<std::uint64_t>(static_cast<std::int64_t>(context->registers[" + std::to_string(kRegisterRax) + "]) >> 63);");
    return;
  }
  if (mnemonic == "lahf") {
    emit("context->registers[0] = (context->registers[0] & ~0xff00ull) | ((static_cast<std::uint64_t>("
         "(context->sign_flag << 7) | (context->zero_flag << 6) | (context->auxiliary_flag << 4) | "
         "(context->parity_flag << 2) | 0x02u | context->carry_flag) << 8));");
    return;
  }
  if (mnemonic == "sahf") {
    emit("{ const std::uint64_t ah = (context->registers[0] >> 8) & 0xffull; "
         "context->sign_flag = (ah >> 7) & 1; context->zero_flag = (ah >> 6) & 1; "
         "context->auxiliary_flag = (ah >> 4) & 1; context->parity_flag = (ah >> 2) & 1; "
         "context->carry_flag = ah & 1; }");
    return;
  }
  if (mnemonic == "cwde") {
    emit("context->registers[" + std::to_string(kRegisterRax) + "] = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int16_t>(context->registers[" + std::to_string(kRegisterRax) + "])));");
    return;
  }
  if (mnemonic == "cdqe") {
    emit("context->registers[" + std::to_string(kRegisterRax) + "] = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(context->registers[" + std::to_string(kRegisterRax) + "])));");
    return;
  }

  if (mnemonic == "push") {
    if (operands[0].kind == Operand::Kind::Immediate) {
      const auto width = operand_width(operands[0], 4);
      emit("push_guest_stack(context, static_cast<std::uint64_t>(static_cast<std::int64_t>(" +
           format_immediate(operands[0].immediate_value, width) + ")));");
    } else {
      const auto width = operand_width(operands[0], 8);
      emit("push_guest_stack(context, " + operand_read_expression(instruction, operands[0], width) + ");");
    }
    return;
  }
  if (mnemonic == "pop") {
    const auto width = operand_width(operands[0], 8);
    const auto value = width >= 8 ? "pop_guest_stack(context)"
                                  : "static_cast<std::uint32_t>(pop_guest_stack(context))";
    emit(operand_write_statement(instruction, operands[0], value, width));
    return;
  }
  if (mnemonic == "leave") {
    emit("context->registers[" + std::to_string(kRegisterRsp) + "] = context->registers[" + std::to_string(kRegisterRbp) + "];");
    emit("context->registers[" + std::to_string(kRegisterRbp) + "] = pop_guest_stack(context);");
    return;
  }

  if (mnemonic.rfind("set", 0) == 0 && condition_codes().count(mnemonic.substr(3)) != 0) {
    emit(operand_write_statement(instruction, operands[0],
                                 "evaluate_condition(context, " + condition_codes().at(mnemonic.substr(3)) + ")",
                                 1));
    return;
  }
  if (mnemonic.rfind("cmov", 0) == 0 && condition_codes().count(mnemonic.substr(4)) != 0) {
    const auto width = operand_width(operands[0], 8);
    emit("if (evaluate_condition(context, " + condition_codes().at(mnemonic.substr(4)) + ")) " +
         operand_write_statement(instruction, operands[0], operand_read_expression(instruction, operands[1], width), width));
    return;
  }

  if (mnemonic == "call") {
    if (const auto* imported = import_for_instruction(discovery_, instruction); imported != nullptr) {
      emit("invoke_win32_import(context, \"" + imported->library_name + "\", \"" + imported->symbol_name +
           "\", " + format_hex(instruction.address + instruction.size) + ");");
      return;
    }
    const auto target = operands.empty() ? std::optional<std::uint64_t>{} : std::optional<std::uint64_t>{
        static_cast<std::uint64_t>(operands[0].immediate_value)};
    if (target && operands[0].kind == Operand::Kind::Immediate) {
      emit("push_guest_stack(context, " + format_hex(instruction.address + instruction.size) + ");");
      emit(guest_function_name(*target) + "(context);");
      return;
    }
    emit("invoke_guest_indirect(context, " +
         operand_read_expression(instruction, operands[0], operand_width(operands[0], 8)) + ", " +
         format_hex(instruction.address + instruction.size) + ");");
    return;
  }
  if (mnemonic == "jmp") {
    if (const auto* imported = import_for_instruction(discovery_, instruction); imported != nullptr) {
      emit("invoke_win32_import(context, \"" + imported->library_name + "\", \"" + imported->symbol_name +
           "\", " + format_hex(instruction.address + instruction.size) + ");");
      emit("return;");
      return;
    }
    if (!operands.empty() && operands[0].kind == Operand::Kind::Immediate) {
      const auto target = static_cast<std::uint64_t>(operands[0].immediate_value);
      if (function.tail_call_targets.count(target) != 0 || function.instructions.count(target) == 0) {
        emit(guest_function_name(target) + "(context);");
        emit("return;");
      } else {
        emit("goto label_" + std::to_string(target) + ";");
      }
      return;
    }
    emit("jump_guest_indirect(context, " +
         operand_read_expression(instruction, operands[0], operand_width(operands[0], 8)) + ");");
    emit("return;");
    return;
  }
  if (kConditionalBranches.count(mnemonic) != 0 && condition_codes().count(mnemonic.substr(1)) != 0) {
    const auto condition = condition_codes().at(mnemonic.substr(1));
    if (!operands.empty() && operands[0].kind == Operand::Kind::Immediate) {
      const auto target = static_cast<std::uint64_t>(operands[0].immediate_value);
      emit("if (evaluate_condition(context, " + condition + ")) goto label_" + std::to_string(target) + ";");
    } else {
      emit("if (evaluate_condition(context, " + condition + ")) { jump_guest_indirect(context, " +
           operand_read_expression(instruction, operands[0], 8) + "); return; }");
    }
    return;
  }
  if (mnemonic == "ret") {
    std::uint64_t adjustment = 8;
    if (!operands.empty() && operands[0].kind == Operand::Kind::Immediate)
      adjustment += static_cast<std::uint64_t>(operands[0].immediate_value);
    emit("return_from_guest_function(context, " + std::to_string(adjustment - 8) + ");");
    emit("return;");
    return;
  }
  if (mnemonic == "retf") {
    emit("return_from_guest_function(context, 8);");
    emit("return;");
    return;
  }
  if (mnemonic == "int3" || mnemonic == "hlt" || mnemonic == "ud2" || mnemonic == "ud1" || mnemonic == "ud0") {
    emit("recomp_trap(context, \"" + mnemonic + "\");");
    emit("return;");
    return;
  }

  if ((mnemonic == "vpxor" || mnemonic == "vandps" || mnemonic == "vpor") && operands.size() == 3 &&
      is_vector_register(operands[0])) {
    const std::string helper = mnemonic == "vpxor" ? "vector_bitwise_xor" : mnemonic == "vandps" ? "vector_bitwise_and" : "vector_bitwise_or";
    emit("std::memcpy(context->vector_registers[" + std::to_string(vector_index(operands[0])) + "], context->vector_registers[" +
         std::to_string(vector_index(operands[1])) + "], 16);");
    if (is_vector_register(operands[2])) {
      emit(helper + "(context, " + std::to_string(vector_index(operands[0])) + ", " + std::to_string(vector_index(operands[2])) + ");");
    } else if (operands[2].kind == discovery::Operand::Kind::Memory) {
      emit(helper + "_memory(context, " + std::to_string(vector_index(operands[0])) + ", " +
           effective_address_expression(instruction, operands[2]) + ", 16);");
    }
    return;
  }
  {
    static const std::map<std::string, std::string> double_helpers = {
        {"addsd", "vector_add_doubles"}, {"subsd", "vector_subtract_doubles"},
        {"mulsd", "vector_multiply_doubles"}, {"divsd", "vector_divide_doubles"}};
    static const std::map<std::string, std::string> float_helpers = {
        {"addss", "vector_add_floats"}, {"subss", "vector_subtract_floats"},
        {"mulss", "vector_multiply_floats"}, {"divss", "vector_divide_floats"}};
    const auto* helpers = double_helpers.count(mnemonic) != 0 ? &double_helpers
                         : float_helpers.count(mnemonic) != 0 ? &float_helpers
                                                             : nullptr;
    if (helpers != nullptr && operands.size() == 2 && is_vector_register(operands[0])) {
      if (is_vector_register(operands[1])) {
        emit(helpers->at(mnemonic) + "(context, " + std::to_string(vector_index(operands[0])) + ", " +
             std::to_string(vector_index(operands[1])) + ");");
      } else if (operands[1].kind == discovery::Operand::Kind::Memory) {
        emit(helpers->at(mnemonic) + "_memory(context, " + std::to_string(vector_index(operands[0])) + ", " +
             effective_address_expression(instruction, operands[1]) + ");");
      }
      return;
    }
  }
  if (mnemonic == "cvtsi2sd" && operands.size() == 2 && is_vector_register(operands[0])) {
    const auto source_width = operand_width(operands[1], 4);
    const auto source = operand_read_expression(instruction, operands[1], source_width);
    const auto signed_value = source_width == 8 ? "static_cast<std::int64_t>(" + source + ")"
                                                : "static_cast<std::int64_t>(static_cast<std::int32_t>(" + source + "))";
    emit("vector_set_double(context, " + std::to_string(vector_index(operands[0])) + ", static_cast<double>(" +
         signed_value + "));");
    return;
  }
  if (mnemonic == "cvttsd2si" && operands.size() == 2) {
    const auto width = operand_width(operands[0], 4);
    const auto source = operands[1].kind == discovery::Operand::Kind::Memory
        ? "load_guest_double(context, " + effective_address_expression(instruction, operands[1]) + ")"
        : "vector_get_double(context, " + std::to_string(vector_index(operands[1])) + ")";
    emit(operand_write_statement(instruction, operands[0],
         "static_cast<std::uint64_t>(static_cast<std::int64_t>(" + source + "))", width));
    return;
  }
  if (mnemonic == "cvtsd2ss" && operands.size() == 2 && is_vector_register(operands[0])) {
    emit("vector_set_float(context, " + std::to_string(vector_index(operands[0])) + ", static_cast<float>(vector_get_double(context, " +
         std::to_string(vector_index(operands[1])) + ")));");
    return;
  }
  if (mnemonic == "cvtss2sd" && operands.size() == 2 && is_vector_register(operands[0])) {
    emit("vector_set_double(context, " + std::to_string(vector_index(operands[0])) + ", static_cast<double>(vector_get_float(context, " +
         std::to_string(vector_index(operands[1])) + ")));");
    return;
  }
  if ((mnemonic == "bsr" || mnemonic == "bsf") && operands.size() == 2) {
    const auto width = operand_width(operands[0], 8);
    if (mnemonic == "bsr") {
      emit(operand_write_statement(instruction, operands[0],
           "bit_scan_reverse(context, " + operand_read_expression(instruction, operands[1], width) + ", " +
               std::to_string(width) + ")", width));
    } else {
      emit(operand_write_statement(instruction, operands[0],
           "bit_scan_forward(context, " + operand_read_expression(instruction, operands[1], width) + ", " +
               std::to_string(width) + ")", width));
    }
    return;
  }
  if ((mnemonic == "xadd" || mnemonic == "cmpxchg") && operands.size() == 2) {
    const auto width = operand_width(operands[1], 8);
    const auto mask = width >= 8 ? std::string("~0ull") : format_hex((1ull << (width * 8)) - 1);
    const auto destination = operand_read_expression(instruction, operands[0], width);
    const auto source = operand_read_expression(instruction, operands[1], width);
    if (mnemonic == "xadd") {
      emit("{ const std::uint64_t source_value = " + source + "; const std::uint64_t original = " + destination +
           "; " + operand_write_statement(instruction, operands[0],
                   "add_with_flags(context, original, source_value, " + std::to_string(width) + ")", width) +
           " " + operand_write_statement(instruction, operands[1], "original", width) + " }");
    } else {
      emit("{ const std::uint64_t accumulator = context->registers[0] & " + mask + "; const std::uint64_t original = " +
           destination + "; compare_with_flags(context, accumulator, original, " + std::to_string(width) + "); "
           "if (context->zero_flag) { " +
           operand_write_statement(instruction, operands[0], source, width) +
           " } else { context->registers[0] = original & " + mask + "; } }");
    }
    return;
  }

  record_unsupported(mnemonic, instruction);
}

std::string X86_64Lifter::lift_function(const RecoveredFunction& function) const {
  std::string output;
  output += "static void " + guest_function_name(function.entry) + "(GuestContext* context) {\n";
  for (const auto& [address, instruction] : function.instructions) {
    if (function.block_starts.count(address) != 0) output += "label_" + std::to_string(address) + ":;\n";
    output += "  trace_instruction(context, " + format_hex(address) + "); // " + instruction.text + "\n";
    emit_instruction(instruction, function, output);
  }
  output += "  return;\n}\n";
  return output;
}

std::string X86_64Lifter::lift_all_functions(bool strict) const {
  std::string declarations;
  std::string definitions;
  for (const auto& [address, symbol] : native_overrides_) {
    (void)address;
    declarations += "extern \"C\" void " + symbol + "(GuestContext* context);\n";
  }
  if (!native_overrides_.empty()) declarations += "\n";
  for (const auto& [address, function] : discovery_.functions()) {
    declarations += "static void " + guest_function_name(address) + "(GuestContext* context);\n";
    if (native_overrides_.count(address) != 0) {
      definitions += "static void " + guest_function_name(address) + "(GuestContext* context) { " +
                     native_overrides_.at(address) + "(context); }\n\n";
      continue;
    }
    if (stubbed_functions_.count(address) != 0) {
      definitions += "static void " + guest_function_name(address) +
                     "(GuestContext* context) { context->registers[4] += 8; context->registers[0] = 0; return; }\n\n";
      continue;
    }
    try {
      definitions += lift_function(function);
      definitions += "\n";
    } catch (const LiftError&) {
      if (strict) throw;
      definitions += "static void " + guest_function_name(address) +
                     "(GuestContext* context) { recomp_unsupported(context, \"function failed to lift\"); }\n\n";
    }
  }
  return declarations + "\n" + definitions;
}

CoverageCensus X86_64Lifter::census() const {
  CoverageCensus result;
  std::map<std::string, UnsupportedInstructionClass> by_mnemonic;
  for (const auto& [function_entry, function] : discovery_.functions()) {
    for (const auto& [address, instruction] : function.instructions) {
      ++result.total_instructions;
      std::string scratch;
      try {
        emit_instruction(instruction, function, scratch);
        ++result.lifted_instructions;
      } catch (const LiftError& error) {
        // Classify this instruction and keep going: the point of the census is
        // the whole program, not the first failure.
        ++result.unsupported_instructions;
        auto& entry = by_mnemonic[instruction.mnemonic];
        if (entry.occurrences == 0) {
          entry.mnemonic = instruction.mnemonic;
          entry.first_address = address;
          entry.first_function_entry = function_entry;
          entry.reason = error.what();
        }
        ++entry.occurrences;
      }
    }
  }
  result.unsupported.reserve(by_mnemonic.size());
  for (auto& [mnemonic, entry] : by_mnemonic) {
    (void)mnemonic;
    result.unsupported.push_back(std::move(entry));
  }
  std::sort(result.unsupported.begin(), result.unsupported.end(),
            [](const UnsupportedInstructionClass& left, const UnsupportedInstructionClass& right) {
              if (left.occurrences != right.occurrences) return left.occurrences > right.occurrences;
              return left.mnemonic < right.mnemonic;
            });
  return result;
}

}  // namespace recomp::semantics
