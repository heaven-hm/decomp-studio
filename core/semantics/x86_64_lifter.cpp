#include "core/semantics/x86_64_lifter.hpp"

#include "core/ir/cpp_backend.hpp"

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
      {"andps", "vector_bitwise_and"}, {"andpd", "vector_bitwise_and"}, {"andnps", "vector_bitwise_and_not"},
      {"pand", "vector_bitwise_and"},
      {"orps", "vector_bitwise_or"},   {"orpd", "vector_bitwise_or"},   {"por", "vector_bitwise_or"}};
  return helpers;
}

int x87_operand_index(const std::string& name) {
  if (name == "st") return 0;
  if (name.size() > 4 && name.compare(0, 3, "st(") == 0) {
    try { return std::stoi(name.substr(3)); } catch (...) { return -1; }
  }
  return -1;
}

// VEX-encoded (AVX) instructions that perform, on 128-bit operands, exactly the
// operation their SSE form already implements. Capstone spells them with a
// leading 'v'. Mapping them lets the two-operand form reuse the SSE handling
// instead of duplicating it; the three-operand form is handled by copying the
// first source into the destination and then applying the same two-operand
// operation.
//
// Only mnemonics the lifter already implements appear here. A VEX instruction
// whose SSE form is unsupported is deliberately absent, so it still fails closed
// rather than being silently mistranslated.
const std::map<std::string, std::string>& vex_equivalents() {
  static const std::map<std::string, std::string> table = {
      // 128-bit moves. The non-temporal forms are the same store; the temporal
      // hint is a cache-policy detail with no effect on the result.
      {"vmovaps", "movaps"}, {"vmovups", "movups"}, {"vmovapd", "movapd"}, {"vmovupd", "movupd"},
      {"vmovdqa", "movdqa"}, {"vmovdqu", "movdqu"}, {"vmovntdq", "movdqa"}, {"vmovntpd", "movapd"},
      {"vmovss", "movss"},   {"vmovsd", "movsd"},   {"vmovd", "movd"},     {"vmovq", "movq"},
      // Bitwise.
      {"vpand", "pand"},     {"vpor", "por"},       {"vpxor", "pxor"},
      {"vpandn", "pandn"},
      // SSE2 packed integer.
      {"vpaddb", "paddb"},   {"vpaddw", "paddw"},   {"vpaddd", "paddd"},   {"vpaddq", "paddq"},
      {"vpsubb", "psubb"},   {"vpsubw", "psubw"},   {"vpsubd", "psubd"},   {"vpsubq", "psubq"},
      {"vpaddsb", "paddsb"}, {"vpaddusb", "paddusb"}, {"vpaddsw", "paddsw"}, {"vpaddusw", "paddusw"},
      {"vpsubsb", "psubsb"}, {"vpsubusb", "psubusb"}, {"vpsubsw", "psubsw"}, {"vpsubusw", "psubusw"},
      {"vpcmpeqb", "pcmpeqb"}, {"vpcmpeqw", "pcmpeqw"}, {"vpcmpeqd", "pcmpeqd"},
      {"vpcmpgtb", "pcmpgtb"}, {"vpcmpgtw", "pcmpgtw"}, {"vpcmpgtd", "pcmpgtd"},
      {"vpmullw", "pmullw"}, {"vpmulhw", "pmulhw"}, {"vpmulhuw", "pmulhuw"}, {"vpmuludq", "pmuludq"},
      {"vpmaddwd", "pmaddwd"}, {"vpsadbw", "psadbw"},
      {"vpsllw", "psllw"},   {"vpslld", "pslld"},   {"vpsllq", "psllq"},
      {"vpsrlw", "psrlw"},   {"vpsrld", "psrld"},   {"vpsrlq", "psrlq"},
      {"vpsraw", "psraw"},   {"vpsrad", "psrad"},
      {"vpsrldq", "psrldq"}, {"vpslldq", "pslldq"},
      {"vpunpcklbw", "punpcklbw"}, {"vpunpckhbw", "punpckhbw"},
      {"vpunpcklwd", "punpcklwd"}, {"vpunpckhwd", "punpckhwd"},
      {"vpacksswb", "packsswb"}, {"vpackuswb", "packuswb"}, {"vpackssdw", "packssdw"},
      {"vpshufb", "pshufb"}, {"vpshuflw", "pshuflw"}, {"vpshufhw", "pshufhw"},
      {"vpmovmskb", "pmovmskb"},
      {"vandps", "andps"},   {"vandpd", "andpd"},   {"vorps", "orps"},
      {"vorpd", "orpd"},     {"vxorps", "xorps"},   {"vxorpd", "xorpd"},
      // Scalar floating-point arithmetic.
      {"vaddsd", "addsd"},   {"vsubsd", "subsd"},   {"vmulsd", "mulsd"},   {"vdivsd", "divsd"},
      {"vaddss", "addss"},   {"vsubss", "subss"},   {"vmulss", "mulss"},   {"vdivss", "divss"},
      // Conversions.
      {"vcvtsi2sd", "cvtsi2sd"}, {"vcvtsi2ss", "cvtsi2ss"}, {"vcvttsd2si", "cvttsd2si"},
      {"vcvttss2si", "cvttss2si"}, {"vcvtsd2ss", "cvtsd2ss"}, {"vcvtss2sd", "cvtss2sd"},
      // PACKED arithmetic. The VEX encoding is a different opcode for the same
      // operation, so it maps onto the legacy implementation rather than needing its own:
      // `vaddps` computes exactly what `addps` computes. Without these entries every
      // packed operation in a modern build was refused even though the implementation
      // was sitting right there under the legacy name.
      {"vaddps", "addps"},   {"vsubps", "subps"},   {"vmulps", "mulps"},   {"vdivps", "divps"},
      {"vaddpd", "addpd"},   {"vsubpd", "subpd"},   {"vmulpd", "mulpd"},   {"vdivpd", "divpd"},
      // Square roots, in both widths.
      {"vsqrtss", "sqrtss"}, {"vsqrtsd", "sqrtsd"}, {"vsqrtps", "sqrtps"}, {"vsqrtpd", "sqrtpd"},
      // Min/max and the compare family.
      {"vminss", "minss"},   {"vmaxss", "maxss"},   {"vminsd", "minsd"},   {"vmaxsd", "maxsd"},
      {"vcmpeqss", "cmpeqss"}, {"vcmpltss", "cmpltss"}, {"vcmpless", "cmpless"},
      {"vcmpeqsd", "cmpeqsd"}, {"vcmpltsd", "cmpltsd"}, {"vcmplesd", "cmplesd"},
      // The ordered/unordered compares, which set EFLAGS rather than a mask.
      {"vcomiss", "comiss"}, {"vucomiss", "ucomiss"}, {"vcomisd", "comisd"}, {"vucomisd", "ucomisd"},
  };
  return table;
}

// SSE2 packed-integer operations, mapped to their runtime helpers. Each helper
// has a register and a memory form, generated together in the runtime so they
// cannot drift.
const std::map<std::string, std::string>& packed_integer_helpers() {
  static const std::map<std::string, std::string> helpers = {
      {"paddb", "vector_add_bytes"},      {"paddw", "vector_add_words"},
      {"paddd", "vector_add_dwords"},     {"paddq", "vector_add_qwords"},
      {"psubb", "vector_subtract_bytes"}, {"psubw", "vector_subtract_words"},
      {"psubd", "vector_subtract_dwords"}, {"psubq", "vector_subtract_qwords"},
      {"paddsb", "vector_add_saturated_signed_bytes"},
      {"paddusb", "vector_add_saturated_unsigned_bytes"},
      {"psubsb", "vector_subtract_saturated_signed_bytes"},
      {"psubusb", "vector_subtract_saturated_unsigned_bytes"},
      {"paddsw", "vector_add_saturated_signed_words"},
      {"paddusw", "vector_add_saturated_unsigned_words"},
      {"psubsw", "vector_subtract_saturated_signed_words"},
      {"psubusw", "vector_subtract_saturated_unsigned_words"},
      {"pcmpeqb", "vector_compare_equal_bytes"},
      {"pcmpeqw", "vector_compare_equal_words"},
      {"pcmpeqd", "vector_compare_equal_dwords"},
      {"pcmpgtb", "vector_compare_greater_signed_bytes"},
      {"pcmpgtw", "vector_compare_greater_signed_words"},
      {"pcmpgtd", "vector_compare_greater_signed_dwords"},
      {"pmullw", "vector_multiply_low_words"},
      {"pmulhw", "vector_multiply_high_words"},
      {"pmulhuw", "vector_multiply_high_unsigned_words"},
      {"pmuludq", "vector_multiply_unsigned_dwords"},
      {"pandn", "vector_bitwise_and_not"},
      {"pmaddwd", "vector_multiply_add_words"},
      {"psadbw", "vector_sum_absolute_differences"},
      // The register/memory form takes one count from the source operand's low
      // 64 bits, so it uses the by-source wrappers rather than an element-wise
      // shift.
      {"psllw", "vector_shift_left_words_by_source"},
      {"pslld", "vector_shift_left_dwords_by_source"},
      {"psllq", "vector_shift_left_qwords_by_source"},
      {"psrlw", "vector_shift_right_logical_words_by_source"},
      {"psrld", "vector_shift_right_logical_dwords_by_source"},
      {"psrlq", "vector_shift_right_logical_qwords_by_source"},
      {"psraw", "vector_shift_right_arithmetic_words_by_source"},
      {"psrad", "vector_shift_right_arithmetic_dwords_by_source"},
  };
  return helpers;
}

// The same operations whose second operand may also be an immediate count.
const std::map<std::string, std::string>& packed_immediate_helpers() {
  static const std::map<std::string, std::string> helpers = {
      {"psllw", "vector_shift_left_words_immediate"},
      {"pslld", "vector_shift_left_dwords_immediate"},
      {"psllq", "vector_shift_left_qwords_immediate"},
      {"psrlw", "vector_shift_right_logical_words_immediate"},
      {"psrld", "vector_shift_right_logical_dwords_immediate"},
      {"psrlq", "vector_shift_right_logical_qwords_immediate"},
      {"psraw", "vector_shift_right_arithmetic_words_immediate"},
      {"psrad", "vector_shift_right_arithmetic_dwords_immediate"},
  };
  return helpers;
}

int vector_register_index(const std::string& name) {
  if (name.size() > 3 && (name.compare(0, 3, "xmm") == 0 || name.compare(0, 3, "ymm") == 0)) {
    try { return std::stoi(name.substr(3)); } catch (...) { return -1; }
  }
  return -1;
}

// AVX widened the architectural vector registers to 256 bits. A ymm operand
// touches all 32 bytes; an xmm operand touches 16.
bool is_wide_vector_register(const std::string& name) {
  return name.size() > 3 && name.compare(0, 3, "ymm") == 0;
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

// Capstone prefixes a mnemonic with `lock `/`rep `/`repe `/`repne `. The lifter
// matches on the bare mnemonic and its diagnostics name the bare mnemonic, so
// classification has to use the same string: otherwise an unsupported
// `lock bts` would be reported under a class name the lifter's own reason calls
// `bts`, and the two would disagree for the same instruction.
struct ParsedMnemonic {
  std::string mnemonic;
  bool has_repeat_prefix{};
};

ParsedMnemonic parse_mnemonic(const std::string& raw) {
  ParsedMnemonic parsed{raw, false};
  // `repz`/`repnz` are the same prefixes as `repe`/`repne`; MSVC emits the
  // `repz ret` padding idiom, so both spellings have to reach the same handling.
  if (parsed.mnemonic.compare(0, 4, "rep ") == 0) {
    parsed.mnemonic = parsed.mnemonic.substr(4);
    parsed.has_repeat_prefix = true;
  } else if (parsed.mnemonic.compare(0, 5, "repe ") == 0 ||
             parsed.mnemonic.compare(0, 5, "repz ") == 0) {
    parsed.mnemonic = parsed.mnemonic.substr(5);
    parsed.has_repeat_prefix = true;
  } else if (parsed.mnemonic.compare(0, 6, "repne ") == 0 ||
             parsed.mnemonic.compare(0, 6, "repnz ") == 0) {
    parsed.mnemonic = parsed.mnemonic.substr(6);
    parsed.has_repeat_prefix = true;
  }
  if (parsed.mnemonic.compare(0, 5, "lock ") == 0) parsed.mnemonic = parsed.mnemonic.substr(5);
  // MPX `bnd` is a non-semantic bounds hint when MPX is disabled; ordinary
  // branches prefixed with it execute exactly like their unprefixed form.
  if (parsed.mnemonic.compare(0, 4, "bnd ") == 0) parsed.mnemonic = parsed.mnemonic.substr(4);
  return parsed;
}

}  // namespace

std::string X86_64Lifter::guest_function_name(std::uint64_t address) const {
  std::ostringstream stream;
  stream << "guest_function_" << std::hex << address;
  return stream.str();
}

// The segment registers a 32-bit guest can name. They are not in the general
// register file, and the guest model has no GDT, so a segment register reads as
// zero. That is not a guess: it was measured against the reference, which reports
// ds, es, ss and cs all as 0x0000 in 32-bit mode because it models no descriptor
// table either. A candidate that invented the real Windows selector 0x23 would
// diverge from the reference on every instruction that stored one.
bool is_segment_register(const std::string& name) {
  return name == "cs" || name == "ds" || name == "es" || name == "ss" || name == "fs" || name == "gs";
}

std::string register_read_expression(const std::string& name) {
  if (is_segment_register(name)) return "0ull";
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
  std::string expression;
  if (has_segment_prefix(instruction, 0x64)) {
    expression = "context->fs_base";
  } else if (has_segment_prefix(instruction, 0x65)) {
    expression = "context->gs_base";
  }
  // An absolute address still carries its segment base: `mov eax, fs:[4]` reads
  // fs_base + 4, not address 4. Taking this early return unconditionally dropped
  // the base, which turned every 32-bit TEB read into a read of the low page --
  // the single most common memory access a 32-bit Windows program makes.
  if (operand.base_register_name.empty() && operand.index_register_name.empty() && expression.empty())
    return "mask_guest_address(" + format_hex(static_cast<std::uint64_t>(operand.displacement)) + ")";
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

// Reading an operand must always produce an expression, and writing one must
// always produce a statement. Both used to return an empty string when they could
// not: a segment register has no entry in the general register file, so
// `mov word ptr [edi], ds` emitted `store_guest_memory(context, addr, , 2);` and
// the failure surfaced as a C++ syntax error in the generated code rather than as
// a lifter diagnostic naming the instruction. Failing here means the address and
// the instruction are both known when the message is written.
[[noreturn]] void fail_operand(const DecodedInstruction& instruction, const char* what,
                               const std::string& detail) {
  throw LiftError("cannot " + std::string(what) + " operand " + detail + " of instruction '" +
                  instruction.text + "' at " + format_hex(instruction.address));
}

std::string operand_read_expression(const DecodedInstruction& instruction, const Operand& operand,
                                    int width_in_bytes) {
  if (operand.kind == Operand::Kind::Register) {
    auto expression = register_read_expression(operand.register_name);
    if (expression.empty())
      fail_operand(instruction, "read", "'" + operand.register_name + "' (no general register with that name)");
    return expression;
  }
  if (operand.kind == Operand::Kind::Immediate) return format_immediate(operand.immediate_value, width_in_bytes);
  return "load_guest_memory(context, " + effective_address_expression(instruction, operand) + ", " +
         std::to_string(width_in_bytes) + ")";
}

std::string operand_write(ir::Function& output, const DecodedInstruction& instruction, const Operand& operand,
                          const std::string& value, int width_in_bytes);

std::string operand_write_statement(const DecodedInstruction& instruction, const Operand& operand,
                                    const std::string& value, int width_in_bytes) {
  if (operand.kind == Operand::Kind::Register) {
    // A write to a segment register TRAPS rather than refusing to translate, which is
    // what `push <segment>` already did. The guest has no descriptor table, so a
    // selector written here could not be read back correctly and a program using it
    // would be silently wrong -- but refusing the whole program for one instruction it
    // may never execute is the worse of the two diagnostics, and it was an
    // inconsistency: `push es` translated and `pop es` did not. The trap names the
    // instruction and the address if it is ever reached.
    if (is_segment_register(operand.register_name)) {
      return "recomp_trap(context, \"write to segment register " + operand.register_name + "\");";
    }
    auto statement = register_write_statement(operand.register_name, value);
    if (statement.empty())
      fail_operand(instruction, "write", "'" + operand.register_name + "' (no general register with that name)");
    return statement;
  }
  return "store_guest_memory(context, " + effective_address_expression(instruction, operand) + ", " + value +
         ", " + std::to_string(width_in_bytes) + ");";
}

std::string operand_write(ir::Function& output, const DecodedInstruction& instruction, const Operand& operand,
                          const std::string& value, int width_in_bytes) {
  const auto text = operand_write_statement(instruction, operand, value, width_in_bytes);
  ir::Statement statement;
  statement.address_of_instruction = instruction.address;
  if (operand.kind == Operand::Kind::Register) {
    // A segment register is not in the register file, so the lookup below would fail
    // the whole program on a statement operand_write_statement has ALREADY decided to
    // turn into a trap -- and the trap text was discarded. Keep it instead.
    if (is_segment_register(operand.register_name)) {
      statement.kind = ir::StatementKind::Verbatim;
      statement.expression = text;
      output.statements.push_back(statement);
      return text;
    }
    const auto iterator = register_descriptors().find(operand.register_name);
    if (iterator == register_descriptors().end())
      fail_operand(instruction, "write", "'" + operand.register_name + "'");
    statement.kind = ir::StatementKind::Assign;
    statement.destination_register = iterator->second.index;
    statement.destination_width = iterator->second.width_in_bytes;
    statement.destination_high_byte_offset = iterator->second.high_byte_offset;
    statement.expression = value;
  } else {
    statement.kind = ir::StatementKind::StoreMemory;
    statement.address = effective_address_expression(instruction, operand);
    statement.expression = value;
    statement.width = width_in_bytes;
  }
  output.statements.push_back(std::move(statement));
  return text;
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
                                    ir::Function& output) const {
  const auto parsed_mnemonic = parse_mnemonic(instruction.mnemonic);
  std::string mnemonic = parsed_mnemonic.mnemonic;
  const int repeat_prefix = parsed_mnemonic.has_repeat_prefix ? 1 : 0;
  const auto& operands = instruction.operands;
  const auto emit = [&output, &instruction](const std::string& line) {
    output.statements.push_back(ir::Statement::verbatim(line, instruction.address));
  };
  // Structured emitters. A statement built this way describes an effect on the
  // guest machine and lets the backend decide how to write it, which is what
  // makes a second backend possible. The C++ backend renders these to exactly the
  // text the verbatim form produced, so migrating a class of statement cannot
  // change the generated code.
  const auto emit_trap = [&output, &instruction](const std::string& what) {
    ir::Statement statement;
    statement.kind = ir::StatementKind::Trap;
    statement.text = what;
    statement.address_of_instruction = instruction.address;
    output.statements.push_back(std::move(statement));
  };
  const auto emit_return = [&output, &instruction] {
    ir::Statement statement;
    statement.kind = ir::StatementKind::Return;
    statement.address_of_instruction = instruction.address;
    output.statements.push_back(std::move(statement));
  };

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
      if (byte_count >= 32) {
        emit("load_guest_vector_256(context, " + effective_address_expression(instruction, source) + ", " +
             std::to_string(vector_index(destination)) + ");");
      } else {
        emit("load_guest_vector(context, " + effective_address_expression(instruction, source) + ", " +
             std::to_string(vector_index(destination)) + ", " + std::to_string(byte_count) + ");");
      }
    } else if (destination.kind == discovery::Operand::Kind::Memory && is_vector_register(source)) {
      if (byte_count >= 32) {
        emit("store_guest_vector_256(context, " + effective_address_expression(instruction, destination) + ", " +
             std::to_string(vector_index(source)) + ");");
      } else {
        emit("store_guest_vector(context, " + effective_address_expression(instruction, destination) + ", " +
             std::to_string(vector_index(source)) + ", " + std::to_string(byte_count) + ");");
      }
    } else if (is_vector_register(destination) && is_vector_register(source)) {
      // A register-to-register move narrower than 16 bytes is a *merge*: SSE
      // movsd copies the low 8 bytes and movss the low 4, leaving the rest of
      // the destination untouched. Copying 16 bytes unconditionally clobbered
      // that upper half, and it also broke the three-operand VEX form, whose
      // whole purpose is that the destination's upper half comes from src1 —
      // the src1 copy was immediately overwritten by this one.
      const auto copy_bytes = byte_count >= 32 ? 32 : byte_count;
      emit("std::memcpy(context->vector_registers[" + std::to_string(vector_index(destination)) +
           "], context->vector_registers[" + std::to_string(vector_index(source)) + "], " +
           std::to_string(copy_bytes) + ");");
    } else {
      throw LiftError("unsupported vector move at " + format_hex(instruction.address));
    }
  };

  // VEX (AVX) encodings. A two-operand VEX instruction is the SSE instruction
  // with the same operands, so the mnemonic is rewritten and the existing
  // handling is reused. A three-operand VEX instruction adds an explicit first
  // source: dst = op(src1, src2), which is dst = src1 followed by that same
  // two-operand operation. This matters for scalar forms, where the upper bits
  // of the destination must come from src1 rather than being left alone.
  if (!mnemonic.empty() && mnemonic[0] == 'v') {
    const auto& equivalents = vex_equivalents();
    const auto equivalent = equivalents.find(mnemonic);
    if (equivalent != equivalents.end()) {
      if (operands.size() == 2) {
        mnemonic = equivalent->second;
      } else if (operands.size() == 3 && is_vector_register(operands[0]) &&
                 is_vector_register(operands[1])) {
        // Copy as much of src1 as the destination register actually holds: a
        // hardcoded 16 left the upper half of a ymm destination stale.
        const auto destination_bytes =
            is_wide_vector_register(operands[0].register_name) ? 32 : 16;
        emit("std::memcpy(context->vector_registers[" + std::to_string(vector_index(operands[0])) +
             "], context->vector_registers[" + std::to_string(vector_index(operands[1])) + "], " +
             std::to_string(destination_bytes) + ");");
        auto two_operand = instruction;
        two_operand.mnemonic = equivalent->second;
        two_operand.operands = {operands[0], operands[2]};
        emit_instruction(two_operand, function, output);
        return;
      }
    }
  }

  // FMSUB has no two-operand SSE equivalent, so it must be handled before the
  // generic VEX rewrite path. Keep the scalar and packed forms on the same
  // fused helpers; a memory third operand is common in compiler-generated code.
  if (mnemonic.rfind("vfmsub", 0) == 0 && operands.size() == 3 &&
      is_vector_register(operands[0])) {
    const bool doubles = mnemonic.size() >= 2 && mnemonic.substr(mnemonic.size() - 2) == "pd";
    const bool scalar_double = mnemonic.size() >= 2 && mnemonic.substr(mnemonic.size() - 2) == "sd";
    const bool scalar_float = mnemonic.size() >= 2 && mnemonic.substr(mnemonic.size() - 2) == "ss";
    const bool packed_float = mnemonic.size() >= 2 && mnemonic.substr(mnemonic.size() - 2) == "ps";
    if (doubles || scalar_double || scalar_float || packed_float) {
      std::string digits;
      for (const auto& candidate : {std::string("132"), std::string("213"), std::string("231")}) {
        if (mnemonic.find(candidate) != std::string::npos) { digits = candidate; break; }
      }
      if (!digits.empty() && is_vector_register(operands[1])) {
        const auto helper = "vector_fmsub" + digits + (doubles || scalar_double ? "_doubles" : "_floats");
        const auto destination = std::to_string(vector_index(operands[0]));
        const auto source = std::to_string(vector_index(operands[1]));
        if (is_vector_register(operands[2])) {
          emit(helper + "(context, " + destination + ", " + source + ", " +
               std::to_string(vector_index(operands[2])) + ");");
          return;
        }
        if (operands[2].kind == discovery::Operand::Kind::Memory) {
          emit(helper + "_memory(context, " + destination + ", " + source + ", " +
               effective_address_expression(instruction, operands[2]) + ");");
          return;
        }
      }
    }
  }

  // SSE2 packed integer. These are element-wise over 128 bits; the runtime
  // generates a register and a memory form of each helper together. The shift
  // family additionally accepts an immediate count.
  if (operands.size() == 2 && is_vector_register(operands[0])) {
    const auto destination = std::to_string(vector_index(operands[0]));
    if (mnemonic == "unpcklps" || mnemonic == "unpckhps" || mnemonic == "unpcklpd" || mnemonic == "unpckhpd") {
      const int element_size = mnemonic.find("pd") != std::string::npos ? 8 : 4;
      const bool high = mnemonic.find('h') != std::string::npos;
      if (is_vector_register(operands[1])) {
        const auto helper = element_size == 8 ? "vector_unpack_qwords" : "vector_unpack_dwords";
        emit(std::string(helper) + "(context, " + destination + ", " +
             std::to_string(vector_index(operands[1])) + ", " + (high ? "1" : "0") + ");");
        return;
      }
      if (operands[1].kind == discovery::Operand::Kind::Memory) {
        emit("vector_unpack_memory(context, " + destination + ", " +
             effective_address_expression(instruction, operands[1]) + ", " + std::to_string(element_size) +
             ", " + (high ? "1" : "0") + ");");
        return;
      }
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory &&
        (mnemonic == "punpcklbw" || mnemonic == "punpckhbw" || mnemonic == "punpcklwd" ||
         mnemonic == "punpckhwd" || mnemonic == "punpckldq" || mnemonic == "punpckhdq" ||
         mnemonic == "punpcklqdq" || mnemonic == "punpckhqdq")) {
      const int element_size = mnemonic.find("qdq") != std::string::npos ? 8
                               : mnemonic.find("dq") != std::string::npos ? 4
                               : mnemonic.find("wd") != std::string::npos ? 2 : 1;
      const bool high = mnemonic.find('h') != std::string::npos;
      emit("vector_unpack_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ", " + std::to_string(element_size) +
           ", " + (high ? "1" : "0") + ");");
      return;
    }
    const auto& packed = packed_integer_helpers();
    const auto helper = packed.find(mnemonic);
    if (helper != packed.end()) {
      if (is_vector_register(operands[1])) {
        emit(helper->second + "(context, " + destination + ", " + std::to_string(vector_index(operands[1])) +
             ");");
        return;
      }
      if (operands[1].kind == discovery::Operand::Kind::Memory) {
        emit(helper->second + "_memory(context, " + destination + ", " +
             effective_address_expression(instruction, operands[1]) + ");");
        return;
      }
    }
    const auto& immediate = packed_immediate_helpers();
    const auto immediate_helper = immediate.find(mnemonic);
    if (immediate_helper != immediate.end() && operands[1].kind == discovery::Operand::Kind::Immediate) {
      emit(immediate_helper->second + "(context, " + destination + ", " +
           std::to_string(operands[1].immediate_value & 0xff) + ");");
      return;
    }
    if ((mnemonic == "psrldq" || mnemonic == "pslldq") &&
        operands[1].kind == discovery::Operand::Kind::Immediate) {
      emit(std::string(mnemonic == "psrldq" ? "vector_shift_right_bytes_immediate"
                                            : "vector_shift_left_bytes_immediate") +
           "(context, " + destination + ", " + std::to_string(operands[1].immediate_value & 0xff) + ");");
      return;
    }
    // unpcklps/unpckhps interleave dwords and unpcklpd/unpckhpd interleave
    // qwords, the same operation the punpck family performs at byte and word
    // granularity. The runtime already implements both, so this is a dispatch
    // entry rather than new semantics.
    if ((mnemonic == "unpcklps" || mnemonic == "unpckhps" || mnemonic == "unpcklpd" ||
         mnemonic == "unpckhpd") &&
        is_vector_register(operands[1])) {
      const bool qwords = mnemonic.back() == 'd';
      const bool high = mnemonic.find('h') != std::string::npos;
      emit(std::string(qwords ? "vector_unpack_qwords" : "vector_unpack_dwords") + "(context, " + destination +
           ", " + std::to_string(vector_index(operands[1])) + ", " + (high ? "1" : "0") + ");");
      return;
    }
    if ((mnemonic == "punpcklbw" || mnemonic == "punpckhbw" || mnemonic == "punpcklwd" ||
         mnemonic == "punpckhwd") &&
        is_vector_register(operands[1])) {
      const bool bytes = mnemonic.find("bw") != std::string::npos;
      const bool high = mnemonic.find('h') != std::string::npos;
      emit(std::string(bytes ? "vector_unpack_bytes" : "vector_unpack_words") + "(context, " + destination +
           ", " + std::to_string(vector_index(operands[1])) + ", " + (high ? "1" : "0") + ");");
      return;
    }
    if ((mnemonic == "packsswb" || mnemonic == "packuswb" || mnemonic == "packssdw") &&
        is_vector_register(operands[1])) {
      const auto helper_name = mnemonic == "packsswb" ? "vector_pack_signed_words"
                              : mnemonic == "packuswb" ? "vector_pack_unsigned_words"
                                                       : "vector_pack_signed_dwords";
      emit(std::string(helper_name) + "(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ");");
      return;
    }
    if (mnemonic == "pshufb" && is_vector_register(operands[1])) {
      emit("vector_shuffle_bytes(context, " + destination + ", " + std::to_string(vector_index(operands[1])) +
           ");");
      return;
    }
    if (mnemonic == "pshufb" && operands[1].kind == Operand::Kind::Memory) {
      emit("vector_shuffle_bytes_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ");");
      return;
    }
  }
  // PSHUFLW/PSHUFHW are encoded with a source register and an immediate, so the
  // destination is a separate operand: dst = shuffle(src, imm).
  if ((mnemonic == "pshuflw" || mnemonic == "pshufhw") && operands.size() == 3 &&
      is_vector_register(operands[0]) && is_vector_register(operands[1]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto source = std::to_string(vector_index(operands[1]));
    const auto control = std::to_string(operands[2].immediate_value & 0xff);
    // The runtime helper shuffles in place, so seed the destination from the
    // source first when they differ.
    if (destination != source)
      emit("std::memcpy(context->vector_registers[" + destination + "], context->vector_registers[" + source +
           "], 16);");
    emit(std::string(mnemonic == "pshuflw" ? "vector_shuffle_low_words" : "vector_shuffle_high_words") +
         "(context, " + destination + ", " + control + ");");
    return;
  }
  if (mnemonic == "pmovmskb" && operands.size() == 2 && is_vector_register(operands[1])) {
    operand_write(output, instruction, operands[0],
         "vector_move_byte_mask(context, " + std::to_string(vector_index(operands[1])) + ")", 4);
    return;
  }
  // Adapted from Remill's Apache-2.0 PINSRW semantics: retain the prior XMM
  // value, replace only one 16-bit lane, and reduce the immediate to eight
  // lanes. PINSRW's scalar source is a general register or a 16-bit memory
  // operand, never another XMM register.
  if (mnemonic == "pinsrw" && operands.size() == 3 && is_vector_register(operands[0]) &&
      !is_wide_vector_register(operands[0].register_name) &&
      operands[2].kind == discovery::Operand::Kind::Immediate &&
      (operands[1].kind == discovery::Operand::Kind::Register ||
       operands[1].kind == discovery::Operand::Kind::Memory)) {
    const auto source = operand_read_expression(instruction, operands[1], 2);
    emit("vector_insert_word(context, " + std::to_string(vector_index(operands[0])) +
         ", static_cast<std::uint16_t>(" + source + "), " +
         std::to_string(operands[2].immediate_value & 0xff) + ");");
    return;
  }
  // Adapted from Remill's Apache-2.0 PEXTRW semantics: select one 16-bit XMM
  // lane modulo eight and zero-extend it into the general-register output.
  if (mnemonic == "pextrw" && operands.size() == 3 && is_vector_register(operands[1]) &&
      !is_wide_vector_register(operands[1].register_name) &&
      operands[0].kind == discovery::Operand::Kind::Register &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    operand_write(output, instruction, operands[0],
                  "vector_extract_word(context, " + std::to_string(vector_index(operands[1])) + ", " +
                      std::to_string(operands[2].immediate_value & 0xff) + ")",
                  operand_width(operands[0], 4));
    return;
  }
  // Adapted from Remill's Apache-2.0 AVX semantics: VPBROADCASTB takes the
  // low byte of an XMM or memory source and fills each 128- or 256-bit
  // destination lane. The helper also clears the unused upper YMM half for a
  // VEX.128 destination.
  if (mnemonic == "vpbroadcastb" && operands.size() == 2 && is_vector_register(operands[0]) &&
      (is_vector_register(operands[1]) || operands[1].kind == discovery::Operand::Kind::Memory)) {
    const auto source = is_vector_register(operands[1])
        ? "vector_get_low(context, " + std::to_string(vector_index(operands[1])) + ", 1)"
        : "load_guest_memory(context, " + effective_address_expression(instruction, operands[1]) + ", 1)";
    const int byte_count = is_wide_vector_register(operands[0].register_name) ? 32 : 16;
    emit("vector_broadcast_byte(context, " + std::to_string(vector_index(operands[0])) +
         ", static_cast<std::uint8_t>(" + source + "), " + std::to_string(byte_count) + ");");
    return;
  }

  // `movsd`/`cmpsd` are both SSE scalar-double instructions and string
  // operations. The string form has no operands; if any operand is an XMM
  // register it is the SSE form, including the store-to-memory shape.
  bool vector_scalar_form = false;
  if (mnemonic == "movsd" || mnemonic == "cmpsd") {
    for (const auto& operand : operands) {
      if (is_vector_register(operand)) { vector_scalar_form = true; break; }
    }
  }
  if (string_operation_sizes().count(mnemonic) != 0 && !vector_scalar_form) {
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
    int byte_count = 16;
    for (const auto& operand : operands)
      if (operand.kind == discovery::Operand::Kind::Register && is_wide_vector_register(operand.register_name))
        byte_count = 32;
    emit_vector_move(operands[0], operands[1], byte_count);
    return;
  }
  if ((mnemonic == "movss" || mnemonic == "movsd") && operands.size() == 2 &&
      (is_vector_register(operands[0]) || is_vector_register(operands[1]))) {
    emit_vector_move(operands[0], operands[1], mnemonic == "movss" ? 4 : 8);
    return;
  }
  if ((mnemonic == "movhps" || mnemonic == "movlps") && operands.size() == 2) {
    const bool high = mnemonic == "movhps";
    if (is_vector_register(operands[0]) && operands[1].kind == Operand::Kind::Memory) {
      const auto destination = std::to_string(vector_index(operands[0]));
      const auto address = effective_address_expression(instruction, operands[1]);
      const auto value = "load_guest_memory(context, " + address + ", 8)";
      emit(high ? "vector_set_high_qword(context, " + destination + ", " + value + ");"
                : "vector_set_low_qword_preserve(context, " + destination + ", " + value + ");");
      return;
    }
    if (operands[0].kind == Operand::Kind::Memory && is_vector_register(operands[1])) {
      const auto source = std::to_string(vector_index(operands[1]));
      const auto address = effective_address_expression(instruction, operands[0]);
      const auto value = high ? "vector_get_high_qword(context, " + source + ")"
                              : "vector_get_low(context, " + source + ", 8)";
      emit("store_guest_memory(context, " + address + ", " + value + ", 8);");
      return;
    }
  }
  // Adapted from Remill's MOVLHPS/MOVHLPS semantics (Apache-2.0): preserve
  // one half of the destination and copy the indicated half of the source.
  // movlps/movhps and their double-precision forms move 64 bits between memory and
  // one half of an XMM register, preserving the other half. Both directions matter and
  // the destination/source order decides which it is: `movhps xmm, m64` loads into the
  // high half, `movhps m64, xmm` stores the high half out.
  if ((mnemonic == "movlps" || mnemonic == "movhps" || mnemonic == "movlpd" ||
       mnemonic == "movhpd") &&
      operands.size() == 2) {
    const bool high_half = mnemonic == "movhps" || mnemonic == "movhpd";
    const std::string offset = high_half ? "8" : "0";
    if (is_vector_register(operands[0]) && operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("load_guest_vector_half(context, " + effective_address_expression(instruction, operands[1]) +
           ", " + std::to_string(vector_index(operands[0])) + ", " + offset + ");");
      return;
    }
    if (operands[0].kind == discovery::Operand::Kind::Memory && is_vector_register(operands[1])) {
      emit("store_guest_vector_half(context, " + effective_address_expression(instruction, operands[0]) +
           ", " + std::to_string(vector_index(operands[1])) + ", " + offset + ");");
      return;
    }
  }
  if ((mnemonic == "movlhps" || mnemonic == "movhlps") && operands.size() == 2 &&
      is_vector_register(operands[0]) && is_vector_register(operands[1]) &&
      !is_wide_vector_register(operands[0].register_name) && !is_wide_vector_register(operands[1].register_name)) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto source = std::to_string(vector_index(operands[1]));
    emit("std::memcpy(context->vector_registers[" + destination + "] + " +
         (mnemonic == "movlhps" ? "8" : "0") + ", context->vector_registers[" + source + "] + " +
         (mnemonic == "movlhps" ? "0" : "8") + ", 8);");
    return;
  }
  if ((mnemonic == "movd" || mnemonic == "movq") && operands.size() == 2 &&
      (is_vector_register(operands[0]) || is_vector_register(operands[1]))) {
    const int byte_count = mnemonic == "movd" ? 4 : 8;
    if (is_vector_register(operands[0])) {
      // A vector source is not a general register: reading it as one throws, and
      // `movq xmm0, xmm3` moves the low 64 bits of the source, which is exactly
      // what vector_get_low returns.
      const auto value = operands[1].kind == discovery::Operand::Kind::Memory
          ? "load_guest_memory(context, " + effective_address_expression(instruction, operands[1]) + ", " +
                std::to_string(byte_count) + ")"
          : is_vector_register(operands[1])
              ? "vector_get_low(context, " + std::to_string(vector_index(operands[1])) + ", " +
                    std::to_string(byte_count) + ")"
              : operand_read_expression(instruction, operands[1], byte_count);
      emit("vector_set_low(context, " + std::to_string(vector_index(operands[0])) + ", " + value + ", " +
           std::to_string(byte_count) + ");");
    } else {
      operand_write(output, instruction, operands[0],
           "vector_get_low(context, " + std::to_string(vector_index(operands[1])) + ", " +
               std::to_string(byte_count) + ")", byte_count);
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
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto control = std::to_string(operands[2].immediate_value & 0xff);
    if (is_vector_register(operands[1])) {
      emit("vector_shuffle_dwords(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ", " + control + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("vector_shuffle_dwords_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ", " + control + ");");
      return;
    }
  }
  if (mnemonic == "shufps" && operands.size() == 3 && is_vector_register(operands[0]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto control = std::to_string(operands[2].immediate_value & 0xff);
    if (is_vector_register(operands[1])) {
      emit("vector_shuffle_single(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ", " + control + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("vector_shuffle_single_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ", " + control + ");");
      return;
    }
  }
  // SHUFPD is not SHUFPS with a different name: it has two 64-bit lanes and its
  // selector bits pick the LOW result from the DESTINATION and the HIGH result from
  // the SOURCE. Treating it as the single-precision form would silently produce the
  // wrong lane order, so it gets its own helper.
  if (mnemonic == "shufpd" && operands.size() == 3 && is_vector_register(operands[0]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto control = std::to_string(operands[2].immediate_value & 0xff);
    if (is_vector_register(operands[1])) {
      emit("vector_shuffle_doubles(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ", " + control + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("vector_shuffle_doubles_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ", " + control + ");");
      return;
    }
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

  // MXCSR is real guest state: it must round-trip through memory and drive the
  // rounding mode of conversions, not be a constant 0x1f80.
  if (mnemonic == "ldmxcsr" && operands.size() == 1 &&
      operands[0].kind == discovery::Operand::Kind::Memory) {
    emit("load_mxcsr(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  if (mnemonic == "stmxcsr" && operands.size() == 1 &&
      operands[0].kind == discovery::Operand::Kind::Memory) {
    emit("store_mxcsr(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }

  // CVTDQ2PS: convert four packed signed dwords to four packed single-precision
  // floats under the MXCSR rounding mode, raising the precision flag if inexact.
  if (mnemonic == "cvtdq2ps" && operands.size() == 2 && is_vector_register(operands[0])) {
    const auto destination = std::to_string(vector_index(operands[0]));
    if (is_vector_register(operands[1])) {
      emit("convert_dwords_to_floats(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("convert_dwords_to_floats_from_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ");");
      return;
    }
  }
  if (mnemonic == "cvttps2dq" && operands.size() == 2 && is_vector_register(operands[0])) {
    const auto destination = std::to_string(vector_index(operands[0]));
    if (is_vector_register(operands[1])) {
      emit("vector_convert_truncated_floats_to_dwords(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("vector_convert_truncated_floats_to_dwords_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ");");
      return;
    }
  }
  if (mnemonic == "roundsd" && operands.size() == 3 && is_vector_register(operands[0]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto immediate = std::to_string(operands[2].immediate_value & 0xff);
    if (is_vector_register(operands[1])) {
      emit("round_scalar_double_register(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ", " + immediate + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("round_scalar_double_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ", " + immediate + ");");
      return;
    }
  }
  if (mnemonic == "pcmpistri" && operands.size() == 3 && is_vector_register(operands[0]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto immediate = std::to_string(operands[2].immediate_value & 0xff);
    if (is_vector_register(operands[1])) {
      emit("vector_pcmpistri_register(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ", " + immediate + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("vector_pcmpistri_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ", " + immediate + ");");
      return;
    }
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
      const std::string mask = "(1ull << bit)";
      // BTR must *clear* the bit, so it ands with the complement. Anding with
      // the mask itself kept only the tested bit and destroyed every other one.
      const auto updated = mnemonic == "bts" ? "(original | " + mask + ")"
                          : mnemonic == "btr" ? "(original & ~" + mask + ")"
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
    operand_write(output, instruction, operands[0], operand_read_expression(instruction, operands[1], width), width);
    return;
  }
  // `movnti m32/m64, r32/r64` stores a general register to memory with a
  // NON-TEMPORAL HINT. The hint is about cache behaviour, not about the value, so the
  // store itself is an ordinary one and the semantics are exactly `mov`. It appears in
  // real applications (t64.exe and w64.exe each had 24, the only unsupported class in
  // either) and is emitted by `_mm_stream_si32`/`_mm_stream_si64`.
  if (mnemonic == "movnti") {
    const auto width = operand_width(operands[0], 4);
    operand_write(output, instruction, operands[0], operand_read_expression(instruction, operands[1], width), width);
    return;
  }
  if (mnemonic == "movzx") {
    const auto destination_width = operand_width(operands[0], 8);
    const auto source_width = operand_width(operands[1], 1);
    const auto source = operand_read_expression(instruction, operands[1], source_width);
    const auto widened = source_width == 1
        ? "static_cast<std::uint64_t>(static_cast<std::uint8_t>(" + source + "))"
        : "static_cast<std::uint64_t>(static_cast<std::uint16_t>(" + source + "))";
    operand_write(output, instruction, operands[0], widened, destination_width);
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
    operand_write(output, instruction, operands[0], widened, destination_width);
    return;
  }
  if (mnemonic == "lea") {
    const auto width = operand_width(operands[0], 8);
    operand_write(output, instruction, operands[0], effective_address_expression(instruction, operands[1]), width);
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
    operand_write(output,
        instruction, operands[0],
        arithmetic_helpers().at(mnemonic) + "(context, " + operand_read_expression(instruction, operands[0], width) +
            ", " + operand_read_expression(instruction, operands[1], width) + ", " + std::to_string(width) + ")",
        width);
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
    operand_write(output, instruction, operands[0], call, width);
    return;
  }

  if ((mnemonic == "shrd" || mnemonic == "shld") && operands.size() == 3) {
    const auto width = operand_width(operands[0], 8);
    const std::string helper = mnemonic == "shrd" ? "shift_right_double" : "shift_left_double";
    operand_write(output, instruction, operands[0],
                                 helper + "(context, " + operand_read_expression(instruction, operands[0], width) +
                                     ", " + operand_read_expression(instruction, operands[1], width) + ", " +
                                     operand_read_expression(instruction, operands[2], 1) + ", " +
                                     std::to_string(width) + ")",
                                 width);
    return;
  }
  if (shift_helpers().count(mnemonic) != 0) {
    const auto width = operand_width(operands[0], 8);
    const auto count = operands.size() > 1 ? operand_read_expression(instruction, operands[1], 1) : "1ull";
    operand_write(output, instruction, operands[0],
                                 shift_helpers().at(mnemonic) + "(context, " +
                                     operand_read_expression(instruction, operands[0], width) + ", " + count + ", " +
                                     std::to_string(width) + ")",
                                 width);
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
      operand_write(output, instruction, operands[0],
                                   "signed_multiply_two(context, " +
                                       operand_read_expression(instruction, operands[0], width) + ", " +
                                       operand_read_expression(instruction, operands[1], width) + ", " +
                                       std::to_string(width) + ")",
                                   width);
      return;
    }
    operand_write(output, instruction, operands[0],
                                 "signed_multiply_two(context, " +
                                     operand_read_expression(instruction, operands[1], width) + ", " +
                                     operand_read_expression(instruction, operands[2], width) + ", " +
                                     std::to_string(width) + ")",
                                 width);
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
  // CWD sign-extends AX into DX:AX, the 16-bit sibling of CDQ/CQO.
  if (mnemonic == "cwd") {
    emit("context->registers[2] = (context->registers[2] & ~0xffffull) | "
         "((context->registers[0] & 0x8000ull) != 0 ? 0xffffull : 0ull);");
    return;
  }
  // TZCNT: trailing zero count, defined for zero input.
  if (mnemonic == "tzcnt" && operands.size() == 2) {
    const auto width = operand_width(operands[0], 8);
    operand_write(output, instruction, operands[0],
         "count_trailing_zeros(context, " + operand_read_expression(instruction, operands[1], width) + ", " +
             std::to_string(width) + ")", width);
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
  // `cbw` sign-extends AL into AX and leaves the rest of EAX alone, which is what
  // distinguishes it from `cwde`: the destination is 16 bits, so only the low 16 bits
  // of the register are written. It appears in 32-bit code compiled from anything that
  // narrows a char before arithmetic, and the lifter refused the whole program for it.
  if (mnemonic == "cbw") {
    const auto rax = std::to_string(kRegisterRax);
    emit("context->registers[" + rax + "] = (context->registers[" + rax +
         "] & ~0xffffull) | static_cast<std::uint64_t>(static_cast<std::uint16_t>(static_cast<std::int16_t>("
         "static_cast<std::int8_t>(context->registers[" + rax + "] & 0xffu))));");
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
    // Segment registers are not in the general register file, so the generic
    // path below would emit an empty expression and produce code that does not
    // compile. A flat address space has no selectors, so this fails loudly
    // instead of inventing one.
    if (operands[0].kind == Operand::Kind::Register &&
        register_read_expression(operands[0].register_name).empty()) {
      emit("recomp_trap(context, \"push " + operands[0].register_name + "\");");
      emit_return();
      return;
    }
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
    operand_write(output, instruction, operands[0], value, width);
    return;
  }
  if (mnemonic == "popal" || mnemonic == "popad") {
    // POPAD restores registers in stack order and consumes, but ignores, the
    // saved ESP slot. Reading that slot into ESP would change the remaining pops.
    const char* registers[] = {"edi", "esi", "ebp", nullptr, "ebx", "edx", "ecx", "eax"};
    for (const auto* name : registers) {
      if (name == nullptr) {
        emit("context->registers[4] = mask_guest_address(context->registers[4] + 4);");
      } else {
        emit(register_write_statement(name, "static_cast<std::uint32_t>(pop_guest_stack(context))"));
      }
    }
    return;
  }
  if (mnemonic == "pushad" || mnemonic == "pushal") {
    // Capstone names it `pushal` for 32-bit and `pushad` for the same encoding read
    // as 64-bit; both push the eight general registers in one instruction.
    emit("push_all_general(context);");
    return;
  }
  // RDRAND/RDSEED write a random value into a general register and set CF to report
  // success. There is no fixed correct answer, so a real random value is the faithful
  // implementation; the carry flag is set because the host always has a source.
  if ((mnemonic == "rdrand" || mnemonic == "rdseed") && operands.size() == 1 &&
      operands[0].kind == discovery::Operand::Kind::Register) {
    const auto iterator = register_descriptors().find(operands[0].register_name);
    if (iterator == register_descriptors().end())
      fail_operand(instruction, "write", "'" + operands[0].register_name + "'");
    emit("random_into_register(context, " + std::to_string(iterator->second.index) + ", " +
         std::to_string(operand_width(operands[0], 4)) + ");");
    return;
  }
  // `sti` sets the interrupt flag, which a user-mode program cannot do: the
  // instruction is privileged and is a no-op outside ring 0. Modelling it as one is
  // not a shortcut, it is what happens. It reaches a lifted program through CRT or
  // compiler-generated code that is never executed.
  if (mnemonic == "sti") {
    // Nothing to emit: the instruction is a no-op outside ring 0, and the statement
    // list must not be left empty for the block, so a comment records why.
    emit("/* sti: privileged, a no-op in user mode */");
    return;
  }
  // `int1` raises a debug exception. Nothing in a user-mode program reaches it except
  // a debugger breakpoint, and if one is reached the honest result is to stop and say
  // where rather than to continue with invented state.
  if (mnemonic == "int1" || mnemonic == "int3" || mnemonic == "icebp") {
    emit("recomp_trap(context, \"" + mnemonic + "\");");
    return;
  }
  // The integer SIMD forms that were the largest remaining classes after FMA.
  // VCVTPS2PH: four singles to four half-precision values, with the rounding mode in the
  // immediate. The immediate is not decoration -- it selects between nearest-even, down,
  // up and truncate, and ignoring it rounds every program's result the same way.
  if (mnemonic == "vcvtps2ph" && operands.size() == 3 && is_vector_register(operands[0]) &&
      is_vector_register(operands[1]) && operands[2].kind == discovery::Operand::Kind::Immediate) {
    emit("vector_convert_floats_to_half(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ", " +
         std::to_string(operands[2].immediate_value & 0xff) + ");");
    return;
  }
  // The VEX form of a two-operand SSE instruction has THREE operands, and the first two
  // are its sources: `vpmaddubsw xmm1, xmm2, xmm3` computes xmm1 = xmm2 op xmm3, where
  // `pmaddubsw xmm1, xmm2` computes xmm1 = xmm1 op xmm2. Normalising the MNEMONIC does not
  // normalise the OPERAND LIST, so a two-operand check never matched a VEX instruction --
  // the implementation was present and still refused. This resolves the two forms to the
  // same (destination, source) pair.
  const auto binary_simd_sources = [&](int expected_operands) -> std::optional<std::pair<int, int>> {
    if (static_cast<int>(operands.size()) != expected_operands) return std::nullopt;
    if (expected_operands == 2) {
      if (!is_vector_register(operands[0]) || !is_vector_register(operands[1])) return std::nullopt;
      return std::make_pair(vector_index(operands[0]), vector_index(operands[1]));
    }
    if (!is_vector_register(operands[0]) || !is_vector_register(operands[1]) ||
        !is_vector_register(operands[2]))
      return std::nullopt;
    // `vex` forms write the first source into the destination, then apply the second.
    return std::make_pair(vector_index(operands[1]), vector_index(operands[2]));
  };
  if ((mnemonic == "pmaddubsw" || mnemonic == "vpmaddubsw") &&
      (operands.size() == 2 || operands.size() == 3)) {
    const auto pair = binary_simd_sources(static_cast<int>(operands.size()));
    if (pair && (operands.size() == 2 || pair->first == vector_index(operands[1]))) {
      if (operands.size() == 3) {
        // Copy the first source into the destination first: the VEX form is a three-input
        // operation and the helper reads its accumulator from the destination.
        emit("std::memcpy(context->vector_registers[" + std::to_string(vector_index(operands[0])) +
             "], context->vector_registers[" + std::to_string(vector_index(operands[1])) + "], 16);");
      }
      emit("vector_multiply_add_unsigned_signed_bytes(context, " +
           std::to_string(vector_index(operands[0])) + ", " + std::to_string(pair->second) + ");");
      return;
    }
  }
  if ((mnemonic == "psignb" || mnemonic == "vpsignb") && operands.size() >= 2 &&
      is_vector_register(operands[0]) && is_vector_register(operands.back())) {
    if (operands.size() == 3 && is_vector_register(operands[1]))
      emit("std::memcpy(context->vector_registers[" + std::to_string(vector_index(operands[0])) +
           "], context->vector_registers[" + std::to_string(vector_index(operands[1])) + "], 16);");
    emit("vector_sign_bytes(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands.back())) + ");");
    return;
  }
  if ((mnemonic == "pmovzxbd" || mnemonic == "vpmovzxbd") && operands.size() == 2 &&
      is_vector_register(operands[0]) && is_vector_register(operands[1])) {
    emit("vector_widen_bytes_to_dwords(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ");");
    return;
  }
  if ((mnemonic == "vinsertps" || mnemonic == "insertps") && operands.size() == 3 &&
      is_vector_register(operands[0]) && is_vector_register(operands[1]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    emit("vector_insert_single(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ", " +
         std::to_string(operands[2].immediate_value & 0xff) + ");");
    return;
  }
  if ((mnemonic == "vpinsrd" || mnemonic == "pinsrd" || mnemonic == "vpinsrq" || mnemonic == "pinsrq") &&
      operands.size() == 3 && is_vector_register(operands[0]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    const bool qword = mnemonic.find("rq") != std::string::npos;
    const auto value = operand_read_expression(instruction, operands[1], qword ? 8 : 4);
    emit(std::string(qword ? "vector_insert_qword" : "vector_insert_dword") + "(context, " +
         std::to_string(vector_index(operands[0])) + ", " + value + ", " +
         std::to_string(operands[2].immediate_value & 0xff) + ");");
    return;
  }
  // FMA, in the three operand orderings the mnemonic's digits encode. The digits are not
  // decoration: `213` and `231` compute different products from the same three registers.
  {
    static const std::map<std::string, std::string> fma_orderings = {
        {"132", "132"}, {"213", "213"}, {"231", "231"}};
    std::string digits;
    for (const auto& candidate : {std::string("132"), std::string("213"), std::string("231")}) {
      if (mnemonic.find(candidate) != std::string::npos) { digits = candidate; break; }
    }
    const auto width_suffix = mnemonic.size() >= 2 ? mnemonic.substr(mnemonic.size() - 2) : std::string{};
    const bool is_fma = mnemonic.rfind("vfmadd", 0) == 0 || mnemonic.rfind("vfmsub", 0) == 0;
    const bool fma_width_ok = width_suffix == "ps" || width_suffix == "pd" ||
                              width_suffix == "ss" || width_suffix == "sd";
    if (is_fma && fma_orderings.count(digits) != 0 && operands.size() == 3 &&
        is_vector_register(operands[0]) && is_vector_register(operands[1]) && fma_width_ok) {
      const bool doubles = width_suffix == "pd" || width_suffix == "sd";
      const auto operation = mnemonic.rfind("vfmsub", 0) == 0 ? "fmsub" : "fma";
      const auto helper = std::string("vector_") + operation + fma_orderings.at(digits) +
                          (doubles ? "_doubles" : "_floats");
      if (is_vector_register(operands[2])) {
        emit(helper + "(context, " + std::to_string(vector_index(operands[0])) + ", " +
             std::to_string(vector_index(operands[1])) + ", " + std::to_string(vector_index(operands[2])) +
             ");");
        return;
      }
      if (operands[2].kind == discovery::Operand::Kind::Memory) {
        emit(helper + "_memory(context, " + std::to_string(vector_index(operands[0])) + ", " +
             std::to_string(vector_index(operands[1])) + ", " +
             effective_address_expression(instruction, operands[2]) + ");");
        return;
      }
    }
  }
  // The 256-bit and variable-blend forms. `vblendvps` was the single largest unsupported
  // class on a real application (905 occurrences).
  if ((mnemonic == "vblendvps" || mnemonic == "vblendvpd") && operands.size() == 4 &&
      is_vector_register(operands[0]) && is_vector_register(operands[1]) &&
      is_vector_register(operands[3])) {
    emit(std::string(mnemonic == "vblendvps" ? "vector_blend_variable_floats"
                                             : "vector_blend_variable_doubles") +
         "(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ", " + std::to_string(vector_index(operands[3])) + ");");
    return;
  }
  if (mnemonic == "vbroadcastss" && operands.size() == 2 && is_vector_register(operands[0])) {
    if (is_vector_register(operands[1])) {
      emit("vector_broadcast_float(context, " + std::to_string(vector_index(operands[0])) + ", " +
           std::to_string(vector_index(operands[1])) + ");");
    } else if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("vector_broadcast_float_memory(context, " + std::to_string(vector_index(operands[0])) + ", " +
           effective_address_expression(instruction, operands[1]) + ");");
    }
    return;
  }
  if (mnemonic == "vinsertf128" && operands.size() == 4 && is_vector_register(operands[0]) &&
      is_vector_register(operands[1]) && operands[3].kind == discovery::Operand::Kind::Immediate) {
    const auto destination = std::to_string(vector_index(operands[0]));
    const auto source = std::to_string(vector_index(operands[1]));
    const auto immediate = std::to_string(operands[3].immediate_value & 0xff);
    if (is_vector_register(operands[2])) {
      emit("vector_insert_128(context, " + destination + ", " + source + ", " +
           std::to_string(vector_index(operands[2])) + ", " + immediate + ");");
      return;
    }
    if (operands[2].kind == discovery::Operand::Kind::Memory) {
      emit("vector_insert_128_memory(context, " + destination + ", " + source + ", " +
           effective_address_expression(instruction, operands[2]) + ", " + immediate + ");");
      return;
    }
  }
  if ((mnemonic == "vinsertf128" || mnemonic == "vextractf128") && operands.size() == 3 &&
      is_vector_register(operands[0]) && is_vector_register(operands[1]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    emit(std::string(mnemonic == "vinsertf128" ? "vector_insert_upper_128" : "vector_extract_upper_128") +
         "(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ", " +
         std::to_string(operands[2].immediate_value & 0xff) + ");");
    return;
  }
  if (mnemonic == "vpextrw" && operands.size() == 3 &&
      operands[0].kind == discovery::Operand::Kind::Register && is_vector_register(operands[1]) &&
      operands[2].kind == discovery::Operand::Kind::Immediate) {
    operand_write(output, instruction, operands[0],
                  "vector_extract_word(context, " + std::to_string(vector_index(operands[1])) + ", " +
                      std::to_string(operands[2].immediate_value & 0xff) + ")",
                  operand_width(operands[0], 4));
    return;
  }
  // The BMI2 variable shifts. Their count comes from a general register, not CL, and
  // they leave the flags ALONE -- which is the whole reason a compiler emits them in
  // preference to `shl`/`shr` when it needs the flags preserved.
  if ((mnemonic == "shlx" || mnemonic == "shrx" || mnemonic == "sarx") && operands.size() == 3 &&
      operands[0].kind == discovery::Operand::Kind::Register &&
      operands[1].kind == discovery::Operand::Kind::Register) {
    const auto width = operand_width(operands[0], 4);
    const auto count = operand_read_expression(instruction, operands[2], width);
    const auto value = operand_read_expression(instruction, operands[1], width);
    const std::string helper = mnemonic == "shlx"   ? "variable_shift_left"
                              : mnemonic == "shrx" ? "variable_shift_right"
                                                   : "variable_shift_right_arithmetic";
    operand_write(output, instruction, operands[0],
                  helper + "(" + value + ", " + count + ", " + std::to_string(width) + ")", width);
    return;
  }
  // `pmulld` multiplies four 32-bit lanes and keeps the LOW half of each product.
  if (mnemonic == "pmulld" && operands.size() == 2 && is_vector_register(operands[0]) &&
      is_vector_register(operands[1])) {
    emit("vector_multiply_low_dwords(context, " + std::to_string(vector_index(operands[0])) + ", " +
         std::to_string(vector_index(operands[1])) + ");");
    return;
  }
  // LFENCE/MFENCE/SFENCE order memory operations for OTHER observers. A single-threaded
  // guest has none, and the generated code touches guest memory through helpers that the
  // compiler may not reorder across, so there is nothing left for these to do. They are
  // accepted rather than refused because refusing them stops a program over a fence that
  // would have had no effect.
  if (mnemonic == "lfence" || mnemonic == "mfence" || mnemonic == "sfence") {
    emit("/* " + mnemonic + ": memory fence, no effect for a single-threaded guest */");
    return;
  }
  if (mnemonic == "leave") {
    emit("context->registers[" + std::to_string(kRegisterRsp) + "] = context->registers[" + std::to_string(kRegisterRbp) + "];");
    emit("context->registers[" + std::to_string(kRegisterRbp) + "] = pop_guest_stack(context);");
    return;
  }

  if (mnemonic.rfind("set", 0) == 0 && condition_codes().count(mnemonic.substr(3)) != 0) {
    operand_write(output, instruction, operands[0],
                                 "evaluate_condition(context, " + condition_codes().at(mnemonic.substr(3)) + ")",
                                 1);
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
    // A DIRECT call is only emitted as a direct call when discovery actually recovered
    // the target. Otherwise the generated code names a function that does not exist and
    // the whole program fails to COMPILE -- which is what happened to two real
    // applications, one of them calling address zero. An unrecovered target is a real
    // situation (the address may be data that decoded as a call, or code discovery did
    // not reach), and the honest response is the runtime's: resolve it and, if it is
    // not there, say which address at the point it is reached.
    if (target && operands[0].kind == Operand::Kind::Immediate &&
        discovery_.functions().count(*target) != 0) {
      emit("push_guest_stack(context, " + format_hex(instruction.address + instruction.size) + ");");
      emit(guest_function_name(*target) + "(context);");
      return;
    }
    if (target && operands[0].kind == Operand::Kind::Immediate) {
      emit("invoke_guest_indirect(context, " + format_hex(*target) + ", " +
           format_hex(instruction.address + instruction.size) + ");");
      return;
    }
    emit("invoke_guest_indirect(context, " +
         operand_read_expression(instruction, operands[0], operand_width(operands[0], 8)) + ", " +
         format_hex(instruction.address + instruction.size) + ");");
    return;
  }
  if (mnemonic == "jmp") {
    if (const auto* imported = import_for_instruction(discovery_, instruction); imported != nullptr) {
      // A jump to an import is a tail call: the return address is already on the
      // stack, so this must not push another one.
      emit("invoke_win32_import_tail(context, \"" + imported->library_name + "\", \"" +
           imported->symbol_name + "\");");
      emit_return();
      return;
    }
    if (!operands.empty() && operands[0].kind == Operand::Kind::Immediate) {
      const auto target = static_cast<std::uint64_t>(operands[0].immediate_value);
      // The same rule as a direct `call`: naming `guest_function_<target>` is only
      // valid when discovery recovered that target. Emitting it otherwise produces a
      // reference to a function that does not exist, and the whole program fails to
      // compile -- which is how a real application ended up calling address zero.
      if (discovery_.functions().count(target) != 0 &&
          (function.tail_call_targets.count(target) != 0 || function.instructions.count(target) == 0)) {
        emit(guest_function_name(target) + "(context);");
        emit_return();
      } else if (function.instructions.count(target) != 0) {
        emit("goto label_" + std::to_string(target) + ";");
      } else {
        emit("jump_guest_indirect(context, " + format_hex(target) + ");");
        emit_return();
      }
      return;
    }
    emit("jump_guest_indirect(context, " +
         operand_read_expression(instruction, operands[0], operand_width(operands[0], 8)) + ");");
    emit_return();
    return;
  }
  // A `goto` is only valid where a label was actually written, and labels exist only
  // for addresses that are instructions in THIS function. A branch anywhere else --
  // outside the recovered range, or into data -- has to go through the runtime's
  // dispatch, which names the address if it is not a function either. Emitting the
  // `goto` unconditionally is what produced "use of undeclared label" in the
  // generated code for a real application.
  const auto branch_body = [&function](std::uint64_t target) {
    if (function.instructions.count(target) != 0)
      return "goto label_" + std::to_string(target) + ";";
    return "{ jump_guest_indirect(context, " + format_hex(target) + "); return; }";
  };
  if (kConditionalBranches.count(mnemonic) != 0 && condition_codes().count(mnemonic.substr(1)) != 0) {
    const auto condition = condition_codes().at(mnemonic.substr(1));
    if (!operands.empty() && operands[0].kind == Operand::Kind::Immediate) {
      const auto target = static_cast<std::uint64_t>(operands[0].immediate_value);
      emit("if (evaluate_condition(context, " + condition + ")) " + branch_body(target));
    } else {
      emit("if (evaluate_condition(context, " + condition + ")) { jump_guest_indirect(context, " +
           operand_read_expression(instruction, operands[0], 8) + "); return; }");
    }
    return;
  }
  if ((mnemonic == "bt" || mnemonic == "bts" || mnemonic == "btr" || mnemonic == "btc") &&
      operands.size() == 2 && operands[0].kind == discovery::Operand::Kind::Memory) {
    const auto width = operand_width(operands[0], 4);
    const auto bits = std::to_string(width * 8);
    const auto element_bytes = std::to_string(width);
    const auto address = effective_address_expression(instruction, operands[0]);
    const auto index = operand_read_expression(instruction, operands[1], width);
    std::string body = "{ const std::uint64_t bit_index = " + index +
                       "; const std::uint64_t element = mask_guest_address(" + address + " + (bit_index / " + bits +
                       ") * " + element_bytes + "); const std::uint64_t bit = bit_index % " + bits +
                       "; const std::uint64_t original = load_guest_memory(context, element, " + element_bytes +
                       "); context->carry_flag = (original >> bit) & 1; ";
    if (mnemonic != "bt") {
      const std::string mask = "(1ull << bit)";
      const auto updated = mnemonic == "bts" ? "(original | " + mask + ")"
                          : mnemonic == "btr" ? "(original & ~" + mask + ")"
                                              : "(original ^ " + mask + ")";
      body += "store_guest_memory(context, element, " + updated + ", " + element_bytes + ");";
    }
    body += " }";
    emit(body);
    return;
  }

  // XGETBV reads the extended control register. This model implements SSE and
  // does not implement AVX, so XCR0 reports the SSE state only and a program
  // that asks takes the SSE path -- which is the honest answer rather than
  // advertising state the recompiler cannot maintain.
  if (mnemonic == "xgetbv") {
    emit("context->registers[0] = 0x1ull; context->registers[2] = 0;");
    return;
  }

  if (mnemonic == "ret") {
    std::uint64_t adjustment = 8;
    if (!operands.empty() && operands[0].kind == Operand::Kind::Immediate)
      adjustment += static_cast<std::uint64_t>(operands[0].immediate_value);
    emit("return_from_guest_function(context, " + std::to_string(adjustment - 8) + ");");
    emit_return();
    return;
  }
  if (mnemonic == "retf") {
    emit("return_from_guest_function(context, 8);");
    emit_return();
    return;
  }

  if (mnemonic == "cbw") {
    emit(register_write_statement("ax", "static_cast<std::int8_t>(" + register_read_expression("al") + ")"));
    return;
  }
  if (mnemonic == "cwde") {
    emit(register_write_statement("eax", "static_cast<std::int16_t>(" + register_read_expression("ax") + ")"));
    return;
  }
  if (mnemonic == "cdqe") {
    emit(register_write_statement("rax", "static_cast<std::int32_t>(" + register_read_expression("eax") + ")"));
    return;
  }
  if (mnemonic == "daa") {
    emit(register_write_statement("al", "decimal_adjust_after_addition(context, " +
                                      register_read_expression("al") + ")"));
    return;
  }
  if (mnemonic == "into") {
    emit("if (context->overflow_flag != 0) recomp_trap(context, \"into\");");
    return;
  }
  if (mnemonic == "int3" || mnemonic == "hlt" || mnemonic == "ud2" || mnemonic == "ud1" || mnemonic == "ud0") {
    emit_trap(mnemonic);
    emit_return();
    return;
  }

  // CLD/STD only touch the direction flag, which is guest state: the string
  // operation helpers already read it, so nothing set it before this. The
  // context is value-initialised, which matches the architectural DF=0 reset.
  if (mnemonic == "cld") { emit("context->direction_flag = 0;"); return; }
  if (mnemonic == "std") { emit("context->direction_flag = 1;"); return; }

  // BSWAP has no memory form and no flags: it reverses the bytes of a 32- or
  // 64-bit register. A 32-bit write zero-extends into the 64-bit register, which
  // register_write_statement already models.
  // CVTDQ2PD converts the low two signed dwords to two doubles, unlike
  // CVTDQ2PS which converts four dwords to four floats.
  if ((mnemonic == "cvtdq2pd" || mnemonic == "vcvtdq2pd") && operands.size() == 2 &&
      is_vector_register(operands[0])) {
    const auto destination = std::to_string(vector_index(operands[0]));
    if (is_vector_register(operands[1])) {
      emit("vector_convert_dwords_to_doubles(context, " + destination + ", " +
           std::to_string(vector_index(operands[1])) + ");");
      return;
    }
    if (operands[1].kind == discovery::Operand::Kind::Memory) {
      emit("vector_convert_dwords_to_doubles_memory(context, " + destination + ", " +
           effective_address_expression(instruction, operands[1]) + ");");
      return;
    }
  }

  // PUSHFD/POPFD and their 64-bit spellings move the whole flags register.
  if (mnemonic == "pushfd" || mnemonic == "pushfq" || mnemonic == "pushfw") {
    emit("push_guest_stack(context, eflags_value(context));");
    return;
  }
  if (mnemonic == "popfd" || mnemonic == "popfq" || mnemonic == "popfw") {
    emit("set_eflags(context, static_cast<std::uint32_t>(pop_guest_stack(context)));");
    return;
  }

  // VZEROUPPER clears the upper half of every vector register and VZEROALL the
  // whole register; both are real state changes in a 256-bit register file.
  if (mnemonic == "vzeroupper") { emit("vector_zero_upper(context);"); return; }
  if (mnemonic == "vzeroall") { emit("vector_zero_all(context);"); return; }

  if (mnemonic == "bswap" && operands.size() == 1 &&
      operands[0].kind == discovery::Operand::Kind::Register) {
    const auto width = operand_width(operands[0], 8);
    const auto& name = operands[0].register_name;
    if (width == 4) {
      emit(register_write_statement(
          name, "byte_swap_32(static_cast<std::uint32_t>(" + register_read_expression(name) + "))"));
      return;
    }
    if (width == 8) {
      emit(register_write_statement(name, "byte_swap_64(" + register_read_expression(name) + ")"));
      return;
    }
    throw LiftError("unsupported bswap operand width at " + format_hex(instruction.address));
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
        {"mulsd", "vector_multiply_doubles"}, {"divsd", "vector_divide_doubles"},
        {"sqrtsd", "vector_square_root_doubles"},
        {"sqrtpd", "vector_square_root_packed_doubles"}};
    static const std::map<std::string, std::string> float_helpers = {
        {"addss", "vector_add_floats"}, {"subss", "vector_subtract_floats"},
        {"mulss", "vector_multiply_floats"}, {"divss", "vector_divide_floats"},
        {"sqrtss", "vector_square_root_floats"},
        {"sqrtps", "vector_square_root_packed_floats"},
        // The PACKED forms. `ps` operates on four singles and `pd` on two doubles; the
        // scalar mnemonics above are the ones ending `ss`/`sd`, and using one for the
        // other would compute the right value in the low lane and leave the rest alone.
        {"addps", "vector_add_packed_floats"}, {"subps", "vector_subtract_packed_floats"},
        {"mulps", "vector_multiply_packed_floats"}, {"divps", "vector_divide_packed_floats"},
        {"addpd", "vector_add_packed_doubles"}, {"subpd", "vector_subtract_packed_doubles"},
        {"mulpd", "vector_multiply_packed_doubles"}, {"divpd", "vector_divide_packed_doubles"},
        {"minss", "vector_min_floats"}, {"maxss", "vector_max_floats"},
        {"minsd", "vector_min_doubles"}, {"maxsd", "vector_max_doubles"},
        // The compare family. Each writes an all-ones or all-zeros MASK per lane, which
        // is why they map to their own helpers rather than to a boolean.
        {"cmpeqss", "vector_compare_equal_floats"}, {"cmpltss", "vector_compare_less_floats"},
        {"cmpless", "vector_compare_less_equal_floats"},
        {"cmpneqss", "vector_compare_not_equal_floats"},
        {"cmpeqsd", "vector_compare_equal_doubles"}, {"cmpltsd", "vector_compare_less_doubles"},
        {"cmplesd", "vector_compare_less_equal_doubles"},
        {"cmpneqsd", "vector_compare_not_equal_doubles"}};
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
  if (mnemonic == "cvtsi2ss" && operands.size() == 2 && is_vector_register(operands[0])) {
    const auto source_width = operand_width(operands[1], 4);
    const auto source = operand_read_expression(instruction, operands[1], source_width);
    const auto signed_value = source_width == 8 ? "static_cast<std::int64_t>(" + source + ")"
                                                : "static_cast<std::int64_t>(static_cast<std::int32_t>(" + source + "))";
    emit("vector_set_float(context, " + std::to_string(vector_index(operands[0])) + ", static_cast<float>(" +
         signed_value + "));");
    return;
  }
  if (mnemonic == "cvttss2si" && operands.size() == 2) {
    const auto width = operand_width(operands[0], 4);
    const auto source = operands[1].kind == discovery::Operand::Kind::Memory
        ? "load_guest_float(context, " + effective_address_expression(instruction, operands[1]) + ")"
        : "vector_get_float(context, " + std::to_string(vector_index(operands[1])) + ")";
    operand_write(output, instruction, operands[0],
         "static_cast<std::uint64_t>(static_cast<std::int64_t>(" + source + "))", width);
    return;
  }
  if (mnemonic == "cvttsd2si" && operands.size() == 2) {
    const auto width = operand_width(operands[0], 4);
    const auto source = operands[1].kind == discovery::Operand::Kind::Memory
        ? "load_guest_double(context, " + effective_address_expression(instruction, operands[1]) + ")"
        : "vector_get_double(context, " + std::to_string(vector_index(operands[1])) + ")";
    operand_write(output, instruction, operands[0],
         "static_cast<std::uint64_t>(static_cast<std::int64_t>(" + source + "))", width);
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
      operand_write(output, instruction, operands[0],
           "bit_scan_reverse(context, " + operand_read_expression(instruction, operands[1], width) + ", " +
               std::to_string(width) + ")", width);
    } else {
      operand_write(output, instruction, operands[0],
           "bit_scan_forward(context, " + operand_read_expression(instruction, operands[1], width) + ", " +
               std::to_string(width) + ")", width);
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

  const auto is_x87_register = [](const discovery::Operand& operand) {
    return operand.kind == discovery::Operand::Kind::Register &&
           x87_operand_index(operand.register_name) >= 0;
  };

  // x87 ---------------------------------------------------------------
  if (mnemonic == "wait" || mnemonic == "fwait") return;

  if (mnemonic == "fld") {
    if (operands.size() == 1 && is_x87_register(operands[0])) {
      emit("x87_push(context, x87_read(context, " + std::to_string(x87_operand_index(operands[0].register_name)) + "));");
    } else if (operands.size() == 1 && operands[0].kind == discovery::Operand::Kind::Memory) {
      emit("x87_load_real(context, " + effective_address_expression(instruction, operands[0]) + ", " +
           std::to_string(operand_width(operands[0], 8)) + ");");
    } else {
      record_unsupported(mnemonic, instruction);
    }
    return;
  }
  if (mnemonic == "fild" && operands.size() == 1) {
    emit("x87_load_integer(context, " + effective_address_expression(instruction, operands[0]) + ", " +
         std::to_string(operand_width(operands[0], 4)) + ");");
    return;
  }
  if ((mnemonic == "fst" || mnemonic == "fstp" || mnemonic == "fstpnce" || mnemonic == "fstpce" ||
       mnemonic == "fstcw" || mnemonic == "fnstcw") &&
      (operands.size() == 1 || (operands.size() == 2 && is_x87_register(operands[0]))) &&
      mnemonic.rfind("fst", 0) == 0) {
    if (mnemonic == "fstcw" || mnemonic == "fnstcw") {
      emit("x87_store_control_word(context, " + effective_address_expression(instruction, operands[0]) + ");");
      return;
    }
    const int pop = mnemonic == "fst" ? 0 : 1;
    if (is_x87_register(operands[0])) {
      emit("x87_write(context, " + std::to_string(x87_operand_index(operands[0].register_name)) +
           ", x87_read(context, 0));");
      if (pop) emit("(void)x87_pop(context);");
    } else {
      emit("x87_store_real(context, " + effective_address_expression(instruction, operands[0]) + ", " +
           std::to_string(operand_width(operands[0], 8)) + ", " + std::to_string(pop) + ");");
    }
    return;
  }
  {
    static const std::map<std::string, int> arithmetic_ops = {
        {"fadd", 0}, {"fmul", 1}, {"fsub", 2}, {"fsubr", 3}, {"fdiv", 4}, {"fdivr", 5},
        {"fiadd", 0}, {"fimul", 1}, {"fisub", 2}, {"fisubr", 3}, {"fidiv", 4}, {"fidivr", 5},
        {"faddp", 0}, {"fmulp", 1}, {"fsubp", 2}, {"fsubrp", 3}, {"fdivp", 4}, {"fdivrp", 5}};
    const auto entry = arithmetic_ops.find(mnemonic);
    if (entry != arithmetic_ops.end()) {
      const int operation = entry->second;
      const int pop = mnemonic.back() == 'p' ? 1 : 0;
      if (operands.size() == 1 && operands[0].kind == discovery::Operand::Kind::Memory) {
        const auto width = operand_width(operands[0], 8);
        const auto address = effective_address_expression(instruction, operands[0]);
        if (width == 4) {
          emit("{ const std::uint32_t bits = static_cast<std::uint32_t>(load_guest_memory(context, " + address +
               ", 4)); float operand = 0; std::memcpy(&operand, &bits, 4); x87_arithmetic(context, " +
               std::to_string(operation) + ", static_cast<double>(operand)); }");
        } else {
          emit("{ const std::uint64_t bits = load_guest_memory(context, " + address +
               ", 8); double operand = 0; std::memcpy(&operand, &bits, 8); x87_arithmetic(context, " +
               std::to_string(operation) + ", operand); }");
        }
      } else {
        // Resolve the destination and source registers. The pop forms
        // (`faddp st(i), st(0)`, and the implicit `faddp` = st(1) += st(0))
        // write the result to ST(i) and only then pop, so writing ST(0) would
        // discard the result.
        int destination = 0;
        int source = 1;
        if (operands.size() == 2 && is_x87_register(operands[0]) && is_x87_register(operands[1])) {
          destination = x87_operand_index(operands[0].register_name);
          source = x87_operand_index(operands[1].register_name);
        } else if (operands.size() == 1 && is_x87_register(operands[0])) {
          const auto index = x87_operand_index(operands[0].register_name);
          if (pop) { destination = index; source = 0; }
          else { destination = 0; source = index; }
        } else if (pop) {
          destination = 1;
          source = 0;
        }
        const char* expression = operation == 0 ? "left + right"
                                 : operation == 1 ? "left * right"
                                 : operation == 2 ? "left - right"
                                 : operation == 3 ? "right - left"
                                 : operation == 4 ? "left / right"
                                                  : "right / left";
        emit("{ const double left = x87_read(context, " + std::to_string(destination) +
             "); const double right = x87_read(context, " + std::to_string(source) +
             "); x87_write(context, " + std::to_string(destination) + ", " + expression + "); }");
      }
      if (pop) emit("(void)x87_pop(context);");
      return;
    }
  }
  if ((mnemonic == "comiss" || mnemonic == "comisd" || mnemonic == "ucomiss" || mnemonic == "ucomisd") &&
      operands.size() == 2 && is_vector_register(operands[0])) {
    const auto destination = vector_index(operands[0]);
    const bool is_double = mnemonic == "comisd" || mnemonic == "ucomisd";
    const std::string left = is_double
        ? "vector_get_double(context, " + std::to_string(destination) + ")"
        : "static_cast<double>(vector_get_float(context, " + std::to_string(destination) + "))";
    if (is_vector_register(operands[1])) {
      const auto source = vector_index(operands[1]);
      const std::string right = is_double
          ? "vector_get_double(context, " + std::to_string(source) + ")"
          : "static_cast<double>(vector_get_float(context, " + std::to_string(source) + "))";
      emit("compare_scalar_floats(context, " + left + ", " + right + ");");
    } else if (operands[1].kind == discovery::Operand::Kind::Memory) {
      const auto address = effective_address_expression(instruction, operands[1]);
      const std::string right = is_double ? "load_guest_double(context, " + address + ")"
                                          : "static_cast<double>(load_guest_float(context, " + address + "))";
      emit("compare_scalar_floats(context, " + left + ", " + right + ");");
    } else {
      record_unsupported(mnemonic, instruction);
    }
    return;
  }

  if (mnemonic == "fist" || mnemonic == "fistp") {
    const int pop = mnemonic == "fistp" ? 1 : 0;
    if (operands.size() == 1 && operands[0].kind == discovery::Operand::Kind::Memory) {
      emit("x87_store_integer(context, " + effective_address_expression(instruction, operands[0]) + ", " +
           std::to_string(operand_width(operands[0], 4)) + ", " + std::to_string(pop) + ");");
    } else if (pop) {
      emit("(void)x87_pop(context);");
    }
    return;
  }
  {
    // FCOMI/FUCOMI write the EFLAGS rather than the x87 status word; the "p"
    // suffix also pops.
    // Capstone spells the popping form "fcompi"/"fucompi"; the Intel manuals
    // write it "fcomip". Accept both.
    static const std::map<std::string, int> flag_compares = {
        {"fcomi", 0}, {"fcomip", 1}, {"fcompi", 1},
        {"fucomi", 0}, {"fucomip", 1}, {"fucompi", 1}};
    const auto flag_compare = flag_compares.find(mnemonic);
    if (flag_compare != flag_compares.end()) {
      const auto pop = std::to_string(flag_compare->second);
      if (operands.size() == 1 && is_x87_register(operands[0])) {
        emit("x87_compare_flags(context, x87_read(context, " +
             std::to_string(x87_operand_index(operands[0].register_name)) + "), " + pop + ");");
      } else {
        emit("x87_compare_flags(context, x87_read(context, 1), " + pop + ");");
      }
      return;
    }
    // FCMOVcc: condition numbers match x87_conditional_move's switch.
    static const std::map<std::string, int> conditional_moves = {
        {"fcmovb", 0}, {"fcmove", 1}, {"fcmovbe", 2}, {"fcmovu", 3},
        {"fcmovnb", 4}, {"fcmovne", 5}, {"fcmovnbe", 6}, {"fcmovnu", 7}};
    const auto conditional_move = conditional_moves.find(mnemonic);
    if (conditional_move != conditional_moves.end()) {
      const auto source = operands.empty()
                              ? 1
                              : x87_operand_index(operands[0].register_name);
      emit("x87_conditional_move(context, " + std::to_string(source) + ", " +
           std::to_string(conditional_move->second) + ");");
      return;
    }
    if (mnemonic == "fxam") { emit("x87_examine(context);"); return; }
  }
  {
    static const std::map<std::string, std::pair<int, int>> compare_ops = {
        {"fcom", {0, 0}}, {"fcomp", {0, 1}}, {"fcompp", {0, 2}},
        {"fucom", {0, 0}}, {"fucomp", {0, 1}}, {"fucompp", {0, 2}},
        {"ftst", {1, 0}}};
    const auto entry = compare_ops.find(mnemonic);
    if (entry != compare_ops.end()) {
      const int pops = entry->second.second;
      if (entry->second.first == 1) {
        emit("x87_compare(context, 0.0);");  // ftst compares ST(0) with zero
      } else if (operands.size() == 1 && operands[0].kind == discovery::Operand::Kind::Memory) {
        const auto width = operand_width(operands[0], 8);
        const auto address = effective_address_expression(instruction, operands[0]);
        if (width == 4) {
          emit("{ const std::uint32_t bits = static_cast<std::uint32_t>(load_guest_memory(context, " + address +
               ", 4)); float operand = 0; std::memcpy(&operand, &bits, 4); x87_compare(context, static_cast<double>(operand)); }");
        } else {
          emit("{ const std::uint64_t bits = load_guest_memory(context, " + address +
               ", 8); double operand = 0; std::memcpy(&operand, &bits, 8); x87_compare(context, operand); }");
        }
      } else if (operands.size() == 1 && is_x87_register(operands[0])) {
        emit("x87_compare(context, x87_read(context, " + std::to_string(x87_operand_index(operands[0].register_name)) + "));");
      } else {
        emit("x87_compare(context, x87_read(context, 1));");
      }
      for (int index = 0; index < pops; ++index) emit("(void)x87_pop(context);");
      return;
    }
  }
  if ((mnemonic == "fxsave" || mnemonic == "fxsave64") && operands.size() == 1) {
    emit("x87_save_state(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  if ((mnemonic == "fxrstor" || mnemonic == "fxrstor64") && operands.size() == 1) {
    emit("x87_restore_state(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  if (mnemonic == "fsincos") { emit("x87_sine_cosine(context);"); return; }
  if (mnemonic == "fyl2xp1") { emit("x87_log2_x_plus_one(context);"); return; }
  // The flag-only instructions and the MMX state reset.
  if (mnemonic == "clc") { emit("context->carry_flag = 0;"); return; }
  if (mnemonic == "stc") { emit("context->carry_flag = 1;"); return; }
  if (mnemonic == "cmc") { emit("context->carry_flag = context->carry_flag != 0 ? 0 : 1;"); return; }
  if (mnemonic == "emms") { return; }  // no MMX tag state is modelled
  // AAM: AL = AH-adjusted BCD digit pair. The immediate form is the general one.
  if (mnemonic == "aam") {
    const auto base = operands.empty() ? 10 : (operands[0].immediate_value & 0xff);
    if (base == 0) throw LiftError("AAM with a zero base at " + format_hex(instruction.address));
    emit("{ const std::uint32_t value = static_cast<std::uint32_t>(context->registers[0] & 0xffu); "
         "context->registers[0] = (context->registers[0] & ~0xffffull) | "
         "(static_cast<std::uint64_t>((value / " + std::to_string(base) + ") << 8) | (value % " +
         std::to_string(base) + ")); "
         "context->zero_flag = (context->registers[0] & 0xffull) == 0 ? 1 : 0; }");
    return;
  }
  // Port I/O and BOUND cannot work in a user-mode recompilation; they fail
  // loudly rather than doing something plausible.
  if (mnemonic == "in" || mnemonic == "out" || mnemonic == "bound") {
    emit_trap(mnemonic);
    emit_return();
    return;
  }
  if (mnemonic == "fptan") { emit("x87_partial_tangent(context);"); return; }
  if (mnemonic == "fnsave" && operands.size() == 1) {
    emit("x87_save_state_87(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  if (mnemonic == "frstor" && operands.size() == 1) {
    emit("x87_restore_state_87(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  // XLATB: AL = [EBX + AL], a byte table lookup with no operands.
  if (mnemonic == "xlatb" || mnemonic == "xlat") {
    emit("{ const std::uint64_t table = context->registers[3] + "
         "(context->registers[0] & 0xffull); context->registers[0] = "
         "(context->registers[0] & ~0xffull) | load_guest_memory(context, mask_guest_address(table), 1); }");
    return;
  }
  // ENTER imm16, imm8. A nonzero nesting level copies display frames; that form
  // is not modelled, so it fails loudly rather than building a wrong frame.
  if (mnemonic == "enter" && operands.size() == 2) {
    const auto frame = operands[0].immediate_value & 0xffff;
    const auto level = operands[1].immediate_value & 0x1f;
    emit("push_guest_stack(context, context->registers[5]);");
    if (level != 0) {
      // The nesting level copies display words from the frame chain, which is
      // what makes ENTER usable for block-structured languages.
      emit("{ const std::uint64_t frame_temporary = context->registers[4];");
      emit("  for (std::uint32_t nesting = 1; nesting < " + std::to_string(level) + "; ++nesting) {");
      emit("    context->registers[5] = mask_guest_address(context->registers[5] - 4);");
      emit("    push_guest_stack(context, load_guest_memory(context, context->registers[5], 4)); }");
      emit("  push_guest_stack(context, frame_temporary); }");
    }
    emit("context->registers[5] = context->registers[4];");
    emit("context->registers[4] = mask_guest_address(context->registers[4] - " + std::to_string(frame) + ");");
    return;
  }
  // Adapted from Remill's AAS semantics, lib/Arch/X86/Semantics/DECIMAL.cpp
  // (Apache-2.0). OF, ZF and PF are undefined; leave them unchanged.
  if (mnemonic == "aas") {
    emit("{ std::uint16_t ax = static_cast<std::uint16_t>(context->registers[0]); "
         "if ((ax & 0xfu) > 9 || context->auxiliary_flag == 1) { "
         "ax = static_cast<std::uint16_t>(ax - 6); "
         "ax = static_cast<std::uint16_t>(ax - 0x100); "
         "context->carry_flag = 1; context->auxiliary_flag = 1; } else { "
         "context->carry_flag = 0; context->auxiliary_flag = 0; } "
         "ax = static_cast<std::uint16_t>((ax & 0xff00u) | (ax & 0x0fu)); "
         "context->registers[0] = (context->registers[0] & ~0xffffull) | ax; }");
    return;
  }
  // AAA: ASCII adjust AL after addition, in the BCD sense the manual defines.
  if (mnemonic == "aaa") {
    emit("{ const std::uint32_t low = static_cast<std::uint32_t>(context->registers[0] & 0x0fu); "
         "if (low > 9 || context->auxiliary_flag != 0) { "
         "context->registers[0] = (context->registers[0] + 0x106u) & 0xff0fu; "
         "context->registers[0] = (context->registers[0] & ~0x100ull) | 0x100ull; "
         "context->carry_flag = 1; context->auxiliary_flag = 1; } else { "
         "context->registers[0] &= 0x0fu; context->carry_flag = 0; context->auxiliary_flag = 0; } }");
    return;
  }
  if (mnemonic == "fprem" || mnemonic == "fprem1") {
    emit(std::string("x87_partial_remainder(context, ") + (mnemonic == "fprem1" ? "1" : "0") + ");");
    return;
  }
  if (mnemonic == "f2xm1") { emit("x87_exponential_minus_one(context);"); return; }
  if (mnemonic == "fscale") { emit("x87_scale(context);"); return; }
  if ((mnemonic == "fnstenv" || mnemonic == "fstenv") && operands.size() == 1) {
    emit("x87_store_environment(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  if (mnemonic == "fldenv" && operands.size() == 1) {
    emit("x87_load_environment(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  // Far-pointer loads. In the flat 32-bit model the selector is ignored and the
  // instruction is a plain 32-bit load.
  if ((mnemonic == "les" || mnemonic == "lds" || mnemonic == "lss" || mnemonic == "lfs" ||
       mnemonic == "lgs") &&
      operands.size() == 2 && operands[1].kind == discovery::Operand::Kind::Memory) {
    const auto width = operand_width(operands[0], 4);
    operand_write(output, instruction, operands[0],
         "load_guest_memory(context, " + effective_address_expression(instruction, operands[1]) + ", " +
             std::to_string(width) + ")", width);
    return;
  }
  // Instructions this recompiler does not model and that a flat 32-bit user-mode
  // image cannot meaningfully execute. They fail loudly rather than silently.
  if (mnemonic == "lcall" || mnemonic == "ljmp" || mnemonic == "insb" || mnemonic == "insw" ||
      mnemonic == "insd" || mnemonic == "outsb" || mnemonic == "outsw" || mnemonic == "outsd" ||
      mnemonic == "int") {
    emit_trap(mnemonic);
    emit_return();
    return;
  }
  if (mnemonic == "fsqrt") { emit("x87_write(context, 0, std::sqrt(x87_read(context, 0)));"); return; }
  if (mnemonic == "fsin") { emit("x87_write(context, 0, std::sin(x87_read(context, 0)));"); return; }
  if (mnemonic == "fcos") { emit("x87_write(context, 0, std::cos(x87_read(context, 0)));"); return; }
  if (mnemonic == "frndint") {
    emit("x87_write(context, 0, static_cast<double>(x87_round_to_integer(context, x87_read(context, 0))));");
    return;
  }
  if (mnemonic == "fldln2") { emit("x87_push(context, 0.69314718055994530942);"); return; }
  if (mnemonic == "fldl2e") { emit("x87_push(context, 1.44269504088896340736);"); return; }
  if (mnemonic == "fldl2t") { emit("x87_push(context, 3.32192809488736234787);"); return; }
  if (mnemonic == "fldlg2") { emit("x87_push(context, 0.30102999566398119521);"); return; }

  if (mnemonic == "fxch") {
    // The operand may be implicit (ST(1)), one register, or two registers.
    int other = 1;
    if (operands.size() == 1 && is_x87_register(operands[0]))
      other = x87_operand_index(operands[0].register_name);
    else if (operands.size() == 2 && is_x87_register(operands[1]))
      other = x87_operand_index(operands[1].register_name);
    emit("{ const double temporary = x87_read(context, " + std::to_string(other) +
         "); x87_write(context, " + std::to_string(other) + ", x87_read(context, 0)); x87_write(context, 0, temporary); }");
    return;
  }
  if (mnemonic == "fyl2x") {
    // ST(1) = ST(1) * log2(ST(0)); then pop.
    emit("x87_write(context, 1, x87_read(context, 1) * std::log2(x87_read(context, 0)));");
    emit("(void)x87_pop(context);");
    return;
  }
  if (mnemonic == "fpatan") {
    // ST(1) = atan2(ST(1), ST(0)); then pop.
    emit("x87_write(context, 1, std::atan2(x87_read(context, 1), x87_read(context, 0)));");
    emit("(void)x87_pop(context);");
    return;
  }
  if (mnemonic == "fabs") { emit("x87_write(context, 0, std::fabs(x87_read(context, 0)));"); return; }
  if (mnemonic == "fchs") { emit("x87_write(context, 0, -x87_read(context, 0));"); return; }
  if (mnemonic == "fld1") { emit("x87_push(context, 1.0);"); return; }
  if (mnemonic == "fldz") { emit("x87_push(context, 0.0);"); return; }
  if (mnemonic == "fldpi") { emit("x87_push(context, 3.14159265358979323846);"); return; }
  if (mnemonic == "fldcw" && operands.size() == 1) {
    emit("x87_load_control_word(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  if (mnemonic == "fnstcw" && operands.size() == 1) {
    emit("x87_store_control_word(context, " + effective_address_expression(instruction, operands[0]) + ");");
    return;
  }
  if ((mnemonic == "fnstsw" || mnemonic == "fstsw") && operands.size() == 1) {
    if (operands[0].kind == discovery::Operand::Kind::Register) {
      emit("x87_store_status_word_ax(context);");
    } else {
      emit("x87_store_status_word(context, " + effective_address_expression(instruction, operands[0]) + ");");
    }
    return;
  }
  if (mnemonic == "fclex" || mnemonic == "fnclex" || mnemonic == "fninit") {
    emit("context->x87_status_word = 0;");
    return;
  }

  // Counted loops. CLD/STD are handled earlier, next to the other
  // direction-flag instruction, so this block only owns the counted jumps.
  if (mnemonic == "jecxz" || mnemonic == "jrcxz") {
    const auto target = static_cast<std::uint64_t>(operands[0].immediate_value);
    emit("if (context->registers[1] == 0) " + branch_body(target));
    return;
  }
  if (mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne") {
    const auto target = static_cast<std::uint64_t>(operands[0].immediate_value);
    std::string condition;
    if (mnemonic == "loope") condition = " && context->zero_flag != 0";
    else if (mnemonic == "loopne") condition = " && context->zero_flag == 0";
    emit("context->registers[1] = mask_guest_address(context->registers[1] - 1); if (context->registers[1] != 0" +
         condition + ") " + branch_body(target));
    return;
  }

  record_unsupported(mnemonic, instruction);
}

ir::Function X86_64Lifter::lift_function_to_ir(const RecoveredFunction& function) const {
  // The body is built as statements and rendered by the C++ backend. Statements
  // that have not been given a structured form yet arrive as Verbatim and are
  // emitted unchanged, so moving the lifter onto the representation cannot alter
  // the generated code -- which the golden test pins.
  ir::Function lifted;
  lifted.address = function.entry;
  lifted.name = guest_function_name(function.entry);
  // Adapted from igi-recomp tools/recomp/gen.py emit_copy (MIT): recovered
  // backward blocks can sort before the function's actual entry.
  if (!function.instructions.empty() && function.instructions.begin()->first != function.entry) {
    ir::Statement jump;
    jump.kind = ir::StatementKind::Jump;
    jump.label = "label_" + std::to_string(function.entry);
    jump.address_of_instruction = function.entry;
    lifted.statements.push_back(std::move(jump));
  }
  // A label is needed wherever anything can JUMP TO, not only at a block start.
  // Discovery's block starts and the set of branch targets are not the same set: a
  // branch into the middle of a recovered block is emitted as `goto label_<target>`
  // and the label was never written, so the generated code failed to compile with
  // "use of undeclared label". Collecting the targets from the instructions
  // themselves is what makes the two agree.
  std::set<std::uint64_t> branch_targets;
  for (const auto& [address, instruction] : function.instructions) {
    (void)address;
    if (instruction.operands.empty()) continue;
    const bool branches = instruction.mnemonic == "jmp" || instruction.mnemonic == "call" ||
                          kConditionalBranches.count(instruction.mnemonic) != 0 ||
                          instruction.mnemonic.rfind("loop", 0) == 0 ||
                          instruction.mnemonic == "jcxz" || instruction.mnemonic == "jecxz" ||
                          instruction.mnemonic == "jrcxz";
    if (branches && instruction.operands[0].kind == Operand::Kind::Immediate)
      branch_targets.insert(static_cast<std::uint64_t>(instruction.operands[0].immediate_value));
  }
  for (const auto& [address, instruction] : function.instructions) {
    if (function.block_starts.count(address) != 0 || branch_targets.count(address) != 0) {
      ir::Statement label;
      label.kind = ir::StatementKind::Label;
      label.label = "label_" + std::to_string(address);
      label.address_of_instruction = address;
      lifted.statements.push_back(std::move(label));
    }
    {
      // 48% of the generated statements are this line and its content is a fixed
      // template, so it is the highest-value single migration. The address and the
      // disassembly are kept as separate fields rather than as pre-joined text, so
      // a backend is not required to reproduce the C++ spelling.
      ir::Statement trace;
      trace.kind = ir::StatementKind::Trace;
      trace.instruction_address = format_hex(address);
      trace.text = instruction.text;
      trace.address_of_instruction = address;
      lifted.statements.push_back(std::move(trace));
    }
    emit_instruction(instruction, function, lifted);
  }
  {
    ir::Statement result;
    result.kind = ir::StatementKind::Return;
    lifted.statements.push_back(std::move(result));
  }

  return lifted;
}

std::string X86_64Lifter::lift_function(const RecoveredFunction& function) const {
  const auto lifted = lift_function_to_ir(function);
  std::string output;
  output += "static void " + lifted.name + "(GuestContext* context) {\n";
  output += ir::render_function(lifted);
  output += "}\n";
  return output;
}

// How much of the recovered program is described as statements rather than as
// text the backend passes through. Reported so that the migration is a measured
// fraction rather than an impression.
ir::StatementCensus X86_64Lifter::statement_census() const {
  ir::Module module;
  for (const auto& [address, function] : discovery_.functions()) {
    if (native_overrides_.count(address) != 0 || stubbed_functions_.count(address) != 0) continue;
    try {
      module.functions.push_back(lift_function_to_ir(function));
    } catch (const LiftError&) {
      // A function that does not lift contributes nothing; the coverage census is
      // what reports those.
    }
  }
  return ir::census(module);
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
      // The census only asks whether an instruction lifts, so the statements are
      // built and discarded. It walks every recovered instruction, so this
      // deliberately does not render them.
      ir::Function scratch;
      try {
        emit_instruction(instruction, function, scratch);
        ++result.lifted_instructions;
      } catch (const LiftError& error) {
        // Classify this instruction and keep going: the point of the census is
        // the whole program, not the first failure.
        ++result.unsupported_instructions;
        // Key on the same bare mnemonic the lift diagnostic names, so the class
        // name and its reason never disagree for an unsupported `lock`/`rep` form.
        const auto classification = parse_mnemonic(instruction.mnemonic).mnemonic;
        auto& entry = by_mnemonic[classification];
        if (entry.occurrences == 0) {
          entry.mnemonic = classification;
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
