#include "core/ir/ir.hpp"

namespace recomp::ir {

std::vector<Operation> lift(const discovery::Analysis& analysis) {
  std::vector<Operation> operations;
  const unsigned pointer_width = analysis.architecture == "x64" ? 64U : 32U;
  for (const auto& instruction : analysis.instructions) {
    std::string opcode;
    if (instruction.mnemonic == "mov") opcode = "write_register";
    else if (instruction.mnemonic == "add" || instruction.mnemonic == "sub" ||
             instruction.mnemonic == "add_rsp" || instruction.mnemonic == "sub_rsp") opcode = "arithmetic_with_eflags";
    else if (instruction.mnemonic == "cmp") opcode = "compare_with_eflags";
    else if (instruction.mnemonic == "call") opcode = "direct_call";
    else if (instruction.mnemonic == "ret") opcode = "return";
    else if (instruction.mnemonic == "jmp" || instruction.mnemonic == "jb" ||
             instruction.mnemonic == "jz" || instruction.mnemonic == "jnz") opcode = "branch";
    else opcode = "no_operation";
    const bool pointer_sized = instruction.mnemonic == "ret" || instruction.mnemonic == "call" ||
                               instruction.mnemonic == "add_rsp" || instruction.mnemonic == "sub_rsp";
    operations.push_back({opcode, pointer_sized ? pointer_width : 32U, instruction.rva});
  }
  return operations;
}

}  // namespace recomp::ir
