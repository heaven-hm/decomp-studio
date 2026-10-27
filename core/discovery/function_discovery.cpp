#include "core/discovery/function_discovery.hpp"

#include <capstone/x86.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace recomp::discovery {
namespace {

const std::set<std::string> kConditionalBranches = {
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
    "jp", "jnp", "jl", "jge", "jle", "jg", "jrcxz", "jecxz", "loop", "loope", "loopne"};

const std::set<std::string> kTerminators = {"ret", "retf", "iret", "iretd", "iretq", "hlt", "ud2", "int3"};

std::string register_name(csh handle, unsigned int register_id) {
  if (register_id == X86_REG_INVALID) return {};
  const char* name = cs_reg_name(handle, register_id);
  return name != nullptr ? name : std::string{};
}

}  // namespace

FunctionDiscovery::FunctionDiscovery(const binary::PortableExecutable& executable) : executable_(executable) {
  // Decoding mode follows the PE machine type: PE32 is 32-bit x86, PE32+ is
  // 64-bit x86. Operand widths, branch targets and addressing all depend on it.
  const auto decode_mode = executable_.is_64_bit ? CS_MODE_64 : CS_MODE_32;
  if (cs_open(CS_ARCH_X86, decode_mode, &capstone_handle_) != CS_ERR_OK)
    throw std::runtime_error("failed to initialise capstone");
  cs_option(capstone_handle_, CS_OPT_DETAIL, CS_OPT_ON);
  for (const auto* section : executable_.executable_sections())
    executable_ranges_.emplace_back(section->virtual_address, section->end_virtual_address());
  for (const auto& imported : executable_.imports)
    import_slots_[imported.import_address_table_rva] = &imported;
}

bool FunctionDiscovery::contains_code(std::uint32_t rva) const {
  for (const auto& range : executable_ranges_)
    if (rva >= range.first && rva < range.second) return true;
  return false;
}

const binary::ImportedSymbol* FunctionDiscovery::import_for_slot(std::uint32_t slot_rva) const {
  const auto iterator = import_slots_.find(slot_rva);
  return iterator == import_slots_.end() ? nullptr : iterator->second;
}

DecodedInstruction FunctionDiscovery::decode(std::uint32_t rva) const {
  DecodedInstruction decoded;
  if (!contains_code(rva)) return decoded;
  const auto bytes = executable_.read_rva(rva, 16);
  cs_insn* instruction = nullptr;
  const auto count = cs_disasm(capstone_handle_, bytes.data(), bytes.size(), executable_.image_base + rva, 1, &instruction);
  if (count == 0) return decoded;

  decoded.address = instruction->address;
  decoded.size = instruction->size;
  decoded.mnemonic = instruction->mnemonic;
  decoded.text = std::string(instruction->mnemonic) + " " + instruction->op_str;
  std::memcpy(decoded.raw_bytes.data(), instruction->bytes, std::min<std::size_t>(16, instruction->size));

  const auto& detail = instruction->detail->x86;
  for (std::uint8_t index = 0; index < detail.op_count; ++index) {
    const auto& source = detail.operands[index];
    Operand operand;
    operand.size_in_bytes = source.size;
    if (source.type == X86_OP_REG) {
      operand.kind = Operand::Kind::Register;
      operand.register_name = register_name(capstone_handle_, source.reg);
    } else if (source.type == X86_OP_IMM) {
      operand.kind = Operand::Kind::Immediate;
      operand.immediate_value = source.imm;
    } else if (source.type == X86_OP_MEM) {
      operand.kind = Operand::Kind::Memory;
      operand.segment_register_name = register_name(capstone_handle_, source.mem.segment);
      operand.base_register_name = register_name(capstone_handle_, source.mem.base);
      operand.index_register_name = register_name(capstone_handle_, source.mem.index);
      operand.scale = source.mem.scale;
      operand.displacement = source.mem.disp;
    }
    decoded.operands.push_back(operand);
  }
  cs_free(instruction, 1);
  return decoded;
}

std::optional<std::uint64_t> FunctionDiscovery::direct_branch_target(const DecodedInstruction& instruction) const {
  if (instruction.operands.empty()) return std::nullopt;
  const auto& operand = instruction.operands.front();
  if (operand.kind != Operand::Kind::Immediate) return std::nullopt;
  return static_cast<std::uint64_t>(operand.immediate_value);
}

void FunctionDiscovery::discover() {
  std::vector<std::uint64_t> pending_entries;
  if (executable_.entry_point_rva != 0 && contains_code(executable_.entry_point_rva))
    pending_entries.push_back(executable_.image_base + executable_.entry_point_rva);
  for (const auto& exported : executable_.exports)
    if (contains_code(exported.rva)) pending_entries.push_back(executable_.image_base + exported.rva);
  for (const auto rva : executable_.tls_callback_rvas)
    if (contains_code(rva)) pending_entries.push_back(executable_.image_base + rva);

  // Function pointers stored in initialised data. A 64-bit or 32-bit base
  // relocation whose stored value points into an executable section is a
  // precise, provenance-backed code pointer (a hand-written function table, a
  // vtable, a callback) that plain recursive descent from the entry point can
  // never reach.
  constexpr std::uint16_t kRelocationHighLow = 3;
  constexpr std::uint16_t kRelocationDir64 = 10;
  for (const auto& relocation : executable_.base_relocations) {
    std::uint64_t target = 0;
    if (relocation.type == kRelocationDir64) {
      const auto value = executable_.read_u64(relocation.rva);
      if (!value) continue;
      target = *value;
    } else if (relocation.type == kRelocationHighLow) {
      const auto value = executable_.read_u32(relocation.rva);
      if (!value) continue;
      target = *value;
    } else {
      continue;
    }
    if (target >= executable_.image_base &&
        contains_code(static_cast<std::uint32_t>(target - executable_.image_base)))
      pending_entries.push_back(target);
  }

  std::set<std::uint64_t> known_entries(pending_entries.begin(), pending_entries.end());
  constexpr std::size_t kMaximumInstructions = 2'000'000;
  std::size_t recovered_instruction_count = 0;

  while (!pending_entries.empty()) {
    const auto entry = pending_entries.back();
    pending_entries.pop_back();
    const auto entry_rva = static_cast<std::uint32_t>(entry - executable_.image_base);
    if (!contains_code(entry_rva) || functions_.count(entry) != 0) continue;

    RecoveredFunction function;
    function.entry = entry;
    function.block_starts.insert(entry);

    std::vector<std::uint64_t> pending_blocks{entry};
    std::set<std::uint64_t> visited_blocks;
    while (!pending_blocks.empty() && recovered_instruction_count < kMaximumInstructions) {
      auto address = pending_blocks.back();
      pending_blocks.pop_back();
      for (;;) {
        const auto address_rva = static_cast<std::uint32_t>(address - executable_.image_base);
        if (!contains_code(address_rva) || function.instructions.count(address) != 0 ||
            visited_blocks.count(address) != 0)
          break;
        visited_blocks.insert(address);
        const auto instruction = decode(address_rva);
        if (instruction.size == 0) break;
        function.instructions.emplace(address, instruction);
        ++recovered_instruction_count;

        const auto next_address = address + instruction.size;
        if (instruction.mnemonic == "call") {
          const auto target = direct_branch_target(instruction);
          if (target && contains_code(static_cast<std::uint32_t>(*target - executable_.image_base))) {
            if (known_entries.insert(*target).second) pending_entries.push_back(*target);
          }
          address = next_address;
          continue;
        }
        if (kConditionalBranches.count(instruction.mnemonic) != 0) {
          const auto target = direct_branch_target(instruction);
          if (target && contains_code(static_cast<std::uint32_t>(*target - executable_.image_base))) {
            function.block_starts.insert(*target);
            pending_blocks.push_back(*target);
          }
          address = next_address;
          continue;
        }
        if (instruction.mnemonic == "jmp") {
          const auto target = direct_branch_target(instruction);
          if (target && contains_code(static_cast<std::uint32_t>(*target - executable_.image_base))) {
            if (known_entries.count(*target) != 0) {
              function.tail_call_targets.insert(*target);
            } else {
              function.block_starts.insert(*target);
              pending_blocks.push_back(*target);
            }
          }
          break;
        }
        if (kTerminators.count(instruction.mnemonic) != 0) break;
        address = next_address;
      }
    }
    functions_.emplace(entry, std::move(function));
  }
}

}  // namespace recomp::discovery
