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

  // Function pointers in initialised data that carry no base relocation. A PE32
  // image with a fixed load address frequently has no relocation for an internal
  // pointer, so the relocation pass above misses them, and recursive descent
  // cannot reach them either because nothing calls them directly -- the pointer
  // is the only reference. Scan the data sections for 32-bit values that land on
  // a run of decodable instructions; random data that happens to look like an
  // address rarely decodes as eight valid instructions in a row.
  // A pointer is only believed to be a function entry when the byte immediately
  // before it ends the previous routine: x86 decodes almost any byte sequence, so
  // "eight instructions decode here" alone accepts a great deal of data, and the
  // resulting phantom functions then fail to lift.
  // A pointer is only believed to be a function entry when the bytes before it
  // end the previous routine. Inside an executable section a single padding byte
  // is not enough evidence -- one nop appears inside ordinary code all the time --
  // so a code section requires either a return or jump, or a run of at least two
  // padding bytes. In a data section a single terminator byte is already strong.
  const auto ends_a_routine = [this](std::uint32_t rva, bool in_code_section) {
    if (rva == 0) return true;  // the very start of a section
    const auto previous = executable_.read_rva(rva - 1, 1);
    if (previous.empty()) return false;
    switch (previous[0]) {
      case 0xc3:  // ret
      case 0xcb:  // retf
      case 0xe9:  // jmp rel32
      case 0xeb:  // jmp rel8
        return true;
      case 0xcc:  // int3 padding
      case 0x90:  // nop padding
      case 0x00: {  // zero padding
        if (!in_code_section) return true;
        if (rva < 2) return true;
        // Alignment padding is usually a multi-byte nop, so what precedes the
        // final padding byte is often a prefix byte rather than another nop:
        // `66 90` is one two-byte nop, not a nop after an operand-size prefix.
        // Accept a run of padding and prefix bytes instead of two literal nops.
        const auto earlier = executable_.read_rva(rva - 2, 1);
        if (earlier.empty()) return false;
        switch (earlier[0]) {
          case 0x90:
          case 0xcc:
          case 0x00:
          case 0x66:  // operand-size prefix
          case 0x67:  // address-size prefix
          case 0xf2:
          case 0xf3:  // rep prefixes
          case 0x2e:
          case 0x36:
          case 0x3e:
          case 0x26:
          case 0x64:
          case 0x65:  // segment prefixes
            return true;
          default:
            return false;
        }
      }
      default:
        return false;
    }
  };
  // A candidate entry must satisfy TWO kinds of evidence, and the second is what
  // makes this usable. Eight decodable instructions in a row alone is far too weak:
  // x86 decodes almost any byte sequence, and a `lea reg, [rip+disp]` seed that
  // accepted eight instructions was measured to invent 1,851 non-functions in one
  // real application, multiplying its unsupported-instruction count by twenty-five.
  // The routine boundary is the evidence that a candidate is a function rather than
  // data that happens to decode.
  const auto decodes_as_code = [this, &ends_a_routine](std::uint64_t target, bool in_code_section) {
    if (target < executable_.image_base) return false;
    auto address = static_cast<std::uint32_t>(target - executable_.image_base);
    if (!ends_a_routine(address, in_code_section)) return false;
    for (int index = 0; index < 8; ++index) {
      if (!contains_code(address)) return false;
      const auto instruction = decode(address);
      if (instruction.size == 0 || instruction.mnemonic.empty()) return false;
      address += static_cast<std::uint32_t>(instruction.size);
    }
    return true;
  };
  // Executable sections are scanned too: a compiler is free to place a function
  // pointer table inside .text, and this one does -- the C runtime's exit table
  // lives there, so skipping code sections missed exactly the entries the
  // program calls on the way out.
  for (const auto& section : executable_.sections) {
    if (section.raw_size < 4) continue;
    const bool in_code_section = section.is_executable();
    for (std::uint32_t offset = 0; offset + 4 <= section.raw_size; offset += 4) {
      const auto value = executable_.read_u32(section.virtual_address + offset);
      if (!value || !decodes_as_code(*value, in_code_section)) continue;
      pending_entries.push_back(*value);
    }
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
