#include "core/discovery/function_discovery.hpp"

#include <capstone/x86.h>

#include <algorithm>
#include <cstring>
#include <limits>
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

  const auto register_family = [](const std::string& name) -> std::string {
    if (name == "rax" || name == "eax" || name == "ax" || name == "al" || name == "ah") return "a";
    if (name == "rbx" || name == "ebx" || name == "bx" || name == "bl" || name == "bh") return "b";
    if (name == "rcx" || name == "ecx" || name == "cx" || name == "cl" || name == "ch") return "c";
    if (name == "rdx" || name == "edx" || name == "dx" || name == "dl" || name == "dh") return "d";
    for (const auto* family : {"si", "di", "bp", "sp"})
      if (name == std::string("r") + family || name == std::string("e") + family || name == family ||
          name == std::string(family) + "l") return family;
    if (name.size() >= 2 && name[0] == 'r' && name[1] >= '8' && name[1] <= '9')
      return name.substr(0, name.find_first_not_of("0123456789", 1));
    return name;
  };

  // Relative switch tables emitted by MSVC and MinGW use a three-instruction
  // sequence: MOVSXD an indexed 32-bit offset, ADD the table base, then JMP the
  // resulting register. IGI Recomp's Analyzer.find_jump_table / _table_bound
  // supplies the bounded table walk used here; this extends that pattern to the
  // x64 relative-offset form (`movsxd; add base; jmp reg`).
  const auto relative_jump_table_targets = [this, &register_family](const RecoveredFunction& function,
                                                                     std::uint64_t jump_address)
      -> std::vector<std::uint64_t> {
    std::vector<const DecodedInstruction*> previous;
    auto cursor = jump_address;
    auto iterator = function.instructions.lower_bound(cursor);
    while (iterator != function.instructions.begin() && previous.size() < 24) {
      --iterator;
      if (iterator->first + iterator->second.size != cursor) break;
      previous.push_back(&iterator->second);
      cursor = iterator->first;
    }
    if (previous.size() < 3) return {};
    const auto& jump = function.instructions.at(jump_address);
    if (jump.operands.empty() || jump.operands[0].kind != Operand::Kind::Register) return {};
    const auto jump_register = register_family(jump.operands[0].register_name);

    for (std::size_t add_index = 0; add_index < std::min<std::size_t>(previous.size(), 2); ++add_index) {
      const auto& add = *previous[add_index];
      if (add.mnemonic != "add" || add.operands.size() < 2 ||
          add.operands[0].kind != Operand::Kind::Register || add.operands[1].kind != Operand::Kind::Register ||
          register_family(add.operands[0].register_name) != jump_register)
        continue;
      const auto base_register = add.operands[1].register_name;
      const auto table_index_register = add.operands[0].register_name;
      std::optional<std::uint64_t> table_address;
      std::optional<std::string> bound_input_register;
      for (std::size_t index = add_index + 1; index < previous.size(); ++index) {
        const auto& instruction = *previous[index];
        if (instruction.mnemonic == "movsxd" && instruction.operands.size() >= 2 &&
            instruction.operands[0].kind == Operand::Kind::Register &&
            instruction.operands[1].kind == Operand::Kind::Memory &&
            register_family(instruction.operands[0].register_name) == jump_register &&
            register_family(instruction.operands[1].base_register_name) == register_family(base_register) &&
            instruction.operands[1].scale == 4 && !instruction.operands[1].index_register_name.empty()) {
          const auto index_register = instruction.operands[1].index_register_name;
          for (std::size_t source_index = index + 1; source_index < previous.size(); ++source_index) {
            const auto& source = *previous[source_index];
            if (source.mnemonic == "movzx" && source.operands.size() >= 2 &&
                source.operands[0].kind == Operand::Kind::Register &&
                source.operands[1].kind == Operand::Kind::Register &&
                register_family(source.operands[0].register_name) == register_family(index_register)) {
              bound_input_register = source.operands[1].register_name;
              break;
            }
          }
        }
        if (instruction.mnemonic == "lea" && instruction.operands.size() >= 2 &&
            instruction.operands[0].kind == Operand::Kind::Register &&
            instruction.operands[1].kind == Operand::Kind::Memory &&
            instruction.operands[1].base_register_name == "rip" &&
            register_family(instruction.operands[0].register_name) == register_family(base_register)) {
          const auto target = static_cast<std::int64_t>(instruction.address + instruction.size) +
                              instruction.operands[1].displacement;
          if (target >= 0) table_address = static_cast<std::uint64_t>(target);
        }
      }
      if (!table_address || !bound_input_register) continue;

      std::optional<std::uint32_t> entry_count;
      for (const auto* instruction : previous) {
        if (instruction->mnemonic != "cmp" || instruction->operands.size() < 2 ||
            instruction->operands[0].kind != Operand::Kind::Register ||
            instruction->operands[1].kind != Operand::Kind::Immediate ||
            register_family(instruction->operands[0].register_name) != register_family(*bound_input_register))
          continue;
        const auto maximum_index = instruction->operands[1].immediate_value;
        if (maximum_index >= 0 && maximum_index < 256)
          entry_count = static_cast<std::uint32_t>(maximum_index) + 1;
        break;
      }
      if (!entry_count) continue;

      std::vector<std::uint64_t> targets;
      for (std::uint32_t index = 0; index < *entry_count; ++index) {
        const auto offset = executable_.read_u32(static_cast<std::uint32_t>(*table_address - executable_.image_base) +
                                                 index * 4);
        if (!offset) break;
        const auto relative = static_cast<std::int32_t>(*offset);
        const auto target = static_cast<std::int64_t>(*table_address) + relative;
        if (target < static_cast<std::int64_t>(executable_.image_base) ||
            !contains_code(static_cast<std::uint32_t>(target - static_cast<std::int64_t>(executable_.image_base))))
          continue;
        targets.push_back(static_cast<std::uint64_t>(target));
      }
      std::sort(targets.begin(), targets.end());
      targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
      if (!targets.empty()) return targets;
    }
    return {};
  };
  // JUMP TABLES. A switch compiles to a table of 32-bit RVAs that a `jmp reg` reaches
  // through `mov reg32, [base + index*4 + disp]` / `add reg, base` / `jmp reg`. The table
  // lives in a DATA section, so the relocation and data-pointer scans above do not see
  // its entries as code addresses: they are small RVAs, not image-base pointers. The
  // targets are real code and a program that reaches one dies with "indirect jump to
  // unmapped guest address" -- which is what `notepad.exe` does at 0x140028109, an address
  // that is entry 6 of a table at RVA 0x37118.
  //
  // The table address is `base + disp`, and `base` is a register whose value is not known
  // statically. The image base is tried, because that is what the compiler puts there in
  // practice (the register dump at the failure shows r10 = 0x140000000). The guess is
  // VALIDATED before anything is added: every entry must be an in-image code address that
  // decodes, and the run must be long enough to be a table rather than coincidence. If the
  // validation fails, nothing is added -- the heuristic fails closed, which is the
  // property the `lea` seed did not have when it invented 1,851 functions.
  {
    const auto image_base = executable_.image_base;
    for (const auto& section : executable_.sections) {
      if (!section.is_executable()) continue;
      for (std::uint32_t offset = 0; offset + 10 <= section.raw_size; ++offset) {
        // `mov r32, [base + index*4 + disp32]` -- opcode 8B with a SIB byte and a
        // 32-bit displacement, which is what a jump table load looks like.
        if (executable_.read_rva(section.virtual_address + offset, 1) != std::vector<std::uint8_t>{0x8b})
          continue;
        const auto modrm = executable_.read_rva(section.virtual_address + offset + 1, 1);
        if (modrm.empty()) continue;
        // The `rm` field is 0b100 (SIB) and `mod` must not be 0b11 (register). Masking
        // with 0xc7 -- which the first version did -- also tests the `reg` field, so it
        // matched almost nothing: the real instruction here is `47 8b 9c 9a ...`, whose
        // modrm is 0x9c, and 0x9c & 0xc7 is 0x84.
        if ((modrm[0] & 0x07) != 0x04 || (modrm[0] & 0xc0) == 0xc0) continue;
        const auto sib = executable_.read_rva(section.virtual_address + offset + 2, 1);
        if (sib.empty() || (sib[0] & 0xc0) != 0x80) continue;  // scale 4 (a 4-byte table)
        if ((sib[0] & 0x07) == 0x05) continue;                // no base register
        const auto displacement = executable_.read_u32(section.virtual_address + offset + 3);
        if (!displacement) continue;
        // The displacement IS the table's RVA. Adding the image base to it was wrong and
        // looked right: 0x140000000 truncated to 32 bits is 0x40000000, not 0, so the
        // table was computed as 0x40037118 instead of 0x37118 and every lookup missed.
        const auto table_rva = *displacement;
        // The table lives in DATA. (The first version of this wrote the test backwards and
        // skipped every candidate, which looked like the heuristic simply not matching.)
        if (contains_code(table_rva)) continue;
        std::vector<std::uint64_t> candidates;
        for (int index = 0; index < 512; ++index) {
          const auto entry = executable_.read_u32(table_rva + static_cast<std::uint32_t>(index) * 4);
          if (!entry || !contains_code(*entry)) break;
          candidates.push_back(image_base + *entry);
        }
        // A table, not a coincidence: at least four entries, every one in an executable
        // section, and every one decoding as instructions.
        //
        // `decodes_as_code` is deliberately NOT used here, and the reason is the whole
        // point of a jump table: its entries are CONSECUTIVE blocks, so the byte before
        // entry N is the last byte of block N-1 and `ends_a_routine` -- the routine-
        // boundary evidence that makes the data-pointer scan safe -- rejects every one of
        // them. The table is the evidence instead: a run of four or more in-image
        // addresses that all decode is not something data produces by accident, and the
        // table's own structure is what is being trusted.
        if (candidates.size() < 4) continue;
        const bool all_decode = std::all_of(candidates.begin(), candidates.end(),
                                            [&](std::uint64_t target) {
                                              auto address = static_cast<std::uint32_t>(target - image_base);
                                              for (int index = 0; index < 4; ++index) {
                                                if (!contains_code(address)) return false;
                                                const auto instruction = decode(address);
                                                if (instruction.size == 0 || instruction.mnemonic.empty())
                                                  return false;
                                                address += static_cast<std::uint32_t>(instruction.size);
                                              }
                                              return true;
                                            });
        if (!all_decode) continue;
        for (const auto target : candidates) pending_entries.push_back(target);
      }
    }
  }

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

        // Recover address-taken functions as a second source of entries. This
        // follows the bounded immediate-pointer pass in IGI Recomp's
        // tools/recomp/analyze.py (MIT, commit 278eaf6394f7f42c7de6cffef2cf982154f59899),
        // and also resolves RIP-relative LEA operands used by x64 callback APIs
        // such as pthread_once. The same boundary and decode checks used for
        // data pointers reject ordinary constants and most mid-function labels.
        std::optional<std::uint64_t> address_taken_target;
        for (const auto& operand : instruction.operands) {
          if (operand.kind == Operand::Kind::Immediate && instruction.mnemonic != "call" &&
              instruction.mnemonic != "jmp") {
            const auto value = static_cast<std::uint64_t>(operand.immediate_value);
            if (value >= executable_.image_base &&
                value - executable_.image_base <= std::numeric_limits<std::uint32_t>::max())
              address_taken_target = value;
          } else if (operand.kind == Operand::Kind::Memory && operand.base_register_name == "rip" &&
                     operand.index_register_name.empty() && instruction.mnemonic == "lea") {
            const auto next = instruction.address + instruction.size;
            const auto target = static_cast<std::int64_t>(next) + operand.displacement;
            if (target >= static_cast<std::int64_t>(executable_.image_base) &&
                static_cast<std::uint64_t>(target) - executable_.image_base <=
                    std::numeric_limits<std::uint32_t>::max())
              address_taken_target = static_cast<std::uint64_t>(target);
          }
        }
        if (address_taken_target && decodes_as_code(*address_taken_target, true) &&
            known_entries.insert(*address_taken_target).second)
          pending_entries.push_back(*address_taken_target);

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
          } else {
            for (const auto case_target : relative_jump_table_targets(function, address)) {
              function.block_starts.insert(case_target);
              pending_blocks.push_back(case_target);
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
