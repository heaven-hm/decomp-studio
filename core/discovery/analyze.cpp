#include "core/discovery/analyze.hpp"

#include <cstdint>

namespace recomp::discovery {
namespace {
std::uint32_t u32(const std::vector<unsigned char>& bytes, std::size_t offset) {
  if (offset + 4 > bytes.size()) throw binary::ParseError{"truncated instruction immediate"};
  return static_cast<std::uint32_t>(bytes[offset]) | (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) | (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
}
}

Analysis analyze_entry(const binary::PeImage& image) {
  const auto entry_offset = binary::file_offset_for_rva(image, image.entry_rva);
  Analysis output{image.architecture, {}, 1};
  std::size_t offset = entry_offset;
  std::uint32_t rva = image.entry_rva;
  for (std::size_t decoded = 0; decoded < 128; ++decoded) {
    if (offset >= image.file_bytes.size()) throw binary::ParseError{"entry code reaches end of file"};
    const auto opcode = image.file_bytes[offset];
    std::string mnemonic;
    std::size_t size = 1;
    bool ends_block = false;
    if (opcode >= 0xb8 && opcode <= 0xbf) { (void)u32(image.file_bytes, offset + 1); mnemonic = "mov"; size = 5; }
    else if (opcode == 0x05) { (void)u32(image.file_bytes, offset + 1); mnemonic = "add"; size = 5; }
    else if (opcode == 0x2d) { (void)u32(image.file_bytes, offset + 1); mnemonic = "sub"; size = 5; }
    else if (opcode == 0x3d) { (void)u32(image.file_bytes, offset + 1); mnemonic = "cmp"; size = 5; }
    else if (opcode == 0xc3) { mnemonic = "ret"; ends_block = true; }
    else if (opcode == 0x90) mnemonic = "nop";
    else if (opcode == 0xe8) { (void)u32(image.file_bytes, offset + 1); mnemonic = "call"; size = 5; }
    else if (opcode == 0xe9) { (void)u32(image.file_bytes, offset + 1); mnemonic = "jmp"; size = 5; ends_block = true; }
    else if (opcode == 0x74 || opcode == 0x75) { if (offset + 2 > image.file_bytes.size()) throw binary::ParseError{"truncated conditional branch"}; mnemonic = opcode == 0x74 ? "jz" : "jnz"; size = 2; ++output.block_count; }
    else throw binary::ParseError{"unsupported x86/x64 opcode 0x" + std::to_string(opcode) + " at entry-reachable address"};
    output.instructions.push_back({mnemonic, rva, size});
    offset += size; rva += static_cast<std::uint32_t>(size);
    if (ends_block) return output;
  }
  throw binary::ParseError{"analysis instruction limit reached without terminal control flow"};
}

}  // namespace recomp::discovery
