#include "core/binary/pe.hpp"

#include "core/common/sha256.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace recomp::binary {
namespace {
class Reader {
 public:
  explicit Reader(std::vector<unsigned char> bytes) : bytes_(std::move(bytes)) {}
  std::uint16_t u16(std::size_t offset) const { require(offset, 2); return static_cast<std::uint16_t>(bytes_[offset] | (bytes_[offset + 1] << 8U)); }
  std::uint32_t u32(std::size_t offset) const { require(offset, 4); return static_cast<std::uint32_t>(bytes_[offset]) | (static_cast<std::uint32_t>(bytes_[offset + 1]) << 8U) | (static_cast<std::uint32_t>(bytes_[offset + 2]) << 16U) | (static_cast<std::uint32_t>(bytes_[offset + 3]) << 24U); }
  const std::vector<unsigned char>& bytes() const { return bytes_; }
  void require(std::size_t offset, std::size_t count) const { if (offset > bytes_.size() || count > bytes_.size() - offset) throw ParseError{"truncated PE structure"}; }
 private: std::vector<unsigned char> bytes_;
};

std::vector<unsigned char> read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw ParseError{"cannot open input file"};
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
std::string section_name(const Reader& reader, std::size_t offset) {
  reader.require(offset, 8); std::string name;
  for (std::size_t index = 0; index < 8 && reader.bytes()[offset + index] != 0; ++index) name += static_cast<char>(reader.bytes()[offset + index]);
  return name;
}
std::string cstring_at(const Reader& reader, std::size_t offset) {
  std::string value;
  for (;;) {
    reader.require(offset, 1);
    const auto byte = reader.bytes()[offset++];
    if (byte == 0) return value;
    value += static_cast<char>(byte);
  }
}
}

PeImage parse_pe(const std::filesystem::path& path) {
  Reader reader{read_file(path)};
  if (reader.u16(0) != 0x5a4d) throw ParseError{"not a DOS MZ executable"};
  const auto pe_offset = reader.u32(0x3c);
  if (reader.u32(pe_offset) != 0x00004550) throw ParseError{"missing PE signature"};
  const auto coff = static_cast<std::size_t>(pe_offset) + 4;
  const auto machine = reader.u16(coff);
  const auto section_count = reader.u16(coff + 2);
  const auto optional_size = reader.u16(coff + 16);
  const auto optional = coff + 20;
  const auto magic = reader.u16(optional);
  if (magic != 0x10b && magic != 0x20b) throw ParseError{"unsupported PE optional-header format"};
  if ((magic == 0x10b && machine != 0x14c) || (magic == 0x20b && machine != 0x8664)) throw ParseError{"PE machine and optional header disagree"};
  if (optional_size < (magic == 0x10b ? 96 : 112)) throw ParseError{"truncated PE optional header"};
  PeImage image;
  image.format = magic == 0x10b ? "PE32" : "PE32+";
  image.architecture = machine == 0x14c ? "x86" : "x64";
  image.entry_rva = reader.u32(optional + 16);
  image.sha256 = common::sha256(reader.bytes());
  const auto section_offset = optional + optional_size;
  for (std::size_t index = 0; index < section_count; ++index) {
    const auto offset = section_offset + index * 40;
    reader.require(offset, 40);
    image.sections.push_back({section_name(reader, offset), reader.u32(offset + 12), reader.u32(offset + 8), reader.u32(offset + 20), reader.u32(offset + 16), reader.u32(offset + 36)});
  }
  const auto rva_to_offset = [&image](std::uint32_t rva) { return file_offset_for_rva(image, rva); };
  const auto directory_offset = optional + (magic == 0x10b ? 96 : 112);
  const auto import_rva = reader.u32(directory_offset + 8);
  const auto import_size = reader.u32(directory_offset + 12);
  if (import_rva != 0 || import_size != 0) {
    if (import_rva == 0 || import_size < 20) throw ParseError{"malformed import directory"};
    const auto directory = rva_to_offset(import_rva);
    for (std::size_t offset = directory; ; offset += 20) {
      reader.require(offset, 20);
      const auto original_first_thunk = reader.u32(offset);
      const auto timestamp = reader.u32(offset + 4);
      const auto forwarder_chain = reader.u32(offset + 8);
      const auto name_rva = reader.u32(offset + 12);
      const auto first_thunk = reader.u32(offset + 16);
      if (original_first_thunk == 0 && timestamp == 0 && forwarder_chain == 0 && name_rva == 0 && first_thunk == 0) break;
      image.imports.push_back(cstring_at(reader, rva_to_offset(name_rva)));
      if (offset - directory + 40 > import_size) throw ParseError{"unterminated import directory"};
    }
  }
  image.file_bytes = reader.bytes();
  return image;
}

std::size_t file_offset_for_rva(const PeImage& image, std::uint32_t rva) {
  for (const auto& section : image.sections) {
    const auto span = std::max(section.virtual_size, section.raw_size);
    if (rva >= section.rva && rva - section.rva < span) return section.raw_offset + (rva - section.rva);
  }
  throw ParseError{"RVA does not map to a file section"};
}

}  // namespace recomp::binary
