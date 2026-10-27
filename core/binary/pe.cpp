#include <algorithm>
#include "core/binary/pe.hpp"

#include <cctype>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace recomp::binary {
namespace {

std::uint16_t read_little_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset + 2 > bytes.size()) throw ParseError("truncated PE structure");
  return static_cast<std::uint16_t>(bytes[offset] | (bytes[offset + 1] << 8u));
}

std::uint32_t read_little_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset + 4 > bytes.size()) throw ParseError("truncated PE structure");
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 8u) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16u) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24u);
}

std::uint64_t read_little_u64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset + 8 > bytes.size()) throw ParseError("truncated PE structure");
  std::uint64_t value = 0;
  for (int index = 7; index >= 0; --index) value = (value << 8u) | bytes[offset + index];
  return value;
}

std::vector<std::uint8_t> read_whole_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw ParseError("cannot open input file: " + path.string());
  return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string section_name(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::string name;
  for (std::size_t index = 0; index < 8; ++index) {
    const auto character = bytes[offset + index];
    if (character == 0) break;
    name.push_back(static_cast<char>(character));
  }
  return name;
}

constexpr std::uint16_t kDirectoryImport = 1;
constexpr std::uint16_t kDirectoryExport = 0;
constexpr std::uint16_t kDirectoryBaseRelocation = 5;
constexpr std::uint16_t kDirectoryTls = 9;

}  // namespace

const Section* PortableExecutable::section_containing(std::uint32_t rva) const {
  for (const auto& section : sections) {
    if (rva >= section.virtual_address && rva < section.end_virtual_address()) return &section;
  }
  return nullptr;
}

std::optional<std::uint32_t> PortableExecutable::file_offset_for_rva(std::uint32_t rva) const {
  const auto* section = section_containing(rva);
  if (section == nullptr) {
    if (rva < size_of_headers && rva < file_bytes.size()) return rva;
    return std::nullopt;
  }
  const auto delta = rva - section->virtual_address;
  if (delta >= section->raw_size) return std::nullopt;
  return section->raw_offset + delta;
}

std::vector<std::uint8_t> PortableExecutable::read_rva(std::uint32_t rva, std::size_t count) const {
  std::vector<std::uint8_t> output(count, 0);
  const auto* section = section_containing(rva);
  if (section == nullptr) {
    if (rva < size_of_headers && rva + count <= file_bytes.size())
      std::memcpy(output.data(), file_bytes.data() + rva, count);
    return output;
  }
  const auto delta = rva - section->virtual_address;
  if (delta >= section->raw_size) return output;
  const auto available = std::min<std::size_t>(count, section->raw_size - delta);
  const auto source = section->raw_offset + delta;
  if (source + available <= file_bytes.size())
    std::memcpy(output.data(), file_bytes.data() + source, available);
  return output;
}

std::optional<std::uint16_t> PortableExecutable::read_u16(std::uint32_t rva) const {
  const auto* section = section_containing(rva);
  if (section == nullptr && rva + 2 > file_bytes.size()) return std::nullopt;
  const auto bytes = read_rva(rva, 2);
  return static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8u));
}

std::optional<std::uint32_t> PortableExecutable::read_u32(std::uint32_t rva) const {
  const auto bytes = read_rva(rva, 4);
  return static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8u) |
         (static_cast<std::uint32_t>(bytes[2]) << 16u) | (static_cast<std::uint32_t>(bytes[3]) << 24u);
}

std::optional<std::uint64_t> PortableExecutable::read_u64(std::uint32_t rva) const {
  const auto bytes = read_rva(rva, 8);
  std::uint64_t value = 0;
  for (int index = 7; index >= 0; --index) value = (value << 8u) | bytes[index];
  return value;
}

std::string PortableExecutable::read_c_string(std::uint32_t rva, std::size_t limit) const {
  std::string value;
  for (std::size_t index = 0; index < limit; ++index) {
    const auto bytes = read_rva(rva + static_cast<std::uint32_t>(index), 1);
    if (bytes[0] == 0) break;
    value.push_back(static_cast<char>(bytes[0]));
  }
  return value;
}

const Section* PortableExecutable::text_section() const {
  for (const auto& section : sections)
    if (section.name == ".text") return &section;
  for (const auto& section : sections)
    if (section.is_executable()) return &section;
  return nullptr;
}

std::vector<const Section*> PortableExecutable::executable_sections() const {
  std::vector<const Section*> output;
  for (const auto& section : sections)
    if (section.is_executable()) output.push_back(&section);
  return output;
}

PortableExecutable PortableExecutable::parse(const std::filesystem::path& path) {
  PortableExecutable executable;
  executable.path = path;
  executable.file_bytes = read_whole_file(path);
  const auto& bytes = executable.file_bytes;
  if (bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z')
    throw ParseError("not a DOS MZ executable");

  const auto pe_offset = read_little_u32(bytes, 0x3c);
  if (pe_offset + 24 > bytes.size() || read_little_u32(bytes, pe_offset) != 0x00004550u)
    throw ParseError("missing PE signature");

  const auto coff_offset = static_cast<std::size_t>(pe_offset) + 4;
  executable.machine = read_little_u16(bytes, coff_offset);
  const auto section_count = read_little_u16(bytes, coff_offset + 2);
  const auto optional_header_size = read_little_u16(bytes, coff_offset + 16);
  const auto characteristics = read_little_u16(bytes, coff_offset + 18);
  executable.is_dynamic_library = (characteristics & 0x2000u) != 0;
  const auto optional_offset = coff_offset + 20;
  const auto optional_magic = read_little_u16(bytes, optional_offset);

  if (optional_magic == 0x10bu) {
    executable.is_64_bit = false;
  } else if (optional_magic == 0x20bu) {
    executable.is_64_bit = true;
  } else {
    throw ParseError("unsupported PE optional header magic");
  }
  if (executable.machine == 0x14c && executable.is_64_bit)
    throw ParseError("machine/optional-header mismatch (x86 with PE32+)");
  if (executable.machine == 0x8664 && !executable.is_64_bit)
    throw ParseError("machine/optional-header mismatch (x64 with PE32)");

  executable.entry_point_rva = read_little_u32(bytes, optional_offset + 16);
  executable.subsystem = read_little_u16(bytes, optional_offset + 68);
  if (executable.is_64_bit) {
    executable.image_base = read_little_u64(bytes, optional_offset + 24);
    executable.size_of_image = read_little_u32(bytes, optional_offset + 56);
    executable.size_of_headers = read_little_u32(bytes, optional_offset + 60);
    executable.size_of_code = read_little_u32(bytes, optional_offset + 4);
  } else {
    executable.image_base = read_little_u32(bytes, optional_offset + 28);
    executable.size_of_image = read_little_u32(bytes, optional_offset + 56);
    executable.size_of_headers = read_little_u32(bytes, optional_offset + 60);
    executable.size_of_code = read_little_u32(bytes, optional_offset + 4);
  }

  const auto section_table_offset = optional_offset + optional_header_size;
  for (std::size_t index = 0; index < section_count; ++index) {
    const auto offset = section_table_offset + index * 40;
    if (offset + 40 > bytes.size()) throw ParseError("truncated section table");
    Section section;
    section.name = section_name(bytes, offset);
    section.virtual_size = read_little_u32(bytes, offset + 8);
    section.virtual_address = read_little_u32(bytes, offset + 12);
    section.raw_size = read_little_u32(bytes, offset + 16);
    section.raw_offset = read_little_u32(bytes, offset + 20);
    section.characteristics = read_little_u32(bytes, offset + 36);
    executable.sections.push_back(section);
  }

  const auto directory_count_offset = executable.is_64_bit ? optional_offset + 108 : optional_offset + 92;
  const auto directory_offset = executable.is_64_bit ? optional_offset + 112 : optional_offset + 96;
  const auto directory_count = std::min<std::uint32_t>(read_little_u32(bytes, directory_count_offset), 16);
  std::vector<std::pair<std::uint32_t, std::uint32_t>> directories;
  for (std::uint32_t index = 0; index < directory_count; ++index) {
    directories.emplace_back(read_little_u32(bytes, directory_offset + index * 8),
                             read_little_u32(bytes, directory_offset + index * 8 + 4));
  }

  const auto directory_rva = [&](std::uint16_t index) -> std::uint32_t {
    return index < directories.size() ? directories[index].first : 0;
  };

  // imports
  const auto import_directory_rva = directory_rva(kDirectoryImport);
  if (import_directory_rva != 0) {
    const auto pointer_size = executable.is_64_bit ? 8u : 4u;
    const auto ordinal_flag = executable.is_64_bit ? 0x8000000000000000ull : 0x80000000ull;
    for (std::uint32_t descriptor_rva = import_directory_rva;; descriptor_rva += 20) {
      const auto original_first_thunk = executable.read_u32(descriptor_rva).value_or(0);
      const auto name_rva = executable.read_u32(descriptor_rva + 12).value_or(0);
      const auto first_thunk = executable.read_u32(descriptor_rva + 16).value_or(0);
      if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) break;
      auto library_name = executable.read_c_string(name_rva);
      for (auto& character : library_name) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
      auto thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;
      auto slot_rva = first_thunk;
      for (;;) {
        const auto thunk_value = executable.is_64_bit ? executable.read_u64(thunk_rva).value_or(0)
                                                      : executable.read_u32(thunk_rva).value_or(0);
        if (thunk_value == 0) break;
        ImportedSymbol imported;
        imported.import_address_table_rva = slot_rva;
        imported.library_name = library_name;
        if ((thunk_value & ordinal_flag) != 0) {
          imported.symbol_name = "#" + std::to_string(thunk_value & 0xffffu);
        } else {
          imported.symbol_name = executable.read_c_string(static_cast<std::uint32_t>(thunk_value) + 2);
        }
        executable.imports.push_back(imported);
        thunk_rva += pointer_size;
        slot_rva += pointer_size;
      }
    }
  }

  // exports
  const auto export_directory_rva = directory_rva(kDirectoryExport);
  if (export_directory_rva != 0) {
    const auto name_count = executable.read_u32(export_directory_rva + 24).value_or(0);
    const auto address_table_rva = executable.read_u32(export_directory_rva + 28).value_or(0);
    const auto name_table_rva = executable.read_u32(export_directory_rva + 32).value_or(0);
    const auto ordinal_table_rva = executable.read_u32(export_directory_rva + 36).value_or(0);
    for (std::uint32_t index = 0; index < std::min(name_count, 100000u); ++index) {
      const auto name_pointer = executable.read_u32(name_table_rva + index * 4).value_or(0);
      const auto ordinal = executable.read_u16(ordinal_table_rva + index * 2).value_or(0);
      const auto function_rva = executable.read_u32(address_table_rva + ordinal * 4).value_or(0);
      if (function_rva != 0) executable.exports.push_back({function_rva, executable.read_c_string(name_pointer)});
    }
  }

  // base relocations
  const auto relocation_directory_rva = directory_rva(kDirectoryBaseRelocation);
  const auto relocation_directory_size = directories.size() > kDirectoryBaseRelocation
                                             ? directories[kDirectoryBaseRelocation].second
                                             : 0u;
  if (relocation_directory_rva != 0 && relocation_directory_size != 0) {
    for (std::uint32_t position = 0; position < relocation_directory_size;) {
      const auto block_rva = executable.read_u32(relocation_directory_rva + position).value_or(0);
      const auto block_size = executable.read_u32(relocation_directory_rva + position + 4).value_or(0);
      if (block_size < 8) break;
      const auto entry_count = (block_size - 8) / 2;
      for (std::uint32_t index = 0; index < entry_count; ++index) {
        const auto entry = executable.read_u16(relocation_directory_rva + position + 8 + index * 2).value_or(0);
        const auto type = static_cast<std::uint16_t>(entry >> 12);
        const auto offset = static_cast<std::uint16_t>(entry & 0xfff);
        if (type != 0) executable.base_relocations.push_back({block_rva + offset, type});
      }
      position += block_size;
    }
  }

  // TLS callbacks
  const auto tls_directory_rva = directory_rva(kDirectoryTls);
  if (tls_directory_rva != 0) {
    const auto callbacks_address = executable.is_64_bit
        ? executable.read_u64(tls_directory_rva + 24).value_or(0)
        : executable.read_u32(tls_directory_rva + 12).value_or(0);
    if (callbacks_address != 0) {
      const auto callbacks_rva = static_cast<std::uint32_t>(callbacks_address >= executable.image_base
          ? callbacks_address - executable.image_base : callbacks_address);
      for (std::uint32_t index = 0; index < 64; ++index) {
        const auto callback = executable.is_64_bit
            ? executable.read_u64(callbacks_rva + index * 8).value_or(0)
            : executable.read_u32(callbacks_rva + index * 4).value_or(0);
        if (callback == 0) break;
        executable.tls_callback_rvas.push_back(static_cast<std::uint32_t>(callback - executable.image_base));
      }
    }
  }

  // Packed-image detection. The general rule is that a section which claims a
  // large virtual size but has no bytes in the file cannot contain the code the
  // loader would map there; known packer section names and the UPX signature are
  // reported by name because that is more useful than a heuristic.
  for (const auto& section : executable.sections) {
    const auto name = section.name;
    if (name.rfind("UPX", 0) == 0 || name == ".UPX0" || name == ".UPX1") {
      executable.packing_reason = "UPX section '" + name + "'";
      break;
    }
  }
  if (executable.packing_reason.empty()) {
    const std::string marker = "UPX!";
    if (executable.file_bytes.size() > marker.size()) {
      const auto begin = executable.file_bytes.end() - static_cast<std::ptrdiff_t>(marker.size() * 4);
      if (std::search(begin, executable.file_bytes.end(), marker.begin(), marker.end()) !=
          executable.file_bytes.end()) {
        executable.packing_reason = "UPX signature in the image";
      }
    }
  }
  if (executable.packing_reason.empty()) {
    for (const auto& section : executable.sections) {
      if (section.is_executable() && section.raw_size == 0 && section.virtual_size >= 0x1000) {
        executable.packing_reason = "executable section '" + section.name +
                                    "' has no bytes in the file (virtual size 0x" +
                                    std::to_string(section.virtual_size) + ")";
        break;
      }
    }
  }

  return executable;
}

LoadedImage load_image(const PortableExecutable& executable, std::uint64_t load_base) {
  LoadedImage loaded;
  loaded.load_base = load_base;
  auto span = std::max<std::uint32_t>(executable.size_of_image, 0x1000);
  for (const auto& section : executable.sections)
    span = std::max<std::uint32_t>(span, section.end_virtual_address());
  span = (span + 0xfffu) & ~0xfffu;
  loaded.image_bytes.assign(span, 0);

  const auto header_size = std::min<std::size_t>(executable.size_of_headers, executable.file_bytes.size());
  std::memcpy(loaded.image_bytes.data(), executable.file_bytes.data(), header_size);
  for (const auto& section : executable.sections) {
    const auto content = executable.read_rva(section.virtual_address, std::max(section.virtual_size, section.raw_size));
    if (section.virtual_address + content.size() > loaded.image_bytes.size()) continue;
    std::memcpy(loaded.image_bytes.data() + section.virtual_address, content.data(), content.size());
  }

  const auto delta = load_base - executable.image_base;
  if (delta != 0) {
    for (const auto& relocation : executable.base_relocations) {
      if (relocation.rva + 8 > loaded.image_bytes.size()) continue;
      auto* destination = loaded.image_bytes.data() + relocation.rva;
      if (relocation.type == 3 || relocation.type == 10) {
        std::uint64_t value = 0;
        std::memcpy(&value, destination, 8);
        value += delta;
        std::memcpy(destination, &value, 8);
      } else if (relocation.type == 1) {
        std::uint16_t value = 0;
        std::memcpy(&value, destination, 2);
        value = static_cast<std::uint16_t>(value + ((delta >> 16) & 0xffff));
        std::memcpy(destination, &value, 2);
      } else if (relocation.type == 2) {
        std::uint16_t value = 0;
        std::memcpy(&value, destination, 2);
        value = static_cast<std::uint16_t>(value + (delta & 0xffff));
        std::memcpy(destination, &value, 2);
      }
    }
  }
  return loaded;
}

}  // namespace recomp::binary
