#include <algorithm>
#include "core/binary/pe.hpp"

#include <cctype>
#include <cstring>
#include <sstream>
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
constexpr std::uint16_t kDirectoryResource = 2;
constexpr std::uint16_t kDirectoryBaseRelocation = 5;
constexpr std::uint16_t kDirectoryTls = 9;
constexpr std::uint16_t kDirectoryLoadConfig = 10;
constexpr std::uint16_t kDirectoryDelayImport = 13;

// Resource type numbers, from winnt.h. Named here because a manifest is found by
// type, and a magic number in the middle of a walk is not self-explanatory.
constexpr std::uint32_t kResourceTypeManifest = 24;
constexpr std::uint32_t kManifestIdCreateProcess = 1;

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

std::vector<const Section*> PortableExecutable::writable_executable_sections() const {
  std::vector<const Section*> output;
  for (const auto& section : sections)
    if (section.is_executable() && section.is_writable()) output.push_back(&section);
  return output;
}

const PortableExecutable::Resource* PortableExecutable::find_resource(std::uint32_t type,
                                                                     std::uint32_t id) const {
  for (const auto& resource : resources)
    if (resource.type == type && resource.id == id) return &resource;
  return nullptr;
}

// Names the format of an input that is not a Windows PE image. "not a DOS MZ
// executable" is true and useless: it does not say what the file is, whether the
// tool could ever read it, or which direction is missing. A macOS .app bundle,
// an ELF binary and a Java class file are all rejected here, and they are not the
// same problem.
std::string describe_foreign_format(const std::vector<std::uint8_t>& bytes) {
  const auto has = [&bytes](std::size_t offset, std::initializer_list<std::uint8_t> magic) {
    if (offset + magic.size() > bytes.size()) return false;
    std::size_t index = 0;
    for (const auto byte : magic) {
      if (bytes[offset + index] != byte) return false;
      ++index;
    }
    return true;
  };
  const auto architecture = [&bytes](std::size_t offset) -> std::string {
    if (offset + 20 > bytes.size()) return {};
    const auto machine = static_cast<std::uint32_t>(bytes[offset + 3]) << 24 |
                         static_cast<std::uint32_t>(bytes[offset + 2]) << 16 |
                         static_cast<std::uint32_t>(bytes[offset + 1]) << 8 |
                         static_cast<std::uint32_t>(bytes[offset]);
    switch (machine) {
      case 0x01000007u: return " x86-64";
      case 0x0100000cu: return " ARM64";
      case 0x00000007u: return " x86";
      case 0x0000000cu: return " ARM";
      default: return {};
    }
  };

  if (has(0, {0x7f, 'E', 'L', 'F'}))
    return "input is an ELF binary, not a Windows PE image; this build reads Windows PE32/PE32+ input only";
  if (has(0, {0xfe, 0xed, 0xfa, 0xce}) || has(0, {0xfe, 0xed, 0xfa, 0xcf}))
    return "input is a Mach-O executable" + architecture(4) +
           ", not a Windows PE image; this build reads Windows PE32/PE32+ input only";
  if (has(0, {0xca, 0xfe, 0xba, 0xbe}))
    return "input is a Mach-O universal binary, not a Windows PE image; this build reads Windows PE32/PE32+ input only";
  if (has(0, {0xcf, 0xfa, 0xed, 0xfe}) || has(0, {0xce, 0xfa, 0xed, 0xfe}))
    return "input is a 64-bit Mach-O executable" + architecture(4) +
           ", not a Windows PE image; this build reads Windows PE32/PE32+ input only";
  if (has(0, {'#', '!', '/', 'b', 'i', 'n'}))
    return "input is a script, not a Windows PE image; this build reads Windows PE32/PE32+ input only";
  if (has(0, {0x50, 0x4b, 0x03, 0x04}))
    return "input is a ZIP archive, not a Windows PE image; if this is a packaged application, extract it first";
  if (has(0, {0xca, 0xfe, 0xba, 0xbe}) || has(0, {0xce, 0xfa, 0xed, 0xfe}))
    return "input is a Java class file, not a Windows PE image; this build reads Windows PE32/PE32+ input only";
  return "not a Windows PE image: the file does not begin with the MZ signature, so it is neither PE32 nor PE32+";
}

PortableExecutable PortableExecutable::parse(const std::filesystem::path& path) {
  PortableExecutable executable;
  executable.path = path;
  executable.file_bytes = read_whole_file(path);
  const auto& bytes = executable.file_bytes;
  if (bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z')
    throw ParseError(describe_foreign_format(bytes));

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
  // Refuse an architecture this build cannot read, BY NAME. Decoding AArch64 machine
  // code as x86-64 produces a plausible-looking census of instructions that do not
  // exist, and a refusal reason naming a mnemonic the program never contained is worse
  // than no answer.
  if (!executable.is_supported_architecture()) {
    throw ParseError("input is a Windows PE image for " + executable.architecture_name() +
                     "; this build reads Windows PE32 (x86) and PE32+ (x86-64) input only");
  }

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

  // Directory 14 is the CLR runtime header. A managed image keeps its code as IL
  // bytecode in the CLR metadata rather than as native machine code, so treating
  // it as a native binary recovers a handful of stub functions and then reports
  // complete coverage of a program whose real code it never saw.
  constexpr std::uint16_t kDirectoryClrRuntimeHeader = 14;
  if (directory_rva(kDirectoryClrRuntimeHeader) != 0 &&
      (directories.size() > kDirectoryClrRuntimeHeader && directories[kDirectoryClrRuntimeHeader].second != 0)) {
    executable.clr_runtime_header_rva = directory_rva(kDirectoryClrRuntimeHeader);
    std::ostringstream text;
    text << "managed .NET image (CLR runtime header at rva 0x" << std::hex
         << executable.clr_runtime_header_rva << ")";
    executable.managed_reason = text.str();
  }

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
          imported.by_ordinal = true;
          imported.ordinal = static_cast<std::uint32_t>(thunk_value & 0xffffu);
          // The name is synthesised from the ordinal, so the report and the shim
          // table are looking at the same string. Ordinal 140 of ws2_32.dll is a
          // different question from a named import: the number is only meaningful
          // for that DLL, so a resolver cannot guess a name from it.
          imported.symbol_name = "#" + std::to_string(imported.ordinal);
        } else {
          imported.symbol_name = executable.read_c_string(static_cast<std::uint32_t>(thunk_value) + 2);
        }
        executable.imports.push_back(imported);
        thunk_rva += pointer_size;
        slot_rva += pointer_size;
      }
    }
  }

  // Delay-loaded imports (directory 13). A program that delay-loads a DLL does not
  // touch it until the first call, so the import directory -- which is what a
  // static census reads -- does not mention it at all. d3d9, xinput and the
  // speech APIs are routinely delay-loaded, and an import report built from the
  // ordinary table alone tells you a game needs nothing it in fact calls.
  const auto delay_directory_rva = directory_rva(kDirectoryDelayImport);
  const auto delay_directory_size = directories.size() > kDirectoryDelayImport
                                        ? directories[kDirectoryDelayImport].second
                                        : 0u;
  if (delay_directory_rva != 0 && delay_directory_size >= 32) {
    const auto pointer_size = executable.is_64_bit ? 8u : 4u;
    const auto ordinal_flag = executable.is_64_bit ? 0x8000000000000000ull : 0x80000000ull;
    // Bounded by the directory's recorded size: a malformed table with no
    // all-zero descriptor has to stop somewhere, and the size is what the image
    // itself claims.
    const auto descriptor_end = delay_directory_rva + delay_directory_size;
    for (std::uint32_t descriptor_rva = delay_directory_rva; descriptor_rva + 32 <= descriptor_end;
         descriptor_rva += 32) {
      const auto name_rva = executable.read_u32(descriptor_rva + 4).value_or(0);
      const auto import_name_table = executable.read_u32(descriptor_rva + 16).value_or(0);
      const auto import_address_table = executable.read_u32(descriptor_rva + 12).value_or(0);
      // The table is terminated by an all-zero descriptor.
      if (name_rva == 0 && import_name_table == 0 && import_address_table == 0) break;
      auto library_name = executable.read_c_string(name_rva);
      for (auto& character : library_name)
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
      for (std::uint32_t index = 0; import_name_table != 0 && index < 65536; ++index) {
        const auto thunk_rva = import_name_table + index * pointer_size;
        const auto thunk_value = executable.is_64_bit ? executable.read_u64(thunk_rva).value_or(0)
                                                     : executable.read_u32(thunk_rva).value_or(0);
        if (thunk_value == 0) break;
        ImportedSymbol imported;
        // The delay IAT is a separate table from the ordinary one; recording its
        // slot is what lets a project bind the thunk where the loader would.
        imported.import_address_table_rva = import_address_table + index * pointer_size;
        imported.library_name = library_name;
        imported.from_delay_table = true;
        if ((thunk_value & ordinal_flag) != 0) {
          imported.by_ordinal = true;
          imported.ordinal = static_cast<std::uint32_t>(thunk_value & 0xffffu);
          imported.symbol_name = "#" + std::to_string(imported.ordinal);
        } else {
          imported.symbol_name = executable.read_c_string(static_cast<std::uint32_t>(thunk_value) + 2);
        }
        executable.imports.push_back(imported);
      }
      descriptor_rva += 32;
    }
  }

  // Every DLL the image names, static or delay, in the order first seen. This is
  // the dependency set a capability resolver has to satisfy, and it is also the
  // honest answer to "what will this program try to load".
  {
    std::vector<std::string> seen;
    for (const auto& imported : executable.imports) {
      if (std::find(seen.begin(), seen.end(), imported.library_name) == seen.end())
        seen.push_back(imported.library_name);
    }
    executable.dependent_dlls = std::move(seen);
  }

  // exports
  const auto export_directory_rva = directory_rva(kDirectoryExport);
  const auto export_directory_size = directories.size() > kDirectoryExport
                                         ? directories[kDirectoryExport].second
                                         : 0u;
  if (export_directory_rva != 0) {
    const auto name_count = executable.read_u32(export_directory_rva + 24).value_or(0);
    const auto address_table_rva = executable.read_u32(export_directory_rva + 28).value_or(0);
    const auto name_table_rva = executable.read_u32(export_directory_rva + 32).value_or(0);
    const auto ordinal_table_rva = executable.read_u32(export_directory_rva + 36).value_or(0);
    for (std::uint32_t index = 0; index < std::min(name_count, 100000u); ++index) {
      const auto name_pointer = executable.read_u32(name_table_rva + index * 4).value_or(0);
      const auto ordinal = executable.read_u16(ordinal_table_rva + index * 2).value_or(0);
      const auto function_rva = executable.read_u32(address_table_rva + ordinal * 4).value_or(0);
      if (function_rva == 0) continue;
      ExportedSymbol exported;
      exported.rva = function_rva;
      exported.name = executable.read_c_string(name_pointer);
      // An export whose target lands inside the export directory is not an
      // address: it is a pointer to the name of somebody else's export. API sets
      // are entirely made of these, so an import of api-ms-win-core-synch must be
      // followed through the forwarder to kernel32 to find the implementation.
      // Reading it as code would name a function that does not exist.
      if (function_rva >= export_directory_rva && function_rva < export_directory_rva + export_directory_size) {
        exported.is_forwarder = true;
        exported.forward_name = executable.read_c_string(function_rva);
      }
      executable.exports.push_back(exported);
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

  // The resource tree (directory 2), walked to its data entries.
  //
  // Three levels -- type, name-or-id, language -- each a directory of eight-byte
  // entries where the high bit of the offset says "another directory" and says
  // "the data" when it does not. Icons, cursors, menus, dialog templates and
  // accelerators are all reached through here, so a shim that has to hand the
  // guest an icon has to start from this tree; guessing from the filename finds
  // nothing, because the icon was compiled into the image.
  const auto resource_directory_rva = directory_rva(kDirectoryResource);
  const auto resource_directory_size = directories.size() > kDirectoryResource
                                           ? directories[kDirectoryResource].second
                                           : 0u;
  if (resource_directory_rva != 0 && resource_directory_size >= 16) {
    const auto resource_end = resource_directory_rva + resource_directory_size;
    // Walks one level of the tree. Offsets inside a resource directory are
    // relative to the start of the whole tree, which is why every one of them is
    // added to `root` here rather than treated as an address.
    struct Walk {
      std::uint32_t root{};
      std::uint32_t limit{};
      const PortableExecutable* image{};
      PortableExecutable::Resource leaf{};
      std::vector<PortableExecutable::Resource> found;
      // Offsets already being descended through: a table that points back at
      // itself is refused rather than walked forever.
      std::vector<std::uint32_t> visiting;

      // A named entry points at a UTF-16 length-prefixed string. The standard
      // resource types are always numbered, so a name here is a string the
      // program gave its own resource; it is recorded because a resource the
      // guest asks for by name cannot be found without it.
      std::string name_at(std::uint32_t offset) const {
        const auto at = root + (offset & 0x7fffffffu);
        if (at + 2 > limit) return {};
        const auto characters = image->read_u16(at).value_or(0);
        if (characters == 0 || characters > 512) return {};
        const auto bytes = image->read_rva(at + 2, characters * 2);
        std::string text;
        for (std::size_t index = 0; index + 1 < bytes.size(); index += 2)
          text.push_back(bytes[index] == 0 ? '?' : static_cast<char>(bytes[index]));
        return text;
      }

      void directory(std::uint32_t offset, int level) {
        const auto at = root + offset;
        if (at + 16 > limit) return;
        const auto entry_count = static_cast<std::uint32_t>(image->read_u16(at + 12).value_or(0)) +
                                 static_cast<std::uint32_t>(image->read_u16(at + 14).value_or(0));
        // No separate cap on the entry count: `entry + 8 > limit` below stops the
        // walk at the end of the declared resource directory, which is the bound
        // that actually means something. A count cap would just decide, in advance,
        // that a large but honest resource tree is not worth reading.
        for (std::uint32_t index = 0; index < entry_count; ++index) {
          const auto entry = at + 16 + index * 8;
          if (entry + 8 > limit) return;
          const auto name_or_id = image->read_u32(entry).value_or(0);
          const auto data_or_subdir = image->read_u32(entry + 4).value_or(0);
          const bool is_named = (name_or_id & 0x80000000u) != 0;
          const auto outer_type = leaf.type;
          const auto outer_id = leaf.id;
          if (level == 0) {
            leaf.type = is_named ? 0 : name_or_id;
            leaf.type_name = is_named ? name_at(name_or_id) : std::string();
          } else if (level == 1) {
            leaf.id = is_named ? 0 : name_or_id;
          } else {
            leaf.language = is_named ? 0 : name_or_id;
          }
          if ((data_or_subdir & 0x80000000u) != 0) {
            const auto child = data_or_subdir & 0x7fffffffu;
            if (level < 2 && std::find(visiting.begin(), visiting.end(), child) == visiting.end()) {
              visiting.push_back(child);
              directory(child, level + 1);
              visiting.pop_back();
            }
          } else if (level == 2) {
            const auto data_at = root + data_or_subdir;
            if (data_at + 12 > limit) continue;
            leaf.rva = image->read_u32(data_at).value_or(0);
            leaf.size = image->read_u32(data_at + 4).value_or(0);
            leaf.code_page = image->read_u32(data_at + 8).value_or(0);
            if (leaf.rva != 0 && leaf.rva < limit) found.push_back(leaf);
          }
          leaf.type = outer_type;
          leaf.id = outer_id;
        }
      }
    } walk{resource_directory_rva, resource_end, &executable, {}, {}, {}};
    walk.directory(0, 0);
    executable.resources = std::move(walk.found);
  }

  // The embedded application manifest. A program asks for the version-6 common
  // controls by naming them here -- not by calling anything -- so a recompiled
  // app that gets version-5 behaviour is not a shim bug, it is a manifest nobody
  // read. Extracting it turns "InitCommonControlsEx does nothing" into a question
  // with an answerable form: which version did this image ask for.
  for (const auto& resource : executable.resources) {
    if (resource.type != kResourceTypeManifest || resource.id != kManifestIdCreateProcess) continue;
    const auto bytes = executable.read_rva(resource.rva, resource.size);
    executable.manifest.assign(bytes.begin(), bytes.end());
    break;
  }
  if (!executable.manifest.empty()) {
    const auto controls = executable.manifest.find("Microsoft.Windows.Common-Controls");
    if (controls != std::string::npos) {
      const auto version_at = executable.manifest.find("version", controls);
      if (version_at != std::string::npos) {
        const auto six = executable.manifest.find('6', version_at);
        const auto closing = executable.manifest.find('"', version_at);
        executable.requests_common_controls_v6 = six != std::string::npos && (closing == std::string::npos || six < closing);
      }
    }
  }

  // Control Flow Guard, from the load configuration directory (10). A CFG image
  // routes indirect calls through guard thunks and validates the target against a
  // table the compiler emitted, so its indirect-call sites are not recoverable
  // from the code alone. Saying so is the difference between an unexplained
  // missing target and a known requirement on the dispatch path.
  const auto load_config_rva = directory_rva(kDirectoryLoadConfig);
  if (load_config_rva != 0) {
    const auto guard_flags_offset = executable.is_64_bit ? 0x70u : 0x6cu;
    const auto guard_flags = executable.read_u32(load_config_rva + guard_flags_offset).value_or(0);
    executable.guard_flags = guard_flags;
    // IMAGE_GUARD_CF_INSTRUMENTED (0x100) means the compiler emitted the checks.
    executable.has_control_flow_guard = (guard_flags & 0x100u) != 0;
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
