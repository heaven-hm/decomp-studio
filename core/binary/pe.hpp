#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace recomp::binary {

struct Section {
  std::string name;
  std::uint32_t virtual_address{};
  std::uint32_t virtual_size{};
  std::uint32_t raw_offset{};
  std::uint32_t raw_size{};
  std::uint32_t characteristics{};

  std::uint32_t end_virtual_address() const {
    return virtual_address + std::max(virtual_size, raw_size);
  }
  bool is_executable() const { return (characteristics & 0x20000000u) != 0; }
};

struct ImportedSymbol {
  std::uint32_t import_address_table_rva{};
  std::string library_name;
  std::string symbol_name;
};

struct ExportedSymbol {
  std::uint32_t rva{};
  std::string name;
};

struct BaseRelocation {
  std::uint32_t rva{};
  std::uint16_t type{};
};

class ParseError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class PortableExecutable {
 public:
  static PortableExecutable parse(const std::filesystem::path& path);

  std::filesystem::path path;
  std::vector<std::uint8_t> file_bytes;
  bool is_64_bit{};
  std::uint16_t machine{};
  bool is_dynamic_library{};
  std::uint32_t entry_point_rva{};
  std::uint64_t image_base{};
  std::uint32_t size_of_image{};
  std::uint32_t size_of_headers{};
  std::uint32_t size_of_code{};
  std::uint16_t subsystem{};
  std::vector<Section> sections;
  std::vector<ImportedSymbol> imports;
  std::vector<ExportedSymbol> exports;
  std::vector<BaseRelocation> base_relocations;
  std::vector<std::uint32_t> tls_callback_rvas;

  std::string format_name() const { return is_64_bit ? "PE32+" : "PE32"; }
  std::string architecture_name() const { return is_64_bit ? "x86_64" : "x86"; }

  const Section* section_containing(std::uint32_t rva) const;
  std::optional<std::uint32_t> file_offset_for_rva(std::uint32_t rva) const;
  std::vector<std::uint8_t> read_rva(std::uint32_t rva, std::size_t count) const;
  std::optional<std::uint16_t> read_u16(std::uint32_t rva) const;
  std::optional<std::uint32_t> read_u32(std::uint32_t rva) const;
  std::optional<std::uint64_t> read_u64(std::uint32_t rva) const;
  std::string read_c_string(std::uint32_t rva, std::size_t limit = 4096) const;
  const Section* text_section() const;
  std::vector<const Section*> executable_sections() const;
};

struct LoadedImage {
  std::uint64_t load_base{};
  std::vector<std::uint8_t> image_bytes;
};

LoadedImage load_image(const PortableExecutable& executable, std::uint64_t load_base);

}  // namespace recomp::binary
