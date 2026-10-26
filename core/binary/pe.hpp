#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace recomp::binary {

struct Section { std::string name; std::uint32_t rva; std::uint32_t virtual_size; std::uint32_t raw_offset; std::uint32_t raw_size; std::uint32_t characteristics; };
struct PeImage {
  std::string format;
  std::string architecture;
  std::string sha256;
  std::uint32_t entry_rva{};
  std::vector<Section> sections;
  std::vector<std::string> imports;
  std::vector<unsigned char> file_bytes;
};
struct ParseError { std::string message; };

PeImage parse_pe(const std::filesystem::path& path);
std::size_t file_offset_for_rva(const PeImage& image, std::uint32_t rva);

}  // namespace recomp::binary
