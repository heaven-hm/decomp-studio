#include "core/common/configuration.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace recomp::common {
namespace {

std::string trim(const std::string& value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return {};
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::string unquote(const std::string& value) {
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"') return value.substr(1, value.size() - 2);
  return value;
}

std::uint64_t parse_integer(const std::string& value) {
  return std::stoull(value, nullptr, 0);
}

std::vector<std::string> split_items(const std::string& value) {
  std::vector<std::string> items;
  std::string current;
  bool inside_quotes = false;
  for (const char character : value) {
    if (character == '"') { inside_quotes = !inside_quotes; continue; }
    if (character == ',' && !inside_quotes) {
      if (!trim(current).empty()) items.push_back(unquote(trim(current)));
      current.clear();
      continue;
    }
    if (character == '[' || character == ']') continue;
    current.push_back(character);
  }
  if (!trim(current).empty()) items.push_back(unquote(trim(current)));
  return items;
}

std::uint8_t parse_byte(const std::string& token) {
  return static_cast<std::uint8_t>(std::stoul(token, nullptr, 16));
}

}  // namespace

Configuration Configuration::load(const std::filesystem::path& path) {
  Configuration configuration;
  std::ifstream input(path);
  if (!input) throw std::runtime_error("cannot open configuration file: " + path.string());
  std::string line;
  while (std::getline(input, line)) {
    const auto comment = line.find('#');
    if (comment != std::string::npos) line = line.substr(0, comment);
    const auto separator = line.find('=');
    if (separator == std::string::npos) continue;
    const auto key = trim(line.substr(0, separator));
    const auto value = trim(line.substr(separator + 1));
    if (key.empty() || value.empty()) continue;

    if (key == "name") configuration.name = unquote(value);
    else if (key == "format") configuration.input_format = unquote(value);
    else if (key == "architecture") configuration.architecture = unquote(value);
    else if (key == "target") configuration.target = unquote(value);
    else if (key == "strict") configuration.strict_lifting = value == "true" || value == "1";
    else if (key == "compiler") configuration.compiler = unquote(value);
    else if (key == "source_style") configuration.source_style = unquote(value);
    else if (key == "source_mode") configuration.source_mode = unquote(value);
    else if (key == "source_quality") configuration.source_quality = unquote(value);
    else if (key == "stack_top") configuration.stack_top = parse_integer(value);
    else if (key == "heap_base") configuration.heap_base = parse_integer(value);
    else if (key == "entry_point_rva") configuration.entry_point_rva = static_cast<std::uint32_t>(parse_integer(value));
    else if (key == "runtime_directory") configuration.runtime_directory = unquote(value);
    else if (key == "compile_flags") {
      for (const auto& item : split_items(value)) configuration.compile_flags.push_back(item);
    } else if (key == "extra_sources") {
      for (const auto& item : split_items(value)) configuration.extra_source_files.emplace_back(item);
    } else if (key == "stub_function") {
      for (const auto& item : split_items(value)) configuration.stubbed_functions.push_back(parse_integer(item));
    } else if (key == "instruction_patch") {
      for (const auto& item : split_items(value)) {
        const auto colon = item.find(':');
        if (colon == std::string::npos) continue;
        InstructionPatch patch;
        patch.address = parse_integer(trim(item.substr(0, colon)));
        std::istringstream bytes(trim(item.substr(colon + 1)));
        std::string token;
        while (bytes >> token) patch.replacement_bytes.push_back(parse_byte(token));
        if (!patch.replacement_bytes.empty()) configuration.instruction_patches.push_back(std::move(patch));
      }
    } else if (key == "native_override") {
      for (const auto& item : split_items(value)) {
        const auto colon = item.find(':');
        if (colon == std::string::npos) continue;
        configuration.native_overrides[parse_integer(trim(item.substr(0, colon)))] = trim(item.substr(colon + 1));
      }
    }
  }
  return configuration;
}

std::string target_triple_for(const std::string& target) {
  if (target == "native") return {};
  if (target == "macos-arm64" || target == "arm64") return "arm64-apple-macos11";
  if (target == "macos-x86_64" || target == "x86_64") return "x86_64-apple-macos11";
  // Windows targets. The triples are the mingw-w64 ones, which is what this host has.
  // Whether the generated RUNTIME compiles for them is a separate question and is answered by
  // attempting it rather than by declaring it here -- see docs/IMPLEMENTATION_PLAN.md.
  if (target == "windows-x86" || target == "win32") return "i686-w64-mingw32";
  if (target == "windows-x64" || target == "win64") return "x86_64-w64-mingw32";
  if (target == "linux-arm64") return "aarch64-unknown-linux-gnu";
  if (target == "linux-x86_64") return "x86_64-unknown-linux-gnu";
  if (target == "wasm") return "wasm32-unknown-unknown";
  return target;
}

}  // namespace recomp::common
