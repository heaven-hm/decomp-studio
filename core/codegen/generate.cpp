#include "core/codegen/generate.hpp"

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace recomp::codegen {
namespace {
std::uint32_t immediate(const binary::PeImage& image, std::uint32_t rva) {
  const auto offset = binary::file_offset_for_rva(image, rva);
  if (offset + 5 > image.file_bytes.size()) throw binary::ParseError{"truncated instruction during code generation"};
  const auto& bytes = image.file_bytes;
  return static_cast<std::uint32_t>(bytes[offset + 1]) | (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 16U) | (static_cast<std::uint32_t>(bytes[offset + 4]) << 24U);
}
std::string quote_shell(const std::filesystem::path& value) {
  std::string output{"'"};
  for (const char character : value.string()) output += character == '\'' ? "'\\''" : std::string(1, character);
  return output + "'";
}
}

void generate_macos_project(const binary::PeImage& image, const discovery::Analysis& analysis,
                            const std::filesystem::path& input, const std::filesystem::path& output) {
  if (analysis.architecture != "x86" && analysis.architecture != "x64") throw binary::ParseError{"only x86 and x64 lowering is supported"};
  std::filesystem::create_directories(output);
  std::filesystem::copy_file(input, output / "input.exe", std::filesystem::copy_options::overwrite_existing);
  std::ofstream cmake{output / "CMakeLists.txt"};
  std::ofstream source{output / "guest.cpp"};
  if (!cmake || !source) throw binary::ParseError{"cannot create generated project files"};
  cmake << "cmake_minimum_required(VERSION 3.20)\nproject(recomp_guest LANGUAGES CXX)\n"
        << "add_executable(recomp-guest guest.cpp)\ntarget_compile_features(recomp-guest PRIVATE cxx_std_20)\n";
  source << "#include <cstdint>\n#include <iostream>\nint main() { std::uint64_t accumulator = 0;\n";
  for (const auto& instruction : analysis.instructions) {
    if (instruction.mnemonic == "mov") source << "accumulator = static_cast<std::uint32_t>(0x" << std::hex << immediate(image, instruction.rva) << "U);\n";
    else if (instruction.mnemonic == "add") source << "accumulator = static_cast<std::uint32_t>(accumulator + 0x" << std::hex << immediate(image, instruction.rva) << "U);\n";
    else if (instruction.mnemonic == "sub") source << "accumulator = static_cast<std::uint32_t>(accumulator - 0x" << std::hex << immediate(image, instruction.rva) << "U);\n";
    else if (instruction.mnemonic == "nop" || instruction.mnemonic == "ret") continue;
    else throw binary::ParseError{"cannot lower instruction '" + instruction.mnemonic + "' yet"};
  }
  source << "std::cout << \"{\\\"status\\\":\\\"ok\\\",\\\"return_value\\\":\" << accumulator << \"}\\n\"; return 0; }\n";
  std::ofstream manifest{output / "recomp-manifest.json"};
  manifest << "{\"status\":\"generated\",\"target\":\"macos-arm64\",\"source_architecture\":\"" << analysis.architecture << "\",\"instruction_count\":" << analysis.instructions.size() << "}\n";
}

int build_project(const std::filesystem::path& project) {
  const auto command = "cmake -S " + quote_shell(project) + " -B " + quote_shell(project / "build") +
                       " -G Ninja && cmake --build " + quote_shell(project / "build");
  return std::system(command.c_str());
}

}  // namespace recomp::codegen
