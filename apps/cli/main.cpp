#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "core/binary/pe.hpp"
#include "core/codegen/generate.hpp"
#include "core/common/diagnostic.hpp"
#include "core/discovery/analyze.hpp"
#include "core/ir/ir.hpp"

namespace {

constexpr const char* kVersion = "0.1.0";

void print_help() {
  std::cout << "recomp-studio " << kVersion << "\n"
            << "Usage: recomp-studio <command> [options]\n\n"
            << "Commands:\n"
            << "  doctor          Report host and target capability\n"
            << "  tools list      List configured tool capabilities\n"
            << "  examples list   List bundled example profiles\n"
            << "  inspect         Inspect a PE executable (coming next)\n";
}

int examples_list(bool json) {
  if (json) {
    std::cout << "{\"status\":\"ok\",\"profiles\":["
                 "{\"name\":\"fixture-x86\",\"kind\":\"console fixture\",\"status\":\"supported\"},"
                 "{\"name\":\"fixture-x64\",\"kind\":\"console fixture\",\"status\":\"supported\"},"
                 "{\"name\":\"tictactoe-ai\",\"kind\":\"game (.NET)\",\"status\":\"blocked\",\"reason\":\".NET runtime lifting is not implemented\"},"
                 "{\"name\":\"putty-plink\",\"kind\":\"software (PE32+)\",\"status\":\"blocked\",\"reason\":\"required Win32 imports and x64 coverage are not implemented\"}]}\n";
  } else {
    std::cout << "+--------------------------------------------------+\n| Recomp Studio :: examples                         |\n+--------------------------------------------------+\n"
              << "[supported] fixture-x86   genuine PE32 machine-code validation\n"
              << "[supported] fixture-x64   genuine PE32+ machine-code validation\n"
              << "[blocked]   tictactoe-ai  requires a .NET lifting backend\n"
              << "[blocked]   putty-plink   requires more x64/Win32 compatibility\n";
  }
  return 0;
}

int unsupported(const std::string& command, bool json) {
  const recomp::common::Diagnostic diagnostic{
      "unsupported", command + " is not implemented in this build", 2};
  if (json) {
    std::cout << recomp::common::to_json(diagnostic) << '\n';
  } else {
    std::cerr << "error: " << diagnostic.message << '\n';
  }
  return diagnostic.exit_code;
}

std::string hex_rva(std::uint32_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
  return stream.str();
}

int inspect(const std::filesystem::path& path, bool json) {
  try {
    const auto image = recomp::binary::parse_pe(path);
    if (json) {
      std::cout << "{\"status\":\"ok\",\"format\":\"" << image.format
                << "\",\"architecture\":\"" << image.architecture
                << "\",\"entry_rva\":\"" << hex_rva(image.entry_rva)
                << "\",\"sha256\":\"" << image.sha256
                << "\",\"section_count\":" << image.sections.size()
                << ",\"imports\":[";
      for (std::size_t index = 0; index < image.imports.size(); ++index) {
        if (index != 0) std::cout << ',';
        std::cout << recomp::common::quote_json(image.imports[index]);
      }
      std::cout << "]}" << '\n';
    } else {
      std::cout << "+--------------------------------------------------+\n"
                << "| Recomp Studio :: inspect                          |\n"
                << "+--------------------------------------------------+\n"
                << "[loading] reading " << path.filename().string() << '\n'
                << "[working] validating DOS, PE, and COFF headers\n"
                << "[working] calculating SHA-256\n"
                << "[idle] format=" << image.format << " arch=" << image.architecture
                << " entry=" << hex_rva(image.entry_rva) << "\n"
                << "[complete] sections=" << image.sections.size() << " sha256="
                << image.sha256 << '\n';
    }
    return 0;
  } catch (const recomp::binary::ParseError& error) {
    const recomp::common::Diagnostic diagnostic{"error", error.message, 1};
    if (json) std::cout << recomp::common::to_json(diagnostic) << '\n';
    else std::cerr << "[error] " << error.message << '\n';
    return diagnostic.exit_code;
  }
}

int analyze(const std::filesystem::path& path, bool json) {
  try {
    const auto image = recomp::binary::parse_pe(path);
    const auto result = recomp::discovery::analyze_entry(image);
    if (json) {
      std::cout << "{\"status\":\"ok\",\"architecture\":\"" << result.architecture
                << "\",\"function_count\":1,\"block_count\":" << result.block_count
                << ",\"instruction_count\":" << result.instructions.size() << ",\"instructions\":[";
      for (std::size_t index = 0; index < result.instructions.size(); ++index) {
        if (index != 0) std::cout << ',';
        std::cout << recomp::common::quote_json(result.instructions[index].mnemonic);
      }
      std::cout << "]}" << '\n';
    } else {
      std::cout << "+--------------------------------------------------+\n"
                << "| Recomp Studio :: analyze                          |\n"
                << "+--------------------------------------------------+\n"
                << "[loading] opening " << path.filename().string() << '\n'
                << "[working] decoding entry-reachable " << result.architecture << " instructions\n"
                << "[idle] functions=1 blocks=" << result.block_count << '\n'
                << "[complete] instructions=" << result.instructions.size() << '\n';
    }
    return 0;
  } catch (const recomp::binary::ParseError& error) {
    const recomp::common::Diagnostic diagnostic{"error", error.message, 1};
    if (json) std::cout << recomp::common::to_json(diagnostic) << '\n';
    else std::cerr << "[error] " << error.message << '\n';
    return diagnostic.exit_code;
  }
}

int cfg(const std::filesystem::path& path, bool json) {
  try {
    const auto image = recomp::binary::parse_pe(path);
    const auto result = recomp::discovery::analyze_entry(image);
    std::ostringstream dot;
    dot << "digraph cfg {\n  entry [label=\"" << hex_rva(image.entry_rva) << "\\n";
    for (const auto& instruction : result.instructions) dot << instruction.mnemonic << "\\n";
    dot << "\"];\n}\n";
    if (json) {
      std::cout << "{\"status\":\"ok\",\"entry_rva\":" << recomp::common::quote_json(hex_rva(image.entry_rva))
                << ",\"block_count\":" << result.block_count << ",\"dot\":" << recomp::common::quote_json(dot.str()) << "}" << '\n';
    } else {
      std::cout << "[loading] parsing executable\n[working] recovering entry-rooted CFG\n[complete] blocks=" << result.block_count << "\n\n" << dot.str();
    }
    return 0;
  } catch (const recomp::binary::ParseError& error) {
    if (json) std::cout << recomp::common::to_json({"error", error.message, 1}) << '\n'; else std::cerr << "[error] " << error.message << '\n';
    return 1;
  }
}

int lift(const std::filesystem::path& path, bool json) {
  try {
    const auto image = recomp::binary::parse_pe(path);
    const auto analysis = recomp::discovery::analyze_entry(image);
    const auto operations = recomp::ir::lift(analysis);
    if (json) {
      std::cout << "{\"status\":\"ok\",\"architecture\":\"" << analysis.architecture << "\",\"operations\":[";
      for (std::size_t index = 0; index < operations.size(); ++index) {
        if (index != 0) std::cout << ',';
        const auto& operation = operations[index];
        std::cout << "{\"opcode\":" << recomp::common::quote_json(operation.opcode)
                  << ",\"width\":" << operation.width << ",\"source_rva\":"
                  << recomp::common::quote_json(hex_rva(operation.source_rva)) << '}';
      }
      std::cout << "]}" << '\n';
    } else {
      std::cout << "+--------------------------------------------------+\n"
                << "| Recomp Studio :: lift                             |\n"
                << "+--------------------------------------------------+\n"
                << "[loading] parsed executable and decoded entry flow\n"
                << "[working] lifting instructions into canonical IR\n"
                << "[idle] architecture=" << analysis.architecture << '\n'
                << "[complete] operations=" << operations.size() << '\n';
    }
    return 0;
  } catch (const recomp::binary::ParseError& error) {
    const recomp::common::Diagnostic diagnostic{"error", error.message, 1};
    if (json) std::cout << recomp::common::to_json(diagnostic) << '\n';
    else std::cerr << "[error] " << error.message << '\n';
    return diagnostic.exit_code;
  }
}

int translate(const std::filesystem::path& input, const std::filesystem::path& output,
              const std::string& target, bool json) {
  if (target != "macos-arm64") return unsupported("target '" + target + "'", json);
  try {
    const auto image = recomp::binary::parse_pe(input);
    const auto analysis = recomp::discovery::analyze_entry(image);
    recomp::codegen::generate_macos_project(image, analysis, input, output);
    if (json) std::cout << "{\"status\":\"ok\",\"target\":\"macos-arm64\",\"project\":" << recomp::common::quote_json(output.string()) << "}" << '\n';
    else std::cout << "[loading] parsing and decoding input\n[working] lowering supported semantics to C++20\n[idle] project=" << output << "\n[complete] target=macos-arm64\n";
    return 0;
  } catch (const recomp::binary::ParseError& error) {
    const recomp::common::Diagnostic diagnostic{"error", error.message, 1};
    if (json) std::cout << recomp::common::to_json(diagnostic) << '\n'; else std::cerr << "[error] " << error.message << '\n';
    return diagnostic.exit_code;
  }
}

int build(const std::filesystem::path& project, bool json) {
  if (!std::filesystem::exists(project / "CMakeLists.txt")) return unsupported("generated project is missing CMakeLists.txt", json);
  const auto result = recomp::codegen::build_project(project);
  if (result == 0) {
    if (json) std::cout << "{\"status\":\"ok\",\"executable\":" << recomp::common::quote_json((project / "build/recomp-guest").string()) << "}" << '\n';
    else std::cout << "[complete] native executable=" << project / "build/recomp-guest" << '\n';
    return 0;
  }
  const recomp::common::Diagnostic diagnostic{"error", "generated host build failed", 1};
  if (json) std::cout << recomp::common::to_json(diagnostic) << '\n'; else std::cerr << "[error] " << diagnostic.message << '\n';
  return 1;
}

int run(const std::filesystem::path& project, bool json) {
  const auto executable = project / "build/recomp-guest";
  if (!std::filesystem::exists(executable)) return unsupported("generated executable is missing; run build first", json);
  const auto command = "'" + executable.string() + "'";
  FILE* stream = popen(command.c_str(), "r");
  if (stream == nullptr) return unsupported("cannot launch generated executable", json);
  char buffer[256];
  std::string output;
  while (fgets(buffer, sizeof(buffer), stream) != nullptr) output += buffer;
  if (pclose(stream) != 0) return unsupported("generated executable failed", json);
  std::cout << output;
  return 0;
}

std::uint64_t immediate_value(const recomp::binary::PeImage& image, std::uint32_t rva) {
  const auto offset = recomp::binary::file_offset_for_rva(image, rva);
  const auto& bytes = image.file_bytes;
  if (offset + 5 > bytes.size()) throw recomp::binary::ParseError{"truncated instruction in reference interpreter"};
  return static_cast<std::uint64_t>(bytes[offset + 1]) | (static_cast<std::uint64_t>(bytes[offset + 2]) << 8U) |
         (static_cast<std::uint64_t>(bytes[offset + 3]) << 16U) | (static_cast<std::uint64_t>(bytes[offset + 4]) << 24U);
}

std::uint64_t interpret(const recomp::binary::PeImage& image, const recomp::discovery::Analysis& analysis) {
  std::uint64_t accumulator = 0;
  for (const auto& instruction : analysis.instructions) {
    if (instruction.mnemonic == "mov") accumulator = static_cast<std::uint32_t>(immediate_value(image, instruction.rva));
    else if (instruction.mnemonic == "add") accumulator = static_cast<std::uint32_t>(accumulator + immediate_value(image, instruction.rva));
    else if (instruction.mnemonic == "sub") accumulator = static_cast<std::uint32_t>(accumulator - immediate_value(image, instruction.rva));
    else if (instruction.mnemonic != "nop" && instruction.mnemonic != "ret") throw recomp::binary::ParseError{"reference interpreter does not support '" + instruction.mnemonic + "'"};
  }
  return accumulator;
}

int verify(const std::filesystem::path& project, bool json) {
  try {
    const auto image = recomp::binary::parse_pe(project / "input.exe");
    const auto reference = interpret(image, recomp::discovery::analyze_entry(image));
    const auto command = "'" + (project / "build/recomp-guest").string() + "'";
    std::string output; char buffer[256];
    FILE* stream = popen(command.c_str(), "r");
    if (stream == nullptr) throw recomp::binary::ParseError{"cannot launch generated executable"};
    while (fgets(buffer, sizeof(buffer), stream) != nullptr) output += buffer;
    if (pclose(stream) != 0) throw recomp::binary::ParseError{"generated executable failed"};
    const auto marker = output.find("\"return_value\":");
    if (marker == std::string::npos) throw recomp::binary::ParseError{"generated executable did not emit return value"};
    const auto native = std::stoull(output.substr(marker + 15));
    const bool passed = native == reference;
    if (json) std::cout << "{\"status\":\"" << (passed ? "pass" : "fail") << "\",\"reference_return_value\":" << reference << ",\"native_return_value\":" << native << "}" << '\n';
    else std::cout << "[working] executing independent reference interpreter\n[working] executing native ARM64 candidate\n[" << (passed ? "complete" : "error") << "] reference=" << reference << " native=" << native << '\n';
    return passed ? 0 : 1;
  } catch (const recomp::binary::ParseError& error) {
    if (json) std::cout << recomp::common::to_json({"error", error.message, 1}) << '\n'; else std::cerr << "[error] " << error.message << '\n'; return 1;
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 1) {
    print_help();
    return 0;
  }

  const std::string first{argv[1]};
  const bool json = argc >= 3 && std::string{argv[argc - 1]} == "--json";
  if (first == "--help" || first == "help") {
    print_help();
    return 0;
  }
  if (first == "--version") {
    if (json) {
      std::cout << "{\"status\":\"ok\",\"version\":\"" << kVersion
                << "\"}" << '\n';
    } else {
      std::cout << kVersion << '\n';
    }
    return 0;
  }
  if (first == "doctor") {
    if (json) {
      std::cout << "{\"status\":\"ok\",\"host\":\"macos\","
                   "\"target\":\"macos-arm64\"}" << '\n';
    } else {
      std::cout << "host: macos; native target: macos-arm64\n";
    }
    return 0;
  }
  if (first == "inspect") {
    if (argc < 3) return unsupported("inspect requires a PE file", json);
    return inspect(argv[2], json);
  }
  if (first == "analyze") {
    if (argc < 3) return unsupported("analyze requires a PE file", json);
    return analyze(argv[2], json);
  }
  if (first == "lift") {
    if (argc < 3) return unsupported("lift requires a PE file", json);
    return lift(argv[2], json);
  }
  if (first == "cfg") {
    if (argc < 3) return unsupported("cfg requires a PE file", json);
    return cfg(argv[2], json);
  }
  if (first == "translate") {
    if (argc < 7) return unsupported("translate requires <file> --target macos-arm64 --output <directory>", json);
    std::filesystem::path output;
    std::string target;
    for (int index = 3; index + 1 < argc; ++index) {
      if (std::string{argv[index]} == "--target") target = argv[++index];
      else if (std::string{argv[index]} == "--output") output = argv[++index];
    }
    if (target.empty() || output.empty()) return unsupported("translate requires --target and --output", json);
    return translate(argv[2], output, target, json);
  }
  if (first == "build") {
    if (argc < 3) return unsupported("build requires a generated project", json);
    return build(argv[2], json);
  }
  if (first == "verify") {
    if (argc < 3) return unsupported("verify requires a generated project", json);
    return verify(argv[2], json);
  }
  if (first == "run") {
    if (argc < 3) return unsupported("run requires a generated project", json);
    return run(argv[2], json);
  }
  if (first == "examples" && argc >= 3 && std::string{argv[2]} == "list") return examples_list(json);
  return unsupported(first, json);
}
#include <cstdio>
