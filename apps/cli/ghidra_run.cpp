#include "core/common/sha256.hpp"
#include "third_party/nlohmann/json.hpp"
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <spawn.h>
#include <sys/wait.h>
#include <vector>

extern char** environ;
namespace fs = std::filesystem;

static std::string file_sha256(const fs::path& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) throw std::runtime_error("cannot read " + path.string());
  const std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)), {});
  if (file.bad()) throw std::runtime_error("failed reading " + path.string());
  return recomp::common::sha256(bytes);
}

int main(int argc, char** argv) {
  if (argc != 5 && !(argc == 6 && std::string(argv[5]) == "--decompile")) {
    std::cerr << "usage: ghidra-run <analyzeHeadless> <pcrecomp script directory> <binary> <new output directory> [--decompile]\n";
    return 2;
  }
  try {
    const auto headless = fs::absolute(argv[1]);
    const auto scripts = fs::absolute(argv[2]);
    const auto binary = fs::canonical(argv[3]);
    const auto output = fs::absolute(argv[4]);
    const auto binary_hash = file_sha256(binary);
    std::ifstream script(scripts / "ExportFunctions.java", std::ios::binary);
    if (!script) throw std::runtime_error("cannot read ExportFunctions.java");
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(script)), {});
    if (recomp::common::sha256(bytes) != "5c13c2fc0d38f266ae07fcf7319a86c50258f115e30bc023baef433d2ef7a9ad")
      throw std::runtime_error("exporter does not match pinned PCRecomp revision");
    const bool decompile = argc == 6;
    if (decompile) {
      std::ifstream source(scripts / "DecompileAll.java", std::ios::binary);
      if (!source) throw std::runtime_error("cannot read DecompileAll.java");
      std::vector<unsigned char> script_bytes((std::istreambuf_iterator<char>(source)), {});
      if (recomp::common::sha256(script_bytes) != "801c4ffdc18697311298b4bb95edf3f8255abc216fa94f1536f40a0a37392c1e")
        throw std::runtime_error("decompiler script does not match pinned PCRecomp revision");
    }
    if (!fs::create_directory(output)) throw std::runtime_error("output directory must not exist");
    std::vector<std::string> args = {headless.string(), output.string(), "analysis", "-import", binary.string(),
      "-scriptPath", scripts.string(), "-postScript", "ExportFunctions.java", output.string()};
    if (decompile) args.insert(args.end(), {"-postScript", "DecompileAll.java", output.string()});
    args.insert(args.end(), {"-deleteProject", "-log", (output / "ghidra.log").string(),
      "-scriptlog", (output / "script.log").string()});
    std::vector<char*> raw;
    for (const auto& arg : args) raw.push_back(const_cast<char*>(arg.c_str()));
    raw.push_back(nullptr);
    pid_t child{};
    if (posix_spawn(&child, raw[0], nullptr, nullptr, raw.data(), environ) != 0)
      throw std::runtime_error("could not launch Ghidra");
    int status{};
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      throw std::runtime_error("Ghidra failed; inspect the output logs");
    std::string name = binary.filename().string();
    for (const auto* suffix : {".dll", ".exe"}) {
      const auto pos = name.find(suffix);
      if (pos != std::string::npos) name.erase(pos, 4);
    }
    const auto exported = output / (name + "_functions.txt");
    if (!fs::is_regular_file(exported) || fs::file_size(exported) == 0)
      throw std::runtime_error("Ghidra produced no function export; inspect the output logs");
    const auto decompiled = output / (name + "_decompiled.c");
    if (decompile && (!fs::is_regular_file(decompiled) || fs::file_size(decompiled) == 0))
      throw std::runtime_error("Ghidra produced no decompiler output; inspect the output logs");
    if (file_sha256(binary) != binary_hash)
      throw std::runtime_error("input binary changed during Ghidra analysis");
    nlohmann::json manifest = {{"schema_version", 1}, {"binary_sha256", binary_hash},
      {"function_export_sha256", file_sha256(exported)},
      {"binary_export_association", "unverified"},
      {"export_script_sha256", recomp::common::sha256(bytes)}};
    if (decompile) {
      manifest["decompiled_sha256"] = file_sha256(decompiled);
      manifest["decompile_script_sha256"] = "801c4ffdc18697311298b4bb95edf3f8255abc216fa94f1536f40a0a37392c1e";
    }
    std::ofstream report(output / "analysis-provenance.json", std::ios::binary);
    if (!(report << manifest.dump(2) << '\n')) throw std::runtime_error("cannot write analysis provenance");
    std::cout << exported.string() << '\n';
    if (decompile) std::cout << decompiled.string() << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ghidra-run: " << error.what() << '\n';
    return 1;
  }
}
