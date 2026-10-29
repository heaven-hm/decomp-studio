#include "core/common/sha256.hpp"
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

int main(int argc, char** argv) {
  if (argc != 5) {
    std::cerr << "usage: ghidra-run <analyzeHeadless> <pcrecomp script directory> <binary> <new output directory>\n";
    return 2;
  }
  try {
    const auto headless = fs::absolute(argv[1]);
    const auto scripts = fs::absolute(argv[2]);
    const auto binary = fs::canonical(argv[3]);
    const auto output = fs::absolute(argv[4]);
    std::ifstream script(scripts / "ExportFunctions.java", std::ios::binary);
    if (!script) throw std::runtime_error("cannot read ExportFunctions.java");
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(script)), {});
    if (recomp::common::sha256(bytes) != "5c13c2fc0d38f266ae07fcf7319a86c50258f115e30bc023baef433d2ef7a9ad")
      throw std::runtime_error("exporter does not match pinned PCRecomp revision");
    if (!fs::create_directory(output)) throw std::runtime_error("output directory must not exist");
    const std::vector<std::string> args = {headless.string(), output.string(), "analysis", "-import", binary.string(),
      "-scriptPath", scripts.string(), "-postScript", "ExportFunctions.java", output.string(),
      "-deleteProject", "-log", (output / "ghidra.log").string(),
      "-scriptlog", (output / "script.log").string()};
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
    std::cout << exported.string() << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ghidra-run: " << error.what() << '\n';
    return 1;
  }
}
