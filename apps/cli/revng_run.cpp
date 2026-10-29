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

static std::string hash_file(const fs::path& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) throw std::runtime_error("cannot read " + path.string());
  const std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)), {});
  if (file.bad()) throw std::runtime_error("failed reading " + path.string());
  return recomp::common::sha256(bytes);
}

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: revng-run <revng executable> <binary> <new output directory>\n";
    return 2;
  }
  try {
    const auto executable = fs::canonical(argv[1]);
    const auto binary = fs::canonical(argv[2]);
    const auto binary_hash = hash_file(binary);
    const auto output = fs::absolute(argv[3]);
    if (!fs::create_directory(output)) throw std::runtime_error("output directory must not exist");
    const auto artifact = output / "decompiled.c.yml";
    std::vector<std::string> args = {executable.string(), "quick", "artifact", "emit-c-as-single-file",
                                     binary.string(), "-o", artifact.string(), "--format", "yaml"};
    std::vector<char*> raw;
    for (auto& arg : args) raw.push_back(arg.data());
    raw.push_back(nullptr);
    pid_t child{};
    if (posix_spawn(&child, raw[0], nullptr, nullptr, raw.data(), environ) != 0)
      throw std::runtime_error("could not launch rev.ng");
    int status{};
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      throw std::runtime_error("rev.ng failed");
    if (!fs::is_regular_file(artifact) || fs::file_size(artifact) == 0)
      throw std::runtime_error("rev.ng produced no artifact");
    if (hash_file(binary) != binary_hash) throw std::runtime_error("input binary changed during rev.ng analysis");
    const nlohmann::json manifest = {{"schema_version", 1}, {"provider_claim", "rev.ng"},
      {"binary_sha256", binary_hash}, {"artifact_sha256", hash_file(artifact)}, {"artifact_format_claim", "yaml"},
      {"binary_artifact_association", "unverified"}, {"verification", "unverified"}};
    std::ofstream report(output / "analysis-provenance.json", std::ios::binary);
    if (!(report << manifest.dump(2) << '\n')) throw std::runtime_error("cannot write analysis provenance");
    std::cout << artifact.string() << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "revng-run: " << error.what() << '\n';
    return 1;
  }
}
