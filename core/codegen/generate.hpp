#pragma once

#include "core/binary/pe.hpp"
#include "core/discovery/analyze.hpp"

#include <filesystem>

namespace recomp::codegen {

void generate_macos_project(const binary::PeImage& image, const discovery::Analysis& analysis,
                            const std::filesystem::path& input, const std::filesystem::path& output);
int build_project(const std::filesystem::path& project);

}  // namespace recomp::codegen
