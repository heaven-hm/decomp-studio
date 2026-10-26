#pragma once

#include "core/binary/pe.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace recomp::discovery {

struct Instruction { std::string mnemonic; std::uint32_t rva; std::size_t size; };
struct Analysis { std::string architecture; std::vector<Instruction> instructions; std::size_t block_count; };

Analysis analyze_entry(const binary::PeImage& image);

}  // namespace recomp::discovery
