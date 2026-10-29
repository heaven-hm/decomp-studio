#pragma once

#include "core/binary/pe.hpp"
#include "core/common/configuration.hpp"
#include "core/discovery/function_discovery.hpp"
#include "core/semantics/x86_64_lifter.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace recomp::codegen {

// Carries the census the gate measured so callers can report the refusal with
// the real classification instead of zeros.
class SourceQualityError : public std::runtime_error {
 public:
  SourceQualityError(std::string message, semantics::SourceCensus census)
      : std::runtime_error(std::move(message)), census_(census) {}
  const semantics::SourceCensus& census() const { return census_; }

 private:
  semantics::SourceCensus census_;
};

struct GeneratedProject {
  std::filesystem::path guest_source;
  std::vector<std::filesystem::path> runtime_sources;
  std::uint64_t image_base{};
  std::uint64_t stack_top{};
  std::uint64_t heap_base{};
  std::size_t function_count{};
  std::size_t import_count{};
  std::size_t high_level_function_count{};
  // The classification that produced the bytes in guest_source, copied from the
  // same LiftedProgram that was written, so a report cannot describe other source.
  std::vector<semantics::FunctionSourceRecord> source_records;
  semantics::SourceCensus source_census;
};

class ProjectGenerator {
 public:
  ProjectGenerator(const binary::PortableExecutable& executable,
                   const discovery::FunctionDiscovery& discovery,
                   const semantics::X86_64Lifter& lifter,
                   const binary::LoadedImage& loaded_image,
                   const common::Configuration& configuration)
      : executable_(executable), discovery_(discovery), lifter_(lifter), loaded_image_(loaded_image),
        configuration_(configuration) {}

  GeneratedProject generate(const std::filesystem::path& output_directory) const;

 private:
  std::string build_guest_source(semantics::LiftedProgram& lifted) const;

  const binary::PortableExecutable& executable_;
  const discovery::FunctionDiscovery& discovery_;
  const semantics::X86_64Lifter& lifter_;
  const binary::LoadedImage& loaded_image_;
  const common::Configuration& configuration_;
};

}  // namespace recomp::codegen
