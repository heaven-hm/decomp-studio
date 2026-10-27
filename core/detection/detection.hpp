#pragma once

// Deterministic input detection.
//
// Before anything is lifted, the pipeline has to know what it is holding. Today
// that question is answered by one `if` in the PE parser, which rejects everything
// else with "not a DOS MZ executable" -- true, and useless: it does not say what
// the file is, whether this tool could ever read it, or which capability is
// missing.
//
// This is the plug-in point. A detector examines bytes and reports what it found
// together with the evidence it used, so a future language-specific frontend
// (ILSpy for IL, Vineflower for JVM bytecode, a Python decompiler) can register
// here without the pipeline being redesigned. The decompilers themselves are NOT
// implemented -- what is implemented is the interface they will plug into, and
// honest detection for the formats that can be recognised without one.
//
// Two rules, both from the project's:
//   * A detector never guesses. When the evidence does not settle the question it
//     reports `Uncertain` and says what it saw, rather than naming a format it
//     cannot support.
//   * Detection never invents source. It reports metadata that is present in the
//     file; it does not reconstruct anything.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace recomp::detection {

// How sure the detector is, given the evidence it recorded.
enum class Confidence {
  Certain,    // the format's own magic, at the offset the format specifies
  Probable,   // a signature that is characteristic but not authoritative
  Uncertain,  // the bytes are recognisable but not identifiable
};

const char* confidence_name(Confidence confidence);

// The container the bytes are wrapped in.
enum class ContainerFormat { Unknown, Pe, Elf, MachO, MachOUniversal, ClassFile, CpythonBytecode, Script, Archive };

const char* container_format_name(ContainerFormat format);

// What executes the contents once the container is opened. Native machine code is
// lifted; the others need a language frontend that does not exist yet.
enum class RuntimeKind { Native, DotNetClr, Jvm, Cpython, Scripted, Unknown };

const char* runtime_kind_name(RuntimeKind runtime);

// One observed fact. The point of recording these is that a detection can be
// checked by a reader rather than trusted.
struct DetectionEvidence {
  std::string description;   // what was observed, in words
  std::uint64_t offset{};    // where in the file
  std::string bytes;         // the bytes, as hex, when they are the evidence
};

struct Detection {
  ContainerFormat container{ContainerFormat::Unknown};
  RuntimeKind runtime{RuntimeKind::Unknown};
  std::string architecture;       // "x86", "x86_64", "arm64", "" when unknown
  std::string runtime_version;    // e.g. "CLR 2.5", "Python 3.11", "" when unknown
  Confidence confidence{Confidence::Uncertain};
  std::vector<DetectionEvidence> evidence;
  std::string summary;            // one line, for the CLI

  // Whether the current pipeline can lift this. A format can be detected
  // correctly and still be unsupported; the reason says which, and why.
  bool is_supported() const { return container == ContainerFormat::Pe && runtime == RuntimeKind::Native; }
  std::string unsupported_reason() const;
};

// A detector for one family of formats. Registering these behind one interface is
// the whole point: adding a language frontend later must not change the pipeline.
class Detector {
 public:
  virtual ~Detector() = default;
  virtual const char* name() const = 0;
  // Cheap: does this detector recognise the leading bytes at all?
  virtual bool applies_to(const std::vector<std::uint8_t>& bytes) const = 0;
  virtual Detection detect(const std::vector<std::uint8_t>& bytes) const = 0;
};

// The detectors the pipeline consults, in order. Exposed so a test can check the
// order rather than assume it.
const std::vector<const Detector*>& detectors();

// Runs the detectors and returns the first conclusion, or an Unknown detection
// carrying the evidence that nothing matched.
Detection detect(const std::vector<std::uint8_t>& bytes);

// Reads the file and detects. Throws when the file cannot be read.
Detection detect_file(const std::string& path);

}  // namespace recomp::detection
