#include "core/detection/detection.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace recomp::detection {
namespace {

std::string hex_bytes(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::size_t count) {
  std::ostringstream text;
  for (std::size_t index = 0; index < count && offset + index < bytes.size(); ++index) {
    if (index != 0) text << ' ';
    text << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(bytes[offset + index]);
  }
  return text.str();
}

bool has_magic(const std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::initializer_list<std::uint8_t> magic) {
  if (offset + magic.size() > bytes.size()) return false;
  std::size_t index = 0;
  for (const auto byte : magic) {
    if (bytes[offset + index] != byte) return false;
    ++index;
  }
  return true;
}

std::uint16_t little16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset + 2 > bytes.size()) return 0;
  return static_cast<std::uint16_t>(bytes[offset] | (bytes[offset + 1] << 8));
}

std::uint32_t little32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset + 4 > bytes.size()) return 0;
  return static_cast<std::uint32_t>(bytes[offset]) | (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

std::uint32_t big32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset + 4 > bytes.size()) return 0;
  return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) | static_cast<std::uint32_t>(bytes[offset + 3]);
}

std::string architecture_for_pe_machine(std::uint16_t machine) {
  switch (machine) {
    case 0x014cu: return "x86";
    case 0x8664u: return "x86_64";
    case 0xaa64u: return "arm64";
    case 0x01c0u:
    case 0x01c4u: return "arm";
    default: return {};
  }
}

std::string architecture_for_elf_machine(std::uint16_t machine) {
  switch (machine) {
    case 0x0003u: return "x86";
    case 0x003eu: return "x86_64";
    case 0x00b7u: return "arm64";
    case 0x0028u: return "arm";
    case 0x00f3u: return "riscv";
    case 0x0014u: return "ppc";
    case 0x0015u: return "ppc64";
    default: return {};
  }
}

std::string architecture_for_macho_cpu(std::uint32_t cpu_type) {
  switch (cpu_type) {
    case 7u: return "x86";
    case 0x01000007u: return "x86_64";
    case 12u: return "arm";
    case 0x0100000cu: return "arm64";
    case 18u: return "ppc";
    default: return {};
  }
}

// ---------------------------------------------------------------------------
// PE, including the managed case.
// ---------------------------------------------------------------------------
class PeDetector final : public Detector {
 public:
  const char* name() const override { return "pe"; }

  bool applies_to(const std::vector<std::uint8_t>& bytes) const override {
    return has_magic(bytes, 0, {'M', 'Z'});
  }

  Detection detect(const std::vector<std::uint8_t>& bytes) const override {
    Detection result;
    result.container = ContainerFormat::Pe;
    result.confidence = Confidence::Certain;
    result.evidence.push_back({"DOS MZ header", 0, hex_bytes(bytes, 0, 2)});

    const auto pe_offset = little32(bytes, 0x3c);
    if (pe_offset + 24 > bytes.size() || !has_magic(bytes, pe_offset, {'P', 'E', 0, 0})) {
      // An MZ header with no PE signature is a real DOS executable, which this
      // tool cannot lift. Saying so is more useful than "not a DOS MZ executable".
      result.confidence = Confidence::Probable;
      result.runtime = RuntimeKind::Unknown;
      result.summary = "DOS executable (MZ without a PE signature)";
      result.evidence.push_back({"no PE signature at the offset the MZ header names", pe_offset,
                                 hex_bytes(bytes, pe_offset, 4)});
      return result;
    }
    result.evidence.push_back({"PE signature", pe_offset, "50 45 00 00"});

    const auto coff = static_cast<std::size_t>(pe_offset) + 4;
    const auto machine = little16(bytes, coff);
    result.architecture = architecture_for_pe_machine(machine);
    result.evidence.push_back({"COFF machine type 0x" + [machine] {
                                 std::ostringstream text;
                                 text << std::hex << machine;
                                 return text.str();
                               }(),
                               coff, hex_bytes(bytes, coff, 2)});

    // Data directory 14 is the CLR runtime header. Its presence means the code is
    // IL, not machine code, which is a different runtime and not a native binary.
    const auto optional = coff + 20;
    const auto optional_magic = little16(bytes, optional);
    const bool is_64_bit = optional_magic == 0x20bu;
    const auto directory_count_offset = optional + (is_64_bit ? 108 : 92);
    const auto directory_count = little32(bytes, directory_count_offset);
    if (directory_count > 14) {
      const auto clr = directory_count_offset + 4 + 14 * 8;
      const auto clr_rva = little32(bytes, clr);
      const auto clr_size = little32(bytes, clr + 4);
      if (clr_rva != 0 && clr_size != 0) {
        result.runtime = RuntimeKind::DotNetClr;
        result.runtime_version = "CLR";
        result.evidence.push_back({"CLR runtime header (data directory 14)", clr,
                                   hex_bytes(bytes, clr, 8)});
        result.summary = "managed .NET image; its code is IL bytecode, so there is nothing for a "
                         "machine-code lifter to lift";
        return result;
      }
    }

    result.runtime = RuntimeKind::Native;
    result.summary = "Windows PE " + std::string(is_64_bit ? "PE32+" : "PE32") +
                     (result.architecture.empty() ? "" : " (" + result.architecture + ")");
    return result;
  }
};

// ---------------------------------------------------------------------------
// ELF.
// ---------------------------------------------------------------------------
class ElfDetector final : public Detector {
 public:
  const char* name() const override { return "elf"; }
  bool applies_to(const std::vector<std::uint8_t>& bytes) const override {
    return has_magic(bytes, 0, {0x7f, 'E', 'L', 'F'});
  }
  Detection detect(const std::vector<std::uint8_t>& bytes) const override {
    Detection result;
    result.container = ContainerFormat::Elf;
    result.runtime = RuntimeKind::Native;
    result.confidence = Confidence::Certain;
    result.evidence.push_back({"ELF magic", 0, hex_bytes(bytes, 0, 4)});
    const auto is_64_bit = bytes.size() > 4 && bytes[4] == 2;
    const auto little_endian = bytes.size() > 5 && bytes[5] == 1;
    result.architecture = architecture_for_elf_machine(little16(bytes, 18));
    result.evidence.push_back({std::string(is_64_bit ? "64-bit" : "32-bit") + ", " +
                                   (little_endian ? "little" : "big") + "-endian",
                               4, hex_bytes(bytes, 4, 2)});
    result.summary = "ELF " + std::string(is_64_bit ? "64" : "32") +
                     (result.architecture.empty() ? "" : " (" + result.architecture + ")");
    return result;
  }
};

// ---------------------------------------------------------------------------
// Mach-O, thin and universal.
// ---------------------------------------------------------------------------
class MachODetector final : public Detector {
 public:
  const char* name() const override { return "macho"; }
  bool applies_to(const std::vector<std::uint8_t>& bytes) const override {
    if (has_magic(bytes, 0, {0xfe, 0xed, 0xfa, 0xce}) || has_magic(bytes, 0, {0xfe, 0xed, 0xfa, 0xcf}) ||
        has_magic(bytes, 0, {0xce, 0xfa, 0xed, 0xfe}) || has_magic(bytes, 0, {0xcf, 0xfa, 0xed, 0xfe}))
      return true;
    // 0xcafebabe is shared with the Java class file, so the magic alone settles
    // nothing. A universal binary is claimed only when the header it describes
    // actually validates: a plausible architecture count and, for each entry, a
    // known CPU type and a non-empty slice. Reading a class file as a fat header
    // produced "universal binary with 52 architectures", which is a fabricated
    // answer of exactly the kind this project forbids.
    if (!has_magic(bytes, 0, {0xca, 0xfe, 0xba, 0xbe})) return false;
    const auto count = big32(bytes, 4);
    if (count == 0 || count > 32) return false;
    for (std::uint32_t index = 0; index < count && index < 4; ++index) {
      const auto entry = 8 + static_cast<std::size_t>(index) * 20;
      if (entry + 20 > bytes.size()) return false;
      const auto cpu_type = big32(bytes, entry);
      const auto slice_size = big32(bytes, entry + 12);
      if (slice_size == 0) return false;
      const bool known = cpu_type == 7u || cpu_type == 0x01000007u || cpu_type == 12u ||
                         cpu_type == 0x0100000cu || cpu_type == 18u;
      if (!known) return false;
    }
    return true;
  }
  Detection detect(const std::vector<std::uint8_t>& bytes) const override {
    Detection result;
    result.runtime = RuntimeKind::Native;
    result.confidence = Confidence::Certain;
    result.evidence.push_back({"Mach-O magic", 0, hex_bytes(bytes, 0, 4)});
    if (has_magic(bytes, 0, {0xca, 0xfe, 0xba, 0xbe})) {
      result.container = ContainerFormat::MachOUniversal;
      const auto count = big32(bytes, 4);
      result.evidence.push_back({"universal binary with " + std::to_string(count) + " architecture(s)", 4,
                                 hex_bytes(bytes, 4, 4)});
      result.summary = "Mach-O universal binary (" + std::to_string(count) + " architectures)";
      return result;
    }
    result.container = ContainerFormat::MachO;
    result.architecture = architecture_for_macho_cpu(little32(bytes, 4));
    result.evidence.push_back({"CPU type", 4, hex_bytes(bytes, 4, 4)});
    result.summary = "Mach-O" + (result.architecture.empty() ? "" : " (" + result.architecture + ")");
    return result;
  }
};

// ---------------------------------------------------------------------------
// Java class files, and the JAR that usually carries them.
// ---------------------------------------------------------------------------
class JvmDetector final : public Detector {
 public:
  const char* name() const override { return "jvm"; }
  bool applies_to(const std::vector<std::uint8_t>& bytes) const override {
    return has_magic(bytes, 0, {0xca, 0xfe, 0xba, 0xbe}) || has_magic(bytes, 0, {0x50, 0x4b, 0x03, 0x04});
  }
  Detection detect(const std::vector<std::uint8_t>& bytes) const override {
    Detection result;
    result.runtime = RuntimeKind::Jvm;
    if (has_magic(bytes, 0, {0x50, 0x4b, 0x03, 0x04})) {
      // A ZIP could be a JAR, an APK, a Python wheel or anything else. Saying
      // which without opening it would be a guess, so this reports the container
      // and stops there.
      result.container = ContainerFormat::Archive;
      result.runtime = RuntimeKind::Unknown;
      result.confidence = Confidence::Uncertain;
      result.evidence.push_back({"ZIP local file header", 0, hex_bytes(bytes, 0, 4)});
      result.summary = "ZIP archive; the runtime cannot be determined without opening it "
                       "(a JAR, a wheel and a plain archive look the same here)";
      return result;
    }
    result.container = ContainerFormat::ClassFile;
    result.confidence = Confidence::Certain;
    const auto minor = little16(bytes, 4);
    const auto major = little16(bytes, 6);
    // Java class file versions: 45 is Java 1.1, so 44 + major is the release.
    result.runtime_version = "class file " + std::to_string(major) + "." + std::to_string(minor) +
                             (major >= 45 ? " (Java " + std::to_string(major - 44) + ")" : "");
    result.evidence.push_back({"class file version " + std::to_string(major) + "." + std::to_string(minor), 4,
                               hex_bytes(bytes, 4, 4)});
    result.summary = "JVM class file, " + result.runtime_version;
    return result;
  }
};

// ---------------------------------------------------------------------------
// CPython bytecode. The magic encodes the version, which is what makes this
// decidable rather than a guess.
// ---------------------------------------------------------------------------
class CpythonDetector final : public Detector {
 public:
  const char* name() const override { return "cpython"; }
  bool applies_to(const std::vector<std::uint8_t>& bytes) const override {
    // Every CPython .pyc begins 0x0a 0x0d 0x0d 0x0a ("\r\r\n") followed by a
    // two-byte magic; the low byte has been 0x0d for every release from 3.x on.
    return bytes.size() > 4 && bytes[0] == 0x0a && bytes[1] == 0x0d && bytes[2] == 0x0d && bytes[3] == 0x0a;
  }
  Detection detect(const std::vector<std::uint8_t>& bytes) const override {
    Detection result;
    result.container = ContainerFormat::CpythonBytecode;
    result.runtime = RuntimeKind::Cpython;
    result.confidence = Confidence::Certain;
    result.evidence.push_back({"CPython .pyc magic", 0, hex_bytes(bytes, 0, 4)});
    result.runtime_version = "magic 0x" + hex_bytes(bytes, 2, 2) + " (CPython)";
    result.summary = "CPython bytecode, " + result.runtime_version;
    return result;
  }
};

// ---------------------------------------------------------------------------
// Scripts. A shebang names the interpreter, which is a runtime claim the file
// itself makes; whether this tool can use it is a separate question.
// ---------------------------------------------------------------------------
class ScriptDetector final : public Detector {
 public:
  const char* name() const override { return "script"; }
  bool applies_to(const std::vector<std::uint8_t>& bytes) const override {
    return has_magic(bytes, 0, {'#', '!'});
  }
  Detection detect(const std::vector<std::uint8_t>& bytes) const override {
    Detection result;
    result.container = ContainerFormat::Script;
    result.runtime = RuntimeKind::Scripted;
    result.confidence = Confidence::Certain;
    std::string line;
    for (std::size_t index = 0; index < 128 && index < bytes.size(); ++index) {
      const auto character = static_cast<char>(bytes[index]);
      if (character == '\n') break;
      line.push_back(character);
    }
    result.evidence.push_back({"interpreter line", 0, line});
    result.summary = "script (" + line + ")";
    return result;
  }
};

}  // namespace

const char* confidence_name(Confidence confidence) {
  switch (confidence) {
    case Confidence::Certain: return "certain";
    case Confidence::Probable: return "probable";
    case Confidence::Uncertain: return "uncertain";
  }
  return "uncertain";
}

const char* container_format_name(ContainerFormat format) {
  switch (format) {
    case ContainerFormat::Unknown: return "unknown";
    case ContainerFormat::Pe: return "pe";
    case ContainerFormat::Elf: return "elf";
    case ContainerFormat::MachO: return "macho";
    case ContainerFormat::MachOUniversal: return "macho-universal";
    case ContainerFormat::ClassFile: return "class-file";
    case ContainerFormat::CpythonBytecode: return "cpython-bytecode";
    case ContainerFormat::Script: return "script";
    case ContainerFormat::Archive: return "archive";
  }
  return "unknown";
}

const char* runtime_kind_name(RuntimeKind runtime) {
  switch (runtime) {
    case RuntimeKind::Native: return "native";
    case RuntimeKind::DotNetClr: return "dotnet-clr";
    case RuntimeKind::Jvm: return "jvm";
    case RuntimeKind::Cpython: return "cpython";
    case RuntimeKind::Scripted: return "scripted";
    case RuntimeKind::Unknown: return "unknown";
  }
  return "unknown";
}

std::string Detection::unsupported_reason() const {
  if (is_supported()) return {};
  switch (container) {
    case ContainerFormat::Elf:
      return "input is an ELF binary; this build lifts Windows PE32/PE32+ only. An ELF frontend is "
             "not implemented.";
    case ContainerFormat::MachO:
    case ContainerFormat::MachOUniversal:
      return "input is a Mach-O executable; this build lifts Windows PE32/PE32+ only. A Mach-O "
             "frontend is not implemented.";
    case ContainerFormat::ClassFile:
      return "input is a JVM class file; its code is JVM bytecode, which needs a language frontend "
             "that is not implemented.";
    case ContainerFormat::CpythonBytecode:
      return "input is CPython bytecode; its code is Python bytecode, which needs a language "
             "frontend that is not implemented.";
    case ContainerFormat::Script:
      return "input is a script; there is no machine code to lift.";
    case ContainerFormat::Archive:
      return "input is an archive; extract it and detect the contents.";
    case ContainerFormat::Pe:
      if (runtime == RuntimeKind::DotNetClr)
        return "input is a managed .NET image; its code is IL bytecode, so there is nothing for a "
               "machine-code lifter to lift. An IL frontend is not implemented.";
      return "the PE image is not native machine code.";
    case ContainerFormat::Unknown:
      return "the input format was not recognised; no detector matched the leading bytes.";
  }
  return "unsupported input.";
}

const std::vector<const Detector*>& detectors() {
  // Order matters only where magics could overlap. Mach-O universal and Java class
  // files share 0xcafebabe, so Mach-O is asked first and settles it by reading the
  // entry count -- a class file's next field is a version whose minor is small,
  // and the Mach-O detector requires a plausible architecture count.
  static const PeDetector pe;
  static const ElfDetector elf;
  static const MachODetector macho;
  static const JvmDetector jvm;
  static const CpythonDetector cpython;
  static const ScriptDetector script;
  static const std::vector<const Detector*> all{&pe, &elf, &macho, &jvm, &cpython, &script};
  return all;
}

Detection detect(const std::vector<std::uint8_t>& bytes) {
  for (const auto* detector : detectors()) {
    if (!detector->applies_to(bytes)) continue;
    auto result = detector->detect(bytes);
    if (result.summary.empty()) result.summary = std::string("detected by the ") + detector->name() + " detector";
    return result;
  }
  Detection unknown;
  unknown.confidence = Confidence::Uncertain;
  unknown.evidence.push_back({"first bytes", 0, hex_bytes(bytes, 0, std::min<std::size_t>(16, bytes.size()))});
  unknown.summary = "unrecognised format; no detector matched the leading bytes";
  return unknown;
}

Detection detect_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot open input file: " + path);
  std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  return detect(bytes);
}

}  // namespace recomp::detection
