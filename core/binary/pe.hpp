#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace recomp::binary {

struct Section {
  std::string name;
  std::uint32_t virtual_address{};
  std::uint32_t virtual_size{};
  std::uint32_t raw_offset{};
  std::uint32_t raw_size{};
  std::uint32_t characteristics{};

  std::uint32_t end_virtual_address() const {
    return virtual_address + std::max(virtual_size, raw_size);
  }
  bool is_executable() const { return (characteristics & 0x20000000u) != 0; }
  bool is_readable() const { return (characteristics & 0x40000000u) != 0; }
  bool is_writable() const { return (characteristics & 0x80000000u) != 0; }
  // Shareable sections are backed by the file image, so a write to one is a write
  // the OS would propagate; self-modifying-code detection has to know which ones
  // are writable *and* executable, which is exactly this pair plus execute.
  bool is_shared() const { return (characteristics & 0x08000000u) != 0; }
  bool contains_code() const { return (characteristics & 0x00000020u) != 0; }

  // The protection as the loader would apply it, spelled the way the reports
  // read. A section that is both writable and executable is worth naming in a
  // report, because it is where a recompiled program's translated code can be
  // overwritten at run time.
  std::string protection() const {
    std::string text;
    if (is_executable()) text += "X";
    if (is_writable()) text += "W";
    if (is_readable()) text += "R";
    if (text.empty()) text = "---";
    return text;
  }
};

struct ImportedSymbol {
  std::uint32_t import_address_table_rva{};
  std::string library_name;
  std::string symbol_name;

  // An import can be by ordinal rather than by name, and the two are not the same
  // question to answer: "#140" is not a name a shim table can be matched against,
  // so the report has to say it is an ordinal and give the number, otherwise an
  // ordinal import reads like an unimplemented function whose name nobody has.
  bool by_ordinal{};
  std::uint32_t ordinal{};

  // The delay-load table is not in the import directory. A program that
  // delay-loads d3d9.dll does not name it until it calls it, so a static import
  // census that ignores this table reports a program as needing less than it does
  // and the missing requirement shows up as a crash instead of as a gap.
  bool from_delay_table{};

  // How the symbol is named, for reports: the name, or "ordinal 140".
  std::string display_name() const {
    if (by_ordinal && symbol_name.empty()) return "ordinal " + std::to_string(ordinal);
    return symbol_name;
  }
};

struct ExportedSymbol {
  std::uint32_t rva{};
  std::string name;

  // An export whose RVA lands inside the export directory is not code: it is a
  // forwarder, a string naming another DLL's export. API sets (api-ms-win-*) are
  // nothing but forwarders, so resolving a guest's import to a real
  // implementation depends on following them rather than treating the alias as a
  // library with no exports.
  bool is_forwarder{};
  std::string forward_name;
};

struct BaseRelocation {
  std::uint32_t rva{};
  std::uint16_t type{};
};

class ParseError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class PortableExecutable {
 public:
  static PortableExecutable parse(const std::filesystem::path& path);

  std::filesystem::path path;
  std::vector<std::uint8_t> file_bytes;
  bool is_64_bit{};
  std::uint16_t machine{};
  bool is_dynamic_library{};
  std::uint32_t entry_point_rva{};
  std::uint64_t image_base{};
  std::uint32_t size_of_image{};
  std::uint32_t size_of_headers{};
  std::uint32_t size_of_code{};
  std::uint16_t subsystem{};
  std::vector<Section> sections;
  std::vector<ImportedSymbol> imports;
  std::vector<ExportedSymbol> exports;
  std::vector<BaseRelocation> base_relocations;
  std::vector<std::uint32_t> tls_callback_rvas;

  // A Win32 resource: the (type, id, language) leaf of the resource tree, with
  // where its bytes live. Icons, cursors, menus, dialog templates and accelerators
  // are all found this way, so a GUI shim that has to hand the guest a resource --
  // LoadIcon, LoadCursor, a menu from a template -- starts here, not with a guess
  // about which file the resource was compiled into.
  struct Resource {
    std::uint32_t type{};
    std::uint32_t id{};
    std::uint32_t language{};
    std::uint32_t code_page{};
    std::uint32_t rva{};
    std::uint32_t size{};
    // Set when the type was named rather than numbered, which happens for the
    // standard types only rarely but is legal.
    std::string type_name;
  };
  std::vector<Resource> resources;

  // The application manifest, when one is embedded. This is not decoration: the
  // manifest is what asks for comctl32 v6, and an app that gets the version-5
  // common controls instead of the version-6 ones it asked for looks like a shim
  // bug while behaving like a different operating system.
  std::string manifest;

  // True when the manifest declares a dependency on Microsoft.Windows.Common-Controls
  // version 6, which is the only way a program asks for the themed controls.
  bool requests_common_controls_v6{};

  // Every DLL this image names, from the import table and the delay-load table,
  // lowercased and de-duplicated. Dependency discovery is what tells a capability
  // resolver which providers have to exist before the program can run, and the
  // delay-load table is part of the answer.
  std::vector<std::string> dependent_dlls;

  // Control Flow Guard. A CFG-compiled binary routes indirect calls through
  // guard-checking thunks, so its real indirect targets are not in the code the
  // disassembler sees; recording that the image uses CFG is the difference
  // between "we could not recover this call" and "this call is checked at run
  // time and we have to model the check".
  bool has_control_flow_guard{};
  std::uint32_t guard_flags{};

  // Set when the image is packed, so the machine code is not the machine code in
  // the file. Recovering functions from a packed image decodes whatever happens
  // to be there — UPX leaves whole sections as zero padding, which decodes
  // happily as `add [eax], al` — and produces a confident, wrong answer.
  std::string packing_reason;
  bool is_packed() const { return !packing_reason.empty(); }

  // A managed image (.NET) keeps its code as IL bytecode in the CLR metadata,
  // not as native machine code. The CLR runtime header is data directory 14, so
  // a non-zero RVA there is what distinguishes it.
  std::uint32_t clr_runtime_header_rva{};
  std::string managed_reason;
  bool is_managed() const { return !managed_reason.empty(); }

  std::string format_name() const { return is_64_bit ? "PE32+" : "PE32"; }
  std::string architecture_name() const { return is_64_bit ? "x86_64" : "x86"; }

  const Section* section_containing(std::uint32_t rva) const;
  std::optional<std::uint32_t> file_offset_for_rva(std::uint32_t rva) const;
  std::vector<std::uint8_t> read_rva(std::uint32_t rva, std::size_t count) const;
  std::optional<std::uint16_t> read_u16(std::uint32_t rva) const;
  std::optional<std::uint32_t> read_u32(std::uint32_t rva) const;
  std::optional<std::uint64_t> read_u64(std::uint32_t rva) const;
  std::string read_c_string(std::uint32_t rva, std::size_t limit = 4096) const;
  const Section* text_section() const;
  std::vector<const Section*> executable_sections() const;

  // A section that is writable and executable at once: the place a program can
  // change its own running code. A recompiler that lays out translated code
  // without noticing this produces a binary that works until the first patch.
  std::vector<const Section*> writable_executable_sections() const;

  // The first resource of a type and id, or nullptr. `RT_*` numbers are the
  // loader's own, so a shim asking for an icon asks for RT_ICON (3) by number.
  const Resource* find_resource(std::uint32_t type, std::uint32_t id) const;
};

struct LoadedImage {
  std::uint64_t load_base{};
  std::vector<std::uint8_t> image_bytes;
};

LoadedImage load_image(const PortableExecutable& executable, std::uint64_t load_base);

}  // namespace recomp::binary
