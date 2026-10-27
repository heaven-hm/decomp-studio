#pragma once

// Guest path translation and the host-file policy that goes with it.
//
// A Windows path in a guest register is a string, not a capability: it names a
// drive, a directory tree and a separator convention that do not exist here. The
// runtime has to turn it into something it can actually open, and it has to do so
// without handing a recompiled program the keys to the machine it runs on. An app
// that opens "savegame.dat" or "C:\Games\MyApp\config.ini" means a file belonging
// to itself, so both resolve inside the app directory; an app that asks for
// something above that directory is refused rather than served.
//
// Refusing is the whole point. A silent escape is not detected by anything else in
// the pipeline -- the program simply works, and the first time anyone learns that
// the recompiled build reads the user's real files is when it writes over them.
// The rejection is reported with the reason, so the next step is a decision
// (widen the app directory, or add a provider) instead of a mystery.

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace recomp {

// How a guest path resolved, in the order the checks are applied.
enum class GuestPathStatus : std::uint32_t {
  Allowed = 0,       // resolved to a host path inside the sandbox
  Empty = 1,         // the guest passed no path at all
  OutsideSandbox = 2,  // a `..` climb, or an absolute path above the sandbox root
  UnsupportedForm = 3,  // UNC share, device namespace, or a form with no host meaning
};

struct GuestPathResolution {
  GuestPathStatus status{GuestPathStatus::Allowed};
  std::string host_path;  // meaningful only when status is Allowed
  std::string reason;     // what made this refusal a refusal, for diagnostics

  bool allowed() const { return status == GuestPathStatus::Allowed; }
};

inline const char* guest_path_status_name(GuestPathStatus status) {
  switch (status) {
    case GuestPathStatus::Allowed: return "allowed";
    case GuestPathStatus::Empty: return "empty";
    case GuestPathStatus::OutsideSandbox: return "outside-sandbox";
    case GuestPathStatus::UnsupportedForm: return "unsupported-form";
  }
  return "unknown";
}

// The directory a recompiled app is allowed to touch. Every guest path resolves
// inside it, and it doubles as the guest's current directory, which is what an
// app that opens a bare filename expects.
class GuestFileSandbox {
 public:
  // The sandbox root in host form, with no trailing separator. Empty means the
  // policy is not armed and no path may be opened.
  const std::string& root() const { return root_; }

  void set_root(std::string root) {
    std::error_code error;
    const auto canonical = std::filesystem::weakly_canonical(root, error);
    root_ = error ? std::filesystem::path(std::move(root)).lexically_normal().string() : canonical.string();
    trim_trailing_separators(root_);
  }

  // True when a root has been chosen, so file services may resolve paths.
  bool armed() const { return !root_.empty(); }

  // Resolves a guest path to a host path, or explains why it will not.
  //
  // `guest_path` is in the form the guest used: backslashes, an optional drive
  // letter, possibly a UNC name. The drive letter is accepted and discarded --
  // rejecting it would break every app that builds a path from its own module
  // name, which on Windows always starts with a drive.
  GuestPathResolution resolve(const std::string& guest_path) const {
    GuestPathResolution resolution;
    if (guest_path.empty()) {
      resolution.status = GuestPathStatus::Empty;
      resolution.reason = "the guest passed an empty path";
      return resolution;
    }
    if (root_.empty()) {
      resolution.status = GuestPathStatus::OutsideSandbox;
      resolution.reason = "no app directory is selected, so no guest path may be opened";
      return resolution;
    }

    std::string path = guest_path;
    for (auto& character : path)
      if (character == '\\') character = '/';

    // The extended-length prefix carries no information here; every path is
    // already handled as a string and resolved lexically. A `\\?\UNC\share\dir`
    // spelling keeps the UNC test below to catch.
    if (path.rfind("//?/GLOBALROOT/", 0) == 0) {
      resolution.status = GuestPathStatus::UnsupportedForm;
      resolution.reason = "the object namespace is not provided: " + guest_path;
      return resolution;
    }
    if (path.rfind("//?/UNC/", 0) == 0) path = "//" + path.substr(6);
    else if (path.rfind("//?/", 0) == 0) path.erase(0, 4);

    // A device namespace name (\\.\COM1, \\?\GLOBALROOT\...) has no host
    // equivalent that could be substituted honestly.
    if (path.rfind("//./", 0) == 0 || path.rfind("//;/", 0) == 0) {
      resolution.status = GuestPathStatus::UnsupportedForm;
      resolution.reason = "device namespace paths have no host equivalent: " + guest_path;
      return resolution;
    }

    // A UNC name names a share on another machine. Refusing is the honest answer:
    // mapping it into the sandbox would turn a network path into a local file
    // that happens to have a similar name.
    if (path.rfind("//", 0) == 0) {
      resolution.status = GuestPathStatus::UnsupportedForm;
      resolution.reason = "UNC share paths are not provided: " + guest_path;
      return resolution;
    }

    // Drive-qualified: the letter is dropped and the remainder is taken relative
    // to the app directory. `C:foo` (drive-relative with no root) is the same
    // thing here, because the sandbox is also the drive's current directory.
    if (is_drive_prefix(path)) path.erase(0, 2);

    const bool absolute = !path.empty() && path.front() == '/';
    auto components = normalize(path);
    (void)absolute;  // both forms are rooted at the sandbox: it is the app's whole world

    for (const auto& component : components) {
      if (component == "..") {
        resolution.status = GuestPathStatus::OutsideSandbox;
        resolution.reason =
            "'" + guest_path + "' resolves above the app directory '" + root_ + "'";
        return resolution;
      }
    }
    auto candidate = std::filesystem::path(root_);
    for (const auto& component : components) candidate /= component;

    // Lexical normalization catches explicit `..`; canonicalization also resolves
    // existing symlinks. A link inside the app directory must not turn an allowed
    // guest path into a host path outside the app directory.
    std::error_code candidate_error;
    std::error_code root_error;
    const auto canonical = std::filesystem::weakly_canonical(candidate, candidate_error);
    const auto canonical_root = std::filesystem::weakly_canonical(root_, root_error);
    if (candidate_error || root_error || !is_within_root(canonical, canonical_root)) {
      resolution.status = GuestPathStatus::OutsideSandbox;
      resolution.reason = "'" + guest_path + "' resolves outside the app directory '" + root_ + "'";
      return resolution;
    }
    resolution.status = GuestPathStatus::Allowed;
    resolution.host_path = canonical.string();
    return resolution;
  }

  // Opens a previously resolved path relative to a pinned sandbox directory.
  // Each component refuses symlinks, so a link swap between resolve() and open
  // cannot redirect a guest file request outside the selected app directory.
  int open_resolved(const std::string& host_path, int flags, unsigned mode = 0) const {
    if (root_.empty()) return -1;
    std::error_code root_error;
    const auto canonical_root = std::filesystem::weakly_canonical(root_, root_error);
    if (root_error) return -1;
    const auto relative = std::filesystem::path(host_path).lexically_relative(canonical_root);
    if (relative.empty() || relative.is_absolute()) return -1;
    for (const auto& component : relative)
      if (component == ".." || component == ".") return -1;

    int directory = ::open(canonical_root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return -1;
    auto component = relative.begin();
    while (component != relative.end()) {
      auto next = component;
      ++next;
      const bool final = next == relative.end();
      const auto name = component->string();
      const auto opened = final
                              ? ::openat(directory, name.c_str(), flags | O_CLOEXEC | O_NOFOLLOW, mode)
                              : ::openat(directory, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (directory >= 0) ::close(directory);
      if (final) return opened;
      if (opened < 0) return -1;
      directory = opened;
      component = next;
    }
    ::close(directory);
    return -1;
  }

  // Presents a host path back to the guest in the Windows form it expects:
  // backslashes and a drive letter, rooted at the sandbox. An app that reads
  // GetModuleFileNameA and appends a data filename must get something it can
  // feed straight back into CreateFileA.
  std::string to_guest_path(const std::string& host_path, char drive = 'C') const {
    std::string relative = host_path;
    if (relative.rfind(root_, 0) == 0) relative.erase(0, root_.size());
    for (auto& character : relative)
      if (character == '/') character = '\\';
    if (!relative.empty() && relative.front() != '\\') relative.insert(relative.begin(), '\\');
    return std::string(1, static_cast<char>(std::toupper(static_cast<unsigned char>(drive)))) + ":" + relative;
  }

 private:
  static bool is_drive_prefix(const std::string& path) {
    return path.size() >= 2 && path[1] == ':' &&
           std::isalpha(static_cast<unsigned char>(path[0])) != 0;
  }

  static void trim_trailing_separators(std::string& path) {
    while (path.size() > 1 && (path.back() == '/' || path.back() == '\\')) path.pop_back();
  }

  static bool is_within_root(const std::filesystem::path& candidate,
                             const std::filesystem::path& root) {
    const auto relative = candidate.lexically_relative(root);
    if (relative.empty()) return candidate == root;
    if (relative.is_absolute()) return false;
    const auto first = relative.begin();
    return first == relative.end() || *first != "..";
  }

  // Collapses `.`, `..`, empty and repeated separators lexically before host
  // symlink resolution applies the final containment check.
  static std::vector<std::string> normalize(const std::string& path) {
    std::vector<std::string> components;
    std::size_t index = 0;
    while (index < path.size()) {
      while (index < path.size() && path[index] == '/') ++index;
      std::size_t end = index;
      while (end < path.size() && path[end] != '/') ++end;
      const auto component = path.substr(index, end - index);
      index = end;
      if (component.empty() || component == ".") continue;
      if (component == "..") {
        if (!components.empty() && components.back() != "..") {
          components.pop_back();
          continue;
        }
        components.push_back("..");
        continue;
      }
      components.push_back(component);
    }
    return components;
  }

  std::string root_;
};

// The sandbox every file-facing shim resolves through. One object, because the
// policy has to be the same for kernel32 file calls, the CRT streams and the
// differential reference; two policies would be two answers to "which file did
// the guest open".
inline GuestFileSandbox& guest_file_sandbox() {
  static GuestFileSandbox sandbox;
  return sandbox;
}

}  // namespace recomp
