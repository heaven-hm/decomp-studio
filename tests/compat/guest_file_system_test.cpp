// The guest path policy, tested on its own.
//
// Every file-facing shim goes through this resolution, so the cases that matter
// are the ones where a wrong answer is invisible: a path that escapes the app
// directory and is served anyway, or a path that is refused and makes an app fail
// for a reason nobody can see in the output. Both are checked here directly rather
// than through a guest program, which would only report the symptom.
#include "guest_file_system.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

using recomp::GuestFileSandbox;
using recomp::GuestPathStatus;

static int failures = 0;

static void expect(const std::string& what, bool condition, const std::string& detail) {
  if (condition) return;
  ++failures;
  std::printf("FAIL: %s (%s)\n", what.c_str(), detail.c_str());
}

static void expect_host(const GuestFileSandbox& sandbox, const std::string& guest,
                        const std::string& wanted) {
  const auto resolution = sandbox.resolve(guest);
  const auto canonical_wanted = std::filesystem::weakly_canonical(wanted);
  expect(guest, resolution.status == GuestPathStatus::Allowed &&
                    std::filesystem::path(resolution.host_path) == canonical_wanted,
         std::string(guest_path_status_name(resolution.status)) + " -> '" + resolution.host_path +
             "' " + resolution.reason);
}

static void expect_refused(const GuestFileSandbox& sandbox, const std::string& guest,
                           GuestPathStatus status) {
  const auto resolution = sandbox.resolve(guest);
  expect(guest, resolution.status == status,
         std::string("got ") + guest_path_status_name(resolution.status) + " -> '" +
             resolution.host_path + "'");
  // A refusal the reader cannot act on is not a refusal worth having.
  expect(guest, !resolution.reason.empty(), "the rejection carries no reason");
}

int main() {
  GuestFileSandbox sandbox;
  sandbox.set_root("/tmp/app/");

  // A bare filename is relative to the app directory, which is also the guest's
  // working directory.
  expect_host(sandbox, "savegame.dat", "/tmp/app/savegame.dat");
  expect_host(sandbox, "data\\levels\\01.bin", "/tmp/app/data/levels/01.bin");
  expect_host(sandbox, "./config.ini", "/tmp/app/config.ini");
  expect_host(sandbox, "sub/../config.ini", "/tmp/app/config.ini");

  // The drive letter is accepted and dropped: an app that built its path from its
  // own module name always starts with one.
  expect_host(sandbox, "C:\\Games\\MyApp\\config.ini", "/tmp/app/Games/MyApp/config.ini");
  expect_host(sandbox, "c:/relative/to/drive", "/tmp/app/relative/to/drive");
  expect_host(sandbox, "C:", "/tmp/app");

  // Absolute paths are rooted at the sandbox rather than at the host root, so a
  // guest that insists on an absolute path still stays inside its own tree.
  expect_host(sandbox, "/Windows/system32/drivers/etc/hosts", "/tmp/app/Windows/system32/drivers/etc/hosts");

  // Repeated and trailing separators, and `.` segments, all collapse.
  expect_host(sandbox, "a//b///c", "/tmp/app/a/b/c");
  expect_host(sandbox, "a/b/c/", "/tmp/app/a/b/c");

  // Climbing out is refused, however it is spelled.
  expect_refused(sandbox, "..", GuestPathStatus::OutsideSandbox);
  expect_refused(sandbox, "../elsewhere", GuestPathStatus::OutsideSandbox);
  expect_refused(sandbox, "a/../../elsewhere", GuestPathStatus::OutsideSandbox);
  expect_refused(sandbox, "C:\\..\\windows", GuestPathStatus::OutsideSandbox);

  // Forms with no honest host equivalent are reported as unsupported rather than
  // quietly mapped onto a local file that merely has a similar name.
  expect_refused(sandbox, "\\\\fileserver\\share\\data.bin", GuestPathStatus::UnsupportedForm);
  expect_refused(sandbox, "\\\\.\\COM1", GuestPathStatus::UnsupportedForm);
  expect_refused(sandbox, "", GuestPathStatus::Empty);

  // An extended-length path is the same path written differently, not a new form.
  expect_host(sandbox, "\\\\?\\C:\\Games\\MyApp\\x.dat", "/tmp/app/Games/MyApp/x.dat");

  // Without a selected app directory nothing resolves. This is the state a
  // generated project is in when nobody has said where the app lives, and the
  // answer must be a refusal with a reason, not a guess.
  GuestFileSandbox unarmed;
  expect_refused(unarmed, "data.bin", GuestPathStatus::OutsideSandbox);

  // A lexical child can still escape through a host symlink. The policy must
  // inspect the resolved host path before any file-facing shim opens it.
  const auto workspace = std::filesystem::temp_directory_path() /
                         ("recomp-sandbox-" + std::to_string(static_cast<long long>(::getpid())));
  const auto root = workspace / "app";
  const auto outside = workspace / "outside";
  std::filesystem::create_directories(root);
  std::filesystem::create_directories(outside);
  std::ofstream(outside / "secret.txt") << "outside";
  std::ofstream(root / "race.txt") << "inside";
  std::filesystem::create_directory_symlink(outside, root / "link");
  GuestFileSandbox symlink_sandbox;
  symlink_sandbox.set_root(root.string());
  expect_refused(symlink_sandbox, "link/secret.txt", GuestPathStatus::OutsideSandbox);

  const auto checked = symlink_sandbox.resolve("race.txt");
  expect("open checked file", checked.allowed(), checked.reason);
  if (checked.allowed()) {
    const auto descriptor = symlink_sandbox.open_resolved(checked.host_path, O_RDONLY);
    expect("open resolved file", descriptor >= 0, "open_resolved refused an in-sandbox file");
    if (descriptor >= 0) ::close(descriptor);
    std::filesystem::rename(root / "race.txt", root / "race-original.txt");
    std::filesystem::create_symlink(outside / "secret.txt", root / "race.txt");
    const auto raced_descriptor = symlink_sandbox.open_resolved(checked.host_path, O_RDONLY);
    expect("reject symlink swapped after check", raced_descriptor < 0,
           "open_resolved followed a symlink inserted after resolve()");
  }
  std::filesystem::remove_all(workspace);

  // Round-tripping a host path back into guest form has to produce something the
  // guest can feed into resolve() again and get the same file.
  const auto host_form = std::filesystem::weakly_canonical("/tmp/app/Games/MyApp/config.ini").string();
  const auto guest_form = sandbox.to_guest_path(host_form);
  expect_host(sandbox, guest_form, host_form);

  if (failures != 0) {
    std::printf("guest path policy: %d failure(s)\n", failures);
    return 1;
  }
  std::printf("guest path policy: all cases passed\n");
  return 0;
}
