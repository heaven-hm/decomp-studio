// The CRT and kernel32 file layer, driven directly through the shared shim table.
//
// A guest program reaches these through imports, which makes a runtime failure look
// like a translation failure. Calling the shims here keeps the two apart, and runs
// both guest widths: the same calls made as PE32 and as PE32+ are how the argument
// conventions get checked against each other rather than assumed to agree.
#include "recomp_runtime.hpp"
#include "win32_abi.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(const std::string& name, bool condition, const std::string& detail = {}) {
  if (condition) return;
  ++failures;
  std::printf("FAIL %s%s%s\n", name.c_str(), detail.empty() ? "" : ": ", detail.c_str());
}

// Runs one import the way the guest's own call site would, using exactly the
// places `import_argument` reads from: registers 1, 2, 8, 9 then the stack for
// x64, and the stack above a return address for x86.
std::uint64_t call(recomp::GuestContext* context, const char* library, const char* symbol,
                   const std::vector<std::uint64_t>& arguments) {
  using namespace recomp;
  for (auto& register_index : {1, 2, 8, 9}) context->registers[register_index] = 0;
  if (guest_pointer_width >= 8) {
    static const int order[4] = {1, 2, 8, 9};
    for (std::size_t index = 0; index < arguments.size() && index < 4; ++index)
      context->registers[order[index]] = arguments[index];
    // The caller reserves 0x20 of shadow space, so the fifth argument is at rsp+0x28.
    for (std::size_t index = 4; index < arguments.size(); ++index)
      store_guest_memory(context, context->registers[4] + 0x28 + (index - 4) * 8, arguments[index], 8);
  } else {
    // A `call` has pushed the return address, so argument 0 sits at [esp+4].
    for (std::size_t index = 0; index < arguments.size(); ++index)
      store_guest_memory(context, context->registers[4] + 4 + index * 4, arguments[index] & 0xffffffffu, 4);
  }
  if (!invoke_shared_shim(context, library, symbol)) {
    std::printf("FAIL %s!%s is not implemented\n", library, symbol);
    ++failures;
    return ~0ull;
  }
  return context->registers[0];
}

std::uint64_t guest_string(recomp::GuestContext* context, std::uint64_t address, const std::string& text) {
  for (std::size_t index = 0; index <= text.size(); ++index)
    recomp::store_guest_memory(context, address + index,
                               index < text.size() ? static_cast<std::uint8_t>(text[index]) : 0, 1);
  return address;
}

constexpr std::uint64_t kScratch = 0x0000000008000000ull;  // argument strings
constexpr std::uint64_t kBuffer = 0x0000000009000000ull;   // read/write buffers
// Each guest string gets its own slot. Reusing one address for several names
// silently rewrites the earlier ones, and a shim that fails on a path the test
// never meant to pass it is worse than no test.
constexpr std::uint64_t kPathWrite = kScratch + 0x000;
constexpr std::uint64_t kPathRaw = kScratch + 0x040;
constexpr std::uint64_t kPathHandle = kScratch + 0x080;
constexpr std::uint64_t kPathEscape = kScratch + 0x0c0;
constexpr std::uint64_t kPathDrive = kScratch + 0x100;
constexpr std::uint64_t kPathRoundTrip = kScratch + 0x140;
constexpr std::uint64_t kModeWrite = kScratch + 0x200;
constexpr std::uint64_t kModeRead = kScratch + 0x240;

}  // namespace

int main() {
  using namespace recomp;

  const auto directory = std::filesystem::temp_directory_path() / "recomp-crt-unit";
  ::setenv("RECOMP_APP_DIR", directory.c_str(), 1);
  // The name GetModuleFileNameA has to hand back: a program strips the last
  // component to find its own directory, so an answer with no final segment puts
  // it one level too high.
  ::setenv("RECOMP_APP_NAME", "unit_guest.exe", 1);
  // The shim writes through real host files; a run that leaves them behind makes
  // the next one see a file it did not create.
  std::error_code stale;
  std::filesystem::remove_all(directory, stale);
  std::filesystem::create_directories(directory);

  for (const int width : {8, 4}) {
    if (!map_guest_memory(kGuestAddressSpaceBytes)) return 1;
    guest_pointer_width = width;
    // Placed so the heap stays inside the guest's own pointer width: a PE32 image
    // cannot represent 0x168000000, so a block allocated there and written into an
    // IAT slot arrives truncated and the stream table is keyed on a different
    // address than the guest holds.
    const auto heap_base = width >= 8 ? 0x168000000ull : 0x60000000ull;
    const auto stack_top = width >= 8 ? 0x170000000ull : 0x70000000ull;
    initialize_guest_state(0x140000000, heap_base, stack_top);
    GuestContext context{};
    context.registers[4] = initial_guest_stack_pointer(stack_top, width);
    const std::string tag = "pe" + std::to_string(width * 8);

    const auto path = guest_string(&context, kPathWrite, "unit_write.dat");
    const auto raw_path = guest_string(&context, kPathRaw, "unit_raw.dat");
    const auto handle_path = guest_string(&context, kPathHandle, "unit_handle.dat");
    const auto escape_path = guest_string(&context, kPathEscape, "../recomp-escape-unit.dat");
    const auto drive_path = guest_string(&context, kPathDrive, "C:\\Games\\unit\\level.dat");
    const auto write_mode = guest_string(&context, kModeWrite, "wb");
    const auto read_mode = guest_string(&context, kModeRead, "rb");

    // ---- fopen / fwrite / fclose ----------------------------------------
    const auto stream = call(&context, "msvcrt.dll", "fopen", {path, write_mode});
    check(tag + "/fopen-write", stream != 0, "fopen returned NULL for " + directory.string());
    if (stream == 0) continue;
    const char payload[] = "abcdefghij";
    for (std::size_t index = 0; index < sizeof(payload); ++index)
      store_guest_memory(&context, kBuffer + index, static_cast<std::uint8_t>(payload[index]), 1);
    const auto written = call(&context, "msvcrt.dll", "fwrite", {kBuffer, 1, 10, stream});
    check(tag + "/fwrite", written == 10, "wrote " + std::to_string(written));
    check(tag + "/fclose", call(&context, "msvcrt.dll", "fclose", {stream}) == 0);
    // Checked here rather than at the end: the closed FILE* is a heap block, and a
    // later fopen can be handed the same address. Testing a stale pointer after it
    // has been reused measures the test, not the runtime.
    check(tag + "/_fileno-of-closed-stream",
          call(&context, "msvcrt.dll", "_fileno", {stream}) ==
              (width >= 8 ? static_cast<std::uint64_t>(-1) : 0xffffffffull));
    {
      std::ifstream input(directory / "unit_write.dat", std::ios::binary);
      const std::string contents((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
      check(tag + "/bytes-on-host", contents == "abcdefghij", "host file holds '" + contents + "'");
    }

    // ---- fopen / fread / ftell / fseek / feof ---------------------------
    const auto reading = call(&context, "msvcrt.dll", "fopen", {path, read_mode});
    check(tag + "/fopen-read", reading != 0);
    if (reading == 0) continue;
    const auto count = call(&context, "msvcrt.dll", "fread", {kBuffer + 0x400, 1, 10, reading});
    check(tag + "/fread-count", count == 10, "read " + std::to_string(count));
    std::string back;
    for (std::size_t index = 0; index < 10; ++index)
      back.push_back(static_cast<char>(load_guest_memory(&context, kBuffer + 0x400 + index, 1)));
    check(tag + "/fread-bytes", back == "abcdefghij", "got '" + back + "'");
    check(tag + "/ftell", call(&context, "msvcrt.dll", "ftell", {reading}) == 10);
    // A read that consumed the file exactly has not hit the end: feof means a read
    // tried to go past it, and reporting it early makes a caller abandon a file it
    // still has bytes in.
    check(tag + "/feof-not-yet", call(&context, "msvcrt.dll", "feof", {reading}) == 0);
    check(tag + "/fread-at-end", call(&context, "msvcrt.dll", "fread", {kBuffer + 0x400, 1, 4, reading}) == 0);
    check(tag + "/feof-after-short-read", call(&context, "msvcrt.dll", "feof", {reading}) == 1);
    check(tag + "/ferror-not-set", call(&context, "msvcrt.dll", "ferror", {reading}) == 0);

    check(tag + "/fseek-set", call(&context, "msvcrt.dll", "fseek", {reading, 2, 0}) == 0);
    check(tag + "/ftell-after-seek", call(&context, "msvcrt.dll", "ftell", {reading}) == 2);
    const auto byte = call(&context, "msvcrt.dll", "fgetc", {reading});
    check(tag + "/fgetc-after-seek", byte == 'c', "got " + std::to_string(byte));
    // ungetc hands the byte back and the following read returns it before advancing.
    call(&context, "msvcrt.dll", "ungetc", {'c', reading});
    check(tag + "/fgetc-after-ungetc", call(&context, "msvcrt.dll", "fgetc", {reading}) == 'c');
    check(tag + "/fgetc-advances", call(&context, "msvcrt.dll", "fgetc", {reading}) == 'd');
    // A negative offset reaches the shim as 0xfffffffc in a 64-bit register,
    // because the guest's own `long` is 32-bit. Treated as unsigned it lands past
    // the end and the next read reports zero bytes -- indistinguishable from an
    // empty file, which is why this is checked explicitly.
    check(tag + "/fseek-negative-from-end",
          call(&context, "msvcrt.dll", "fseek", {reading, 0xfffffffc, 2}) == 0);
    check(tag + "/ftell-from-end", call(&context, "msvcrt.dll", "ftell", {reading}) == 6,
          "ten bytes, seek(-4, SEEK_END): " + std::to_string(call(&context, "msvcrt.dll", "ftell", {reading})));
    check(tag + "/feof-cleared-by-seek", call(&context, "msvcrt.dll", "feof", {reading}) == 0);
    call(&context, "msvcrt.dll", "fclose", {reading});

    // ---- _open / _write / _close / _open / _read / _lseek ---------------
    const auto create_flags = std::uint64_t{0x0001} | 0x0100 | 0x0200;  // WONLY|CREAT|TRUNC
    const auto descriptor = call(&context, "msvcrt.dll", "_open", {raw_path, create_flags, 0644});
    check(tag + "/_open-write", descriptor != static_cast<std::uint64_t>(-1),
          "descriptor " + std::to_string(descriptor));
    check(tag + "/_write", call(&context, "msvcrt.dll", "_write", {descriptor, kBuffer, 10}) == 10);
    check(tag + "/_close", call(&context, "msvcrt.dll", "_close", {descriptor}) == 0);

    const auto reading_descriptor = call(&context, "msvcrt.dll", "_open", {raw_path, 0, 0});
    check(tag + "/_open-read", reading_descriptor != static_cast<std::uint64_t>(-1));
    check(tag + "/_read",
          call(&context, "msvcrt.dll", "_read", {reading_descriptor, kBuffer + 0x800, 10}) == 10);
    check(tag + "/_lseek-set", call(&context, "msvcrt.dll", "_lseek", {reading_descriptor, 0, 0}) == 0);
    const auto near_end = call(&context, "msvcrt.dll", "_lseek", {reading_descriptor, 0xfffffffc, 2});
    check(tag + "/_lseek-negative-from-end", near_end == 6,
          "seek(-4, SEEK_END) landed at " + std::to_string(near_end));
    const auto tail = call(&context, "msvcrt.dll", "_read", {reading_descriptor, kBuffer + 0x800, 4});
    check(tag + "/_read-after-seek-to-end", tail == 4, "read " + std::to_string(tail));
    check(tag + "/_close-read", call(&context, "msvcrt.dll", "_close", {reading_descriptor}) == 0);

    // ---- _fileno ---------------------------------------------------------
    const auto standard_out = call(&context, "msvcrt.dll", "__acrt_iob_func", {1});
    check(tag + "/_fileno-stdout", call(&context, "msvcrt.dll", "_fileno", {standard_out}) == 1);

    // ---- CreateFileA / ReadFile / GetFileSize / CloseHandle -------------
    const auto write_handle = call(&context, "kernel32.dll", "CreateFileA",
                                   {handle_path, 0x40000000 /*GENERIC_WRITE*/, 3, 0,
                                    2 /*CREATE_ALWAYS*/, 0, 0});
    check(tag + "/CreateFileA-write", write_handle != 0 && write_handle != ~0ull,
          "handle " + std::to_string(write_handle));
    std::uint64_t transferred_slot = kBuffer + 0x900;
    call(&context, "kernel32.dll", "WriteFile", {write_handle, kBuffer, 10, transferred_slot, 0});
    check(tag + "/WriteFile-count",
          load_guest_memory(&context, transferred_slot, 4) == 10,
          "reported " + std::to_string(load_guest_memory(&context, transferred_slot, 4)));
    check(tag + "/CloseHandle-write", call(&context, "kernel32.dll", "CloseHandle", {write_handle}) == 1);

    const auto read_handle = call(&context, "kernel32.dll", "CreateFileA",
                                  {handle_path, 0x80000000 /*GENERIC_READ*/, 1, 0,
                                   3 /*OPEN_EXISTING*/, 0, 0});
    check(tag + "/CreateFileA-read", read_handle != 0 && read_handle != ~0ull);
    check(tag + "/GetFileSize", call(&context, "kernel32.dll", "GetFileSize", {read_handle, 0}) == 10);
    check(tag + "/SetFilePointer", call(&context, "kernel32.dll", "SetFilePointer", {read_handle, 2, 0, 0}) == 2);
    check(tag + "/ReadFile-at-2",
          call(&context, "kernel32.dll", "ReadFile", {read_handle, kBuffer + 0x400, 3, transferred_slot, 0}) == 1);
    std::string from_handle;
    for (std::size_t index = 0; index < 3; ++index)
      from_handle.push_back(static_cast<char>(load_guest_memory(&context, kBuffer + 0x400 + index, 1)));
    check(tag + "/ReadFile-bytes", from_handle == "cde", "got '" + from_handle + "'");

    // A write-only handle refuses a read and says which error it is. Opened fresh
    // because the write handle above has already been closed, and a closed handle
    // fails for a different reason with a different code.
    const auto metadata_handle = call(&context, "kernel32.dll", "CreateFileA",
                                      {handle_path, 0x40000000 /*GENERIC_WRITE*/, 3, 0,
                                       3 /*OPEN_EXISTING*/, 0, 0});
    check(tag + "/read-on-write-handle-refused",
          call(&context, "kernel32.dll", "ReadFile", {metadata_handle, kBuffer + 0x400, 1, transferred_slot, 0}) == 0);
    check(tag + "/read-on-write-handle-error",
          call(&context, "kernel32.dll", "GetLastError", {}) == 5, "expected ERROR_ACCESS_DENIED");
    call(&context, "kernel32.dll", "CloseHandle", {metadata_handle});

    // ---- _open_osfhandle and _fdopen ------------------------------------
    // The bridge a Win32 program uses to read a handle it opened with CreateFileA.
    const auto bridged = call(&context, "msvcrt.dll", "_open_osfhandle", {read_handle, 0});
    check(tag + "/_open_osfhandle", bridged != static_cast<std::uint64_t>(-1));
    const auto fd_stream = call(&context, "msvcrt.dll", "_fdopen",
                                {bridged, kModeRead});
    check(tag + "/_fdopen", fd_stream != 0);
    if (fd_stream != 0) {
      call(&context, "msvcrt.dll", "fseek", {fd_stream, 0, 0});
      check(tag + "/fread-through-_fdopen",
            call(&context, "msvcrt.dll", "fread", {kBuffer + 0x400, 1, 10, fd_stream}) == 10);
    }

    // Closing the handle invalidates everything made from it.
    call(&context, "kernel32.dll", "CloseHandle", {read_handle});
    check(tag + "/read-after-close-fails",
          call(&context, "kernel32.dll", "ReadFile", {read_handle, kBuffer, 4, transferred_slot, 0}) == 0);
    check(tag + "/invalid-handle-error", call(&context, "kernel32.dll", "GetLastError", {}) == 6,
          "expected ERROR_INVALID_HANDLE");

    // ---- the app-directory policy, through the shims ---------------------
    check(tag + "/sandbox-escape-refused", call(&context, "msvcrt.dll", "fopen", {escape_path, write_mode}) == 0);
    const auto escape_error = call(&context, "kernel32.dll", "GetLastError", {});
    check(tag + "/sandbox-escape-error", escape_error == 5 || escape_error == 3,
          "last error " + std::to_string(escape_error));
    check(tag + "/escape-file-not-created",
          !std::filesystem::exists(directory.parent_path() / "recomp-escape-unit.dat"));

    // A drive-qualified path is the shape a program produces from its own module
    // name; refusing it would make every bundled data file unreachable. The
    // directories have to exist first, exactly as they would on Windows -- the
    // drive letter is dropped, the tree under it is not conjured.
    const auto drive_root = guest_string(&context, kScratch + 0x180, "C:\\Games");
    const auto drive_unit = guest_string(&context, kScratch + 0x1c0, "C:\\Games\\unit");
    call(&context, "kernel32.dll", "CreateDirectoryA", {drive_root, 0});
    call(&context, "kernel32.dll", "CreateDirectoryA", {drive_unit, 0});
    check(tag + "/CreateDirectoryA-made-host-dirs",
          std::filesystem::exists(directory / "Games/unit"), "CreateDirectoryA did not create the tree");
    const auto drive_stream = call(&context, "msvcrt.dll", "fopen", {drive_path, write_mode});
    check(tag + "/drive-qualified-opens", drive_stream != 0, "a drive letter must not refuse the path");
    if (drive_stream != 0) {
      call(&context, "msvcrt.dll", "fwrite", {kBuffer, 1, 10, drive_stream});
      call(&context, "msvcrt.dll", "fclose", {drive_stream});
      check(tag + "/drive-qualified-on-host",
            std::filesystem::exists(directory / "Games/unit/level.dat"));
    }

    // GetModuleFileNameA has to produce a path the policy resolves back to itself,
    // which is the whole reason a program calls it: to find the directory to read
    // its own files from. The named file exists here for that check to mean
    // something, and the answer is asserted to sit at the top of the app directory
    // rather than somewhere that merely looks plausible.
    std::ofstream(directory / "unit_guest.exe") << "stand-in for the image";
    const auto module_buffer = kBuffer + 0x1000;
    const auto module_length = call(&context, "kernel32.dll", "GetModuleFileNameA",
                                    {0, module_buffer, 0x200});
    check(tag + "/GetModuleFileNameA-length", module_length > 4,
          "reported " + std::to_string(module_length));
    std::string module_name;
    for (std::uint64_t index = 0; index < module_length; ++index)
      module_name.push_back(static_cast<char>(load_guest_memory(&context, module_buffer + index, 1)));
    check(tag + "/GetModuleFileNameA-ends-in-exe",
          module_name.size() > 4 && module_name.compare(module_name.size() - 4, 4, ".exe") == 0,
          "'" + module_name + "'");
    // Reopening the name it handed back has to reach the app directory. The drive
    // stands for the app directory, so "C:\name" and nothing else is the shape a
    // guest can feed back in and get the same file.
    guest_string(&context, kPathRoundTrip, module_name);
    check(tag + "/GetModuleFileNameA-round-trips",
          call(&context, "kernel32.dll", "GetFileAttributesA", {kPathRoundTrip}) != 0xffffffffull,
          "'" + module_name + "' does not resolve back to the app directory");
    // And stripping the last component has to land on the app directory itself,
    // which is what a program does to find its data files.
    const auto directory_only = module_name.substr(0, module_name.find_last_of('\\'));
    guest_string(&context, kScratch + 0x280, directory_only + "\\unit_write2.dat");
    const auto beside = call(&context, "msvcrt.dll", "fopen", {kScratch + 0x280, write_mode});
    check(tag + "/module-directory-append-opens", beside != 0,
          "'" + directory_only + "\\unit_write2.dat' was refused");
    if (beside != 0) call(&context, "msvcrt.dll", "fclose", {beside});
    check(tag + "/module-directory-stays-inside", std::filesystem::exists(directory / "unit_write2.dat"));

    // ---- DeleteFileA / GetFileAttributesA --------------------------------
    check(tag + "/attributes-present", call(&context, "kernel32.dll", "GetFileAttributesA", {path}) != 0xffffffffull);
    check(tag + "/DeleteFileA", call(&context, "kernel32.dll", "DeleteFileA", {path}) == 1);
    check(tag + "/attributes-after-delete",
          call(&context, "kernel32.dll", "GetFileAttributesA", {path}) == 0xffffffffull);
    check(tag + "/delete-absent-fails", call(&context, "kernel32.dll", "DeleteFileA", {path}) == 0);
    check(tag + "/delete-absent-error", call(&context, "kernel32.dll", "GetLastError", {}) == 2,
          "expected ERROR_FILE_NOT_FOUND");

    std::printf("%s: crt file layer checks complete\n", tag.c_str());
  }

  std::error_code cleanup;
  std::filesystem::remove_all(directory, cleanup);
  if (failures != 0) {
    std::printf("CRT file layer: %d failure(s)\n", failures);
    return 1;
  }
  std::printf("CRT file layer: all checks passed on PE32 and PE32+\n");
  return 0;
}
