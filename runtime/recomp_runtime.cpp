#include "recomp_runtime.hpp"
#include "guest_file_system.hpp"
#include "win32_abi.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cctype>
#include <clocale>
#include <cwchar>
#include <cwctype>
#include <climits>
#include <cstdlib>
#include <array>
#include <sstream>
#include <fstream>
#include <condition_variable>
#include <mutex>
#include <chrono>
#include <fcntl.h>
#include <sys/stat.h>
#include <system_error>
#include <map>
#include <filesystem>
#include <algorithm>

// The host environment, used to build the guest's environment blocks.
extern char** environ;
#include <ctime>
#include <string>
#include <vector>
// THE PLATFORM LAYER, and it is deliberately this small. The guest address space is one
// anonymous, unreserved mapping; on a POSIX host that is `mmap`, and on Windows it is
// `VirtualAlloc` with MEM_RESERVE. Nothing else in the runtime is host-specific, which is why
// a Windows target is a handful of lines rather than a porting project.
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <functional>

// Compile the unmodified MIT scanner in callback mode. Its standard-input
// wrappers are disabled; the guest adapter supplies the host stream explicitly.
#define SCANF_SSCANF_ONLY 1
#include "upstream_scanf.c"

namespace recomp {

// A FIXED CLOCK, because the alternative is a verification that depends on when it ran.
//
// The candidate is a subprocess and the reference runs in the harness process. Both called
// the HOST clock, so a program that seeds its RNG from the time -- `srand(time(NULL))`, which
// is the idiom -- received a DIFFERENT seed on each side whenever the two runs straddled a
// second boundary. The guest then chose a different word, took a different branch, and the
// two instruction streams diverged. That is the `hangman` divergence: measured at about 8%
// of runs, because most runs land inside one second and some do not.
//
// This is not a tolerance and it hides nothing: the clock is an INPUT to the guest, and a
// differential comparison is only meaningful if both sides receive the same input. The value
// is fixed rather than removed so that a program which asks the time gets a plausible answer,
// and it can be overridden for a program that must be driven with a specific date.
// PORTABLE 64x64 -> 128 ARITHMETIC, and it is here rather than using `__int128` for one
// measured reason: 32-bit mingw does not support `__int128`, so every use of it is a wall
// between this runtime and a Windows target.
//
// The implementations are EXACT, not approximations. The multiply splits each operand into
// 32-bit halves and sums the four partial products, which is the schoolbook method and cannot
// lose a bit. The divide is shift-and-subtract over 128 bits, which is exact for the same
// reason long division is. Neither rounds, saturates or truncates.
//
// They are verified the only way that matters: by differential comparison against Unicorn,
// which executes the real instruction. An error in either would show up as a divergence in
// `mul`, `imul`, `div` or `idiv`, and the fixtures exercise all four.

struct WideProduct {
  std::uint64_t high{};
  std::uint64_t low{};
};

inline WideProduct multiply_wide(std::uint64_t left, std::uint64_t right) {
  const std::uint64_t left_low = left & 0xffffffffull;
  const std::uint64_t left_high = left >> 32;
  const std::uint64_t right_low = right & 0xffffffffull;
  const std::uint64_t right_high = right >> 32;
  const std::uint64_t low_product = left_low * right_low;
  const std::uint64_t cross_one = left_high * right_low;
  const std::uint64_t cross_two = left_low * right_high;
  const std::uint64_t high_product = left_high * right_high;
  // The middle column carries into the high half; the two additions are done separately so
  // each carry is captured rather than lost.
  const std::uint64_t middle = (low_product >> 32) + (cross_one & 0xffffffffull) +
                               (cross_two & 0xffffffffull);
  return WideProduct{high_product + (cross_one >> 32) + (cross_two >> 32) + (middle >> 32),
                     (middle << 32) | (low_product & 0xffffffffull)};
}

// Exact 128 / 64. `overflow` reports the one case x86 calls #DE: a quotient that does not fit
// in 64 bits, which is `high >= divisor`. Returning that rather than truncating is what keeps
// the fault visible to the guest instead of silently producing a wrong answer.
struct WideQuotient {
  std::uint64_t quotient{};
  std::uint64_t remainder{};
  bool overflow{};
};

inline WideQuotient divide_wide(std::uint64_t high, std::uint64_t low, std::uint64_t divisor) {
  if (divisor == 0) return WideQuotient{0, 0, true};
  if (high >= divisor) return WideQuotient{0, 0, true};
  std::uint64_t quotient = 0;
  std::uint64_t remainder = high;
  for (int bit = 63; bit >= 0; --bit) {
    const std::uint64_t carry = remainder >> 63;
    remainder = (remainder << 1) | ((low >> bit) & 1ull);
    if (carry != 0 || remainder >= divisor) {
      remainder -= divisor;
      quotient |= 1ull << bit;
    }
  }
  return WideQuotient{quotient, remainder, false};
}

// Signed 128 / 64, expressed through the exact unsigned divide by working in magnitudes and
// re-applying the signs. The magnitudes are computed in UNSIGNED arithmetic, so the most
// negative value -- whose negation overflows a signed type -- is handled correctly rather than
// being undefined behaviour.
inline WideQuotient divide_wide_signed(std::uint64_t high, std::uint64_t low, std::uint64_t divisor) {
  const bool dividend_negative = (high >> 63) != 0;
  const bool divisor_negative = (divisor >> 63) != 0;
  std::uint64_t magnitude_high = high;
  std::uint64_t magnitude_low = low;
  if (dividend_negative) {
    magnitude_low = ~magnitude_low + 1ull;
    magnitude_high = ~magnitude_high + (magnitude_low == 0 ? 1ull : 0ull);
  }
  std::uint64_t magnitude_divisor = divisor;
  if (divisor_negative) magnitude_divisor = ~magnitude_divisor + 1ull;
  const auto wide = divide_wide(magnitude_high, magnitude_low, magnitude_divisor);
  if (wide.overflow) return wide;
  WideQuotient result = wide;
  if (dividend_negative != divisor_negative) result.quotient = ~result.quotient + 1ull;
  if (dividend_negative) result.remainder = ~result.remainder + 1ull;
  return result;
}

std::time_t guest_fixed_time() {
  static const std::time_t fixed = [] {
    if (const char* setting = std::getenv("RECOMP_FIXED_TIME")) {
      try { return static_cast<std::time_t>(std::stoll(setting)); } catch (const std::exception&) {}
    }
    return static_cast<std::time_t>(1700000000);  // 2023-11-14T22:13:20Z, an arbitrary fixed instant
  }();
  return fixed;
}


std::uint8_t* guest_memory = nullptr;
std::uint64_t guest_memory_size = 0;
std::uint64_t recompiled_image_base = 0;
bool guest_tracing_enabled = false;
int guest_pointer_width = 8;
const std::string* guest_input_capture = nullptr;
std::size_t guest_input_position = 0;

namespace {
std::FILE* guest_trace_stream = nullptr;
}

void guest_trace_address(std::uint64_t address) {
  if (guest_trace_stream != nullptr) std::fwrite(&address, sizeof(address), 1, guest_trace_stream);
}

namespace {

[[noreturn]] void terminate_with_message(const char* format, ...) {
  std::fflush(stdout);
  std::fputs("recomp: ", stderr);
  va_list arguments;
  va_start(arguments, format);
  std::vfprintf(stderr, format, arguments);
  va_end(arguments);
  std::fputs("\n", stderr);
  std::fflush(stderr);
  std::exit(3);
}

constexpr int kRegisterReturnValue = 0;
constexpr int kRegisterArgument0 = 1;
constexpr int kRegisterArgument1 = 2;
constexpr int kRegisterStackPointer = 4;
constexpr int kRegisterArgument2 = 8;
constexpr int kRegisterArgument3 = 9;

constexpr std::uint64_t kGuestMemoryBytes = 0x200000000ull;
// Runtime-owned blocks must be addressable by the guest, including PE32 images
// whose pointers cannot represent the upper half of the mapped address space.
std::uint64_t guest_reserved_top() {
  return guest_pointer_width >= 8 ? guest_memory_size
                                  : std::min<std::uint64_t>(guest_memory_size, 0x100000000ull);
}
constexpr std::uint64_t kThreadEnvironmentBlockAddress64 = 0x0000000164000000ull;
constexpr std::uint64_t kProcessEnvironmentBlockAddress64 = 0x0000000164001000ull;
constexpr std::uint64_t kThreadEnvironmentBlockAddress32 = 0x000000007ffd0000ull;
constexpr std::uint64_t kProcessEnvironmentBlockAddress32 = 0x000000007ffd1000ull;
// Import thunk addresses must fit in the guest pointer width: a 32-bit IAT
// slot can only hold a value below 4 GiB.
constexpr std::uint64_t kImportThunkBase64 = 0x0000000100000000ull;
constexpr std::uint64_t kImportThunkBase32 = 0x0000000060000000ull;

std::uint64_t import_thunk_base() {
  return guest_pointer_width >= 8 ? kImportThunkBase64 : kImportThunkBase32;
}

constexpr int kFunctionHashBits = 18;
constexpr std::uint32_t kFunctionHashSize = 1u << kFunctionHashBits;

std::vector<GuestFunctionDescriptor> function_table;
std::uint32_t* function_hash = nullptr;
std::vector<std::uint64_t> import_thunk_addresses;
std::vector<void (*)(GuestContext*)> import_thunk_functions;
std::vector<std::string> import_thunk_libraries;
std::vector<std::string> import_thunk_symbols;

// The dispatcher knows which import it is about to call, so a failure can name
// it. "call to an unbound import thunk" without a symbol is not actionable: the
// point of the diagnostic is to say which shim to add next.
std::size_t current_thunk_index = 0;

std::uint32_t hash_function_address(std::uint64_t address) {
  return static_cast<std::uint32_t>((address * 0x9e3779b97f4a7c15ull) >> (64 - kFunctionHashBits));
}

void (*lookup_guest_function(std::uint64_t address))(GuestContext*) {
  if (function_hash == nullptr) return nullptr;
  const auto start = hash_function_address(address);
  for (std::uint32_t probe = 0; probe < kFunctionHashSize; ++probe) {
    const auto slot = (start + probe) & (kFunctionHashSize - 1);
    const auto entry = function_hash[slot];
    if (entry == 0) return nullptr;
    if (function_table[entry - 1].address == address) return function_table[entry - 1].function;
  }
  return nullptr;
}

long lookup_import_thunk(std::uint64_t address) {
  for (std::size_t index = 0; index < import_thunk_addresses.size(); ++index)
    if (import_thunk_addresses[index] == address) return static_cast<long>(index);
  return -1;
}

// Runs an import thunk reached through a register or memory operand. On 32-bit
// x86 the callee's `ret`/`ret n` must still remove the return address and the
// stdcall arguments, exactly as for a direct import call.
void invoke_import_thunk(GuestContext* context, long index, std::uint64_t return_address, bool push_return) {
  if (push_return)
    push_guest_stack(context, return_address);
  current_thunk_index = static_cast<std::size_t>(index);
  // The thunk table calls the shim directly, so the shim marker has to be set
  // here as well as around invoke_win32_import.
  guest_in_shim = true;
  import_thunk_functions[static_cast<std::size_t>(index)](context);
  guest_in_shim = false;
  if (guest_pointer_width < 8) {
    context->registers[4] = mask_guest_address(
        context->registers[4] +
        win32_import_stack_cleanup(import_thunk_libraries[static_cast<std::size_t>(index)].c_str(),
                                   import_thunk_symbols[static_cast<std::size_t>(index)].c_str()));
  } else if (push_return) {
    // On x86-64 the arguments are in registers, so the return address is the only
    // thing a `call` moves and the only thing the shim's `ret` removes. Popping it
    // leaves the stack pointer exactly where it was, but the push above has now
    // written the return address to memory the way hardware does -- which is what
    // the differential reference sees, and what a program that reads its own
    // stack expects. Skipping the write made the two sides disagree about a slot
    // that later falls above the stack pointer and becomes live.
    (void)pop_guest_stack(context);
  }
}

std::string read_guest_string(std::uint64_t address) {
  std::string value;
  while (value.size() < 4096 && address < guest_memory_size && guest_memory[address] != 0) {
    value.push_back(static_cast<char>(guest_memory[address]));
    ++address;
  }
  return value;
}

// Reads a UTF-16 guest string as bytes. Only the low half of each unit is kept,
// which is exact for ASCII and lossy above it; the callers are the wide forms of
// LoadLibrary, _wfopen and CreateFileW, where the name is a path or a DLL and a
// non-ASCII character is a name this host cannot open under either spelling.
// Every path the runtime then touches goes through the app directory.
std::string read_guest_wide_string(std::uint64_t address) {
  std::string text;
  for (std::uint64_t index = 0; index < 512; ++index) {
    if (address + index * 2 + 1 >= guest_memory_size) break;
    const auto unit = load_guest_memory(nullptr, address + index * 2, 2);
    if (unit == 0) break;
    text.push_back(static_cast<char>(unit & 0xffu));
  }
  return text;
}

// ---- Win32 last-error -----------------------------------------------------
// The guest's only channel for asking why a call failed, so a shim that reports a
// failure without recording one here has told the program nothing. A constant 0
// (the previous behaviour) means a program that checks GetLastError on the error
// path -- which is most programs, on the error path -- concludes the call worked
// and carries on with a handle that is NULL.
std::uint32_t guest_last_error = 0;

// Only the codes a shim actually produces are named. The values are the ones in
// winerror.h, because the guest compares against them.
enum Win32ErrorCode : std::uint32_t {
  kErrorInvalidFunction = 1,
  kErrorFileNotFound = 2,
  kErrorPathNotFound = 3,
  kErrorAccessDenied = 5,
  kErrorInvalidHandle = 6,
  kErrorNotEnoughMemory = 8,
  kErrorSharingViolation = 32,
  kErrorNotSupported = 50,
  kErrorInvalidParameter = 87,
  kErrorCallNotImplemented = 120,
  kErrorProcNotFound = 127,
  kErrorModNotFound = 126,
  kErrorDirectoryNotSupported = 267,
};

void set_guest_last_error(std::uint32_t code) { guest_last_error = code; }
void clear_guest_last_error() { guest_last_error = 0; }

// ---- Win32 handle table ---------------------------------------------------
// Handles are opaque to the guest, but every shim that accepts one has to agree
// with the shim that produced it about what it refers to. The three standard
// handles keep the values the reference also returns for GetStdHandle (10, 11,
// 12), so the table does not change anything a differential comparison can
// observe; it simply knows what those values mean.
//
// A handle carries its type. The type is what makes a wrong handle a diagnosable
// mistake rather than a corrupt one: passing a find handle to ReadFile, or a
// closed file to WriteFile, is reported as an invalid handle, and a host pointer
// never appears here at all.
enum GuestHandleType {
  kGuestHandleFree = 0,
  kGuestHandleStandard = 1,
  kGuestHandleFile = 2,
  kGuestHandleFind = 3,
  kGuestHandleHeap = 4,
  kGuestHandleMutex = 5,
  kGuestHandleEvent = 6,
  kGuestHandleSemaphore = 7,
};

struct GuestHandle {
  int type{kGuestHandleFree};
  int host_descriptor{-1};
  // The access the handle was opened with, so a read through a write-only handle
  // fails the way Windows fails it instead of succeeding wrongly.
  bool may_read{false};
  bool may_write{false};
  // The guest path it was opened through, for diagnostics that name the file.
  std::string path;
  bool signaled{false};
  bool manual_reset{false};
  std::uint32_t semaphore_count{0};
  std::uint32_t semaphore_maximum{0};
};

constexpr std::uint32_t kGuestHandleBase = 0x1000;
constexpr std::uint32_t kGuestHandleCount = 1024;
GuestHandle guest_handles[kGuestHandleCount];
std::mutex guest_sync_mutex;
std::condition_variable guest_sync_changed;
GuestHandle standard_handles[3] = {{kGuestHandleStandard, STDIN_FILENO, true, false, "<stdin>"},
                                   {kGuestHandleStandard, STDOUT_FILENO, false, true, "<stdout>"},
                                   {kGuestHandleStandard, STDERR_FILENO, false, true, "<stderr>"}};

GuestHandle* guest_handle_lookup(std::uint64_t handle) {
  if (handle == 10) return &standard_handles[0];
  if (handle == 11) return &standard_handles[1];
  if (handle == 12) return &standard_handles[2];
  if (handle < kGuestHandleBase) return nullptr;
  const auto index = static_cast<std::uint32_t>((handle - kGuestHandleBase) / 4u);
  if (index >= kGuestHandleCount) return nullptr;
  if (guest_handles[index].type == kGuestHandleFree) return nullptr;
  return &guest_handles[index];
}

std::uint64_t guest_handle_new(int type, int descriptor = -1) {
  for (std::uint32_t index = 1; index < kGuestHandleCount; ++index) {
    if (guest_handles[index].type == kGuestHandleFree) {
      guest_handles[index] = GuestHandle{};
      guest_handles[index].type = type;
      guest_handles[index].host_descriptor = descriptor;
      return kGuestHandleBase + index * 4u;
    }
  }
  return 0;  // exhausted; the shim reports the failure
}

// Opens a host file and hands back the guest handle for it, recording which way
// the handle is allowed to be used.
std::uint64_t guest_file_handle_new(int descriptor, bool may_read, bool may_write, const std::string& path) {
  const auto handle = guest_handle_new(kGuestHandleFile, descriptor);
  if (handle == 0) return 0;
  const auto index = static_cast<std::uint32_t>((handle - kGuestHandleBase) / 4u);
  guest_handles[index].may_read = may_read;
  guest_handles[index].may_write = may_write;
  guest_handles[index].path = path;
  return handle;
}

void guest_handle_close(std::uint64_t handle) {
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || entry->type == kGuestHandleStandard) return;
  if (entry->host_descriptor >= 0) ::close(entry->host_descriptor);
  *entry = GuestHandle{};
}

// The descriptor behind a handle, checked for the access the caller wants. An
// invalid handle or a read through a write-only handle both report the Windows
// error and give back -1, so the shim's failure path is one path.
int guest_handle_descriptor(std::uint64_t handle, bool for_write, GuestContext* context) {
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || entry->host_descriptor < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    // An invalid handle is a normal Windows error, not a missing capability, so
    // the guest is not stopped. But it is nearly always a bug in the guest -- a
    // double close, or a handle used after CloseHandle -- and the alternative to
    // naming it here is a program that silently does nothing to the wrong object.
    if (context != nullptr) {
      std::fprintf(stderr, "recomp: invalid handle 0x%" PRIx64 " passed to %s (ip=0x%" PRIx64 ")\n",
                   handle, for_write ? "a write" : "a read", context->instruction_pointer);
    }
    return -1;
  }
  if (for_write && !entry->may_write) {
    set_guest_last_error(kErrorAccessDenied);
    return -1;
  }
  if (!for_write && !entry->may_read) {
    set_guest_last_error(kErrorAccessDenied);
    return -1;
  }
  return entry->host_descriptor;
}

int standard_handle_to_descriptor(std::uint64_t handle) {
  const auto* entry = guest_handle_lookup(handle);
  if (entry != nullptr && entry->host_descriptor >= 0) return entry->host_descriptor;
  return STDOUT_FILENO;
}

// The general registers, for diagnostics that would otherwise report only an
// address the guest computed.
std::string describe_registers(const GuestContext* context) {
  static const char* names[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
                                "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
  std::string text;
  char buffer[64];
  for (int index = 0; index < 16; ++index) {
    const auto value = guest_pointer_width >= 8 ? context->registers[index]
                                                : (context->registers[index] & 0xffffffffull);
    std::snprintf(buffer, sizeof(buffer), "%s%s=0x%llx", text.empty() ? "" : " ", names[index],
                  static_cast<unsigned long long>(value));
    text += buffer;
  }
  return text;
}

std::uint64_t next_heap_address = 0;

// ---- guest heap ---------------------------------------------------------
// A boundary-tag allocator inside the guest address space. HeapFree used to be
// a no-op and HeapAlloc only ever bumped a pointer, so a guest that allocates
// and frees in a loop — which is what loading a level does — exhausted the heap
// and started getting null back. Each block carries an 8-byte header
// immediately before the pointer the guest sees:
//
//   +0  std::uint32_t payload size in bytes (16-byte aligned, header excluded)
//   +4  std::uint32_t 1 when the block is free
//
// Blocks are contiguous from heap_first_block up to heap_region_end, and free
// neighbours are coalesced so the region can be reused rather than consumed.
constexpr std::uint64_t kHeapHeaderSize = 8;
constexpr std::uint64_t kHeapAlignment = 16;

std::uint64_t heap_first_block = 0;
std::uint64_t heap_region_end = 0;

void heap_write_header(std::uint64_t block, std::uint32_t size, std::uint32_t is_free) {
  store_guest_memory(nullptr, block, size, 4);
  store_guest_memory(nullptr, block + 4, is_free, 4);
}
std::uint32_t heap_read_size(std::uint64_t block) {
  return static_cast<std::uint32_t>(load_guest_memory(nullptr, block, 4));
}
std::uint32_t heap_read_free(std::uint64_t block) {
  return static_cast<std::uint32_t>(load_guest_memory(nullptr, block + 4, 4));
}
std::uint64_t heap_next_block(std::uint64_t block) { return block + kHeapHeaderSize + heap_read_size(block); }

// Lays out one free block spanning the whole heap region. Called once, after
// guest memory exists and before any translated code runs.
void heap_initialize(std::uint64_t base, std::uint64_t limit) {
  heap_first_block = 0;
  heap_region_end = 0;
  if (limit > guest_memory_size) limit = guest_memory_size;
  const auto start = (base + kHeapAlignment - 1) & ~(kHeapAlignment - 1);
  if (limit < start + kHeapHeaderSize + kHeapAlignment) return;
  heap_first_block = start;
  heap_region_end = limit;
  heap_write_header(start, static_cast<std::uint32_t>(limit - start - kHeapHeaderSize), 1);
}

// ---- Win32 shims -------------------------------------------------------
void win32_get_std_handle(GuestContext* context) {
  const auto which = static_cast<std::int32_t>(import_argument(context, 0));
  set_import_result(context, which == -10 ? 10 : which == -12 ? 12 : 11);
}
void win32_write_file(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  const auto buffer = import_argument(context, 1);
  const auto length = import_argument(context, 2);
  const auto written_pointer = import_argument(context, 3);
  if (buffer + length > guest_memory_size) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  // Resolved through the handle table rather than defaulting to stdout. A file
  // handle used to fall through to STDOUT_FILENO, so a program that opened a
  // file and wrote to it wrote to the terminal and was told it had succeeded.
  const auto* entry = guest_handle_lookup(handle);
  const auto descriptor = guest_handle_descriptor(handle, true, context);
  if (descriptor < 0) { set_import_result(context, 0); return; }
  // The count reported back is what the host accepted, not what was requested.
  // Reporting the requested length made a short write -- a full disk, a closed
  // descriptor -- look like success, and a program that trusts the count would
  // believe data had been written that had not.
  std::uint64_t written = 0;
  while (written < length) {
    // The standard handles go through the output writer, which is what the
    // differential reference captures; a real file is written straight to its own
    // descriptor, because a file's bytes are not program output.
    const auto accepted = entry != nullptr && entry->type == kGuestHandleStandard
        ? write_guest_output(descriptor, reinterpret_cast<const char*>(guest_memory + buffer + written),
                             static_cast<std::size_t>(length - written))
        : ::write(descriptor, guest_memory + buffer + written, static_cast<std::size_t>(length - written));
    if (accepted <= 0) break;
    written += static_cast<std::uint64_t>(accepted);
  }
  if (written_pointer != 0) store_guest_memory(context, written_pointer, written, 4);
  if (written == 0 && length != 0) {
    set_guest_last_error(kErrorInvalidHandle);
    // WriteFile succeeds when it wrote something; a partial write is still a
    // success with a short count, which is what the API specifies.
    set_import_result(context, 0);
    return;
  }
  clear_guest_last_error();
  set_import_result(context, 1);
}
void win32_read_file(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  const auto buffer = import_argument(context, 1);
  const auto length = import_argument(context, 2);
  const auto read_pointer = import_argument(context, 3);
  if (buffer + length > guest_memory_size) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  const auto descriptor = guest_handle_descriptor(handle, false, context);
  if (descriptor < 0) { set_import_result(context, 0); return; }
  auto count = ::read(descriptor, guest_memory + buffer, static_cast<std::size_t>(length));
  if (count < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    if (read_pointer != 0) store_guest_memory(context, read_pointer, 0, 4);
    set_import_result(context, 0);
    return;
  }
  if (read_pointer != 0) store_guest_memory(context, read_pointer, static_cast<std::uint64_t>(count), 4);
  // A read of zero bytes at end of file is a successful read of nothing; the
  // guest distinguishes EOF from failure by the count, exactly as on Windows.
  clear_guest_last_error();
  set_import_result(context, 1);
}
void win32_exit_process(GuestContext* context) {
  guest_request_exit(static_cast<int>(static_cast<std::uint32_t>(import_argument(context, 0))));
}
void win32_terminate_process(GuestContext* context) {
  (void)context;
  std::fflush(stdout);
  std::exit(1);
}
void win32_zero(GuestContext* context) { set_import_result(context, 0); }
void win32_ignore(GuestContext* context) { (void)context; }
void win32_one(GuestContext* context) { set_import_result(context, 1); }
void win32_registry_not_found(GuestContext* context) {
  // No host registry is exposed to a recompiled app. Returning the documented
  // ERROR_FILE_NOT_FOUND result lets callers take their normal default path.
  set_import_result(context, 2);
}
void win32_path_find_filename_w(GuestContext* context) {
  // Preserve a valid guest pointer; callers that only need to test for a path
  // component still take their normal fallback path in headless mode.
  set_import_result(context, import_argument(context, 0));
}
void win32_gdiplus_startup(GuestContext* context) {
  const auto token = import_argument(context, 0);
  if (token != 0) store_guest_memory(context, token, 1, guest_pointer_width);
  set_import_result(context, 0);
}
void win32_gdiplus_write_handle(GuestContext* context) {
  const auto result = import_argument(context, 1);
  if (result != 0) store_guest_memory(context, result, 1, guest_pointer_width);
  set_import_result(context, 0);
}
void win32_gdiplus_write_result(GuestContext* context) {
  const auto result = import_argument(context, 1);
  if (result != 0) store_guest_memory(context, result, 1, guest_pointer_width);
  set_import_result(context, 0);
}
void win32_gdiplus_write_result0(GuestContext* context) {
  const auto result = import_argument(context, 0);
  if (result != 0) store_guest_memory(context, result, 1, guest_pointer_width);
  set_import_result(context, 0);
}
// GetLastError is the guest's only way to ask why something failed, so it reports
// what the failing shim recorded rather than a constant that says "nothing went
// wrong". SetLastError is a real store, because programs set it to 0 before a call
// whose failure they want to distinguish from a previous one.
void win32_get_last_error(GuestContext* context) { set_import_result(context, guest_last_error); }
void win32_set_last_error(GuestContext* context) {
  set_guest_last_error(static_cast<std::uint32_t>(import_argument(context, 0)));
}
void win32_current_process_id(GuestContext* context) { set_import_result(context, 4321); }
void win32_current_thread_id(GuestContext* context) { set_import_result(context, 4321); }
void win32_current_process(GuestContext* context) { set_import_result(context, static_cast<std::uint64_t>(-1)); }
void win32_current_thread(GuestContext* context) { set_import_result(context, static_cast<std::uint64_t>(-2)); }
void win32_is_processor_feature_present(GuestContext* context) { set_import_result(context, 0); }
void win32_get_version(GuestContext* context) { set_import_result(context, 0x0a000000); }
void win32_code_page(GuestContext* context) { set_import_result(context, 65001); }
// The process ANSI code page above is UTF-8, which has no DBCS lead bytes.
void win32_is_dbcs_lead_byte(GuestContext* context) {
  (void)import_argument(context, 0);
  set_import_result(context, 0);
}

void win32_virtual_alloc(GuestContext* context) {
  const auto requested = import_argument(context, 0);
  const auto size = import_argument(context, 1);
  if (requested != 0) { set_import_result(context, requested); return; }
  const auto aligned = (size + 0xfff) & ~0xfffull;
  if (next_heap_address + aligned > guest_memory_size) { set_import_result(context, 0); return; }
  set_import_result(context, next_heap_address);
  next_heap_address += aligned;
}
// VirtualProtect. The guest address space is one flat region that is always
// readable, writable and executable, so every protection change already holds.
// The old protection is reported as PAGE_EXECUTE_READWRITE for the same reason.
void win32_virtual_protect(GuestContext* context) {
  const auto old_protection = import_argument(context, 3);
  if (old_protection != 0) store_guest_memory(context, old_protection, 0x40, 4);
  set_import_result(context, 1);
}

// VirtualQuery fills a MEMORY_BASIC_INFORMATION. This runtime presents one flat
// committed region, so every page reports the same state; the fields a program
// actually inspects (BaseAddress, RegionSize, State, Protect) are the ones
// filled in, and the structure is 28 bytes on 32-bit and 48 on 64-bit.
void win32_virtual_query(GuestContext* context) {
  const auto address = import_argument(context, 0);
  const auto information = import_argument(context, 1);
  const auto length = import_argument(context, 2);
  const std::uint64_t required = guest_pointer_width >= 8 ? 48 : 28;
  if (information == 0 || information + required > guest_memory_size) { set_import_result(context, 0); return; }
  for (std::uint64_t offset = 0; offset < required; ++offset)
    store_guest_memory(context, information + offset, 0, 1);
  const auto base = address & ~static_cast<std::uint64_t>(0xfff);
  const auto width = static_cast<std::uint64_t>(guest_pointer_width);
  store_guest_memory(context, information + 0, base, static_cast<int>(width));       // BaseAddress
  store_guest_memory(context, information + width, base, static_cast<int>(width));   // AllocationBase
  store_guest_memory(context, information + width * 2, 0x40, 4);                     // PAGE_EXECUTE_READWRITE
  store_guest_memory(context, information + width * 2 + 4, 0x1000, static_cast<int>(width));  // RegionSize
  store_guest_memory(context, information + width * 3 + 4, 0x1000, 4);               // MEM_COMMIT
  store_guest_memory(context, information + width * 3 + 8, 0x20000, 4);              // MEM_PRIVATE
  set_import_result(context, required < length ? required : length);
}

void win32_virtual_free(GuestContext* context) { set_import_result(context, 1); }
// ---- kernel32: environment, version and handle-count ----------------------
// Ported from HenryKun55/igi-recomp (MIT), shim/src/kernel32.c, with the
// stdcall pop removed: this runtime pops the guest stack centrally through
// runtime/win32_abi.hpp, so a shim must only set the result. Each of these also
// needs an entry in the ABI table there, or `imports` will still report it
// missing.
void win32_get_version_ex_a(GuestContext* context) {
  // OSVERSIONINFOA. The values are igi-recomp's, kept identical so the two
  // sides of a differential comparison observe the same thing.
  const auto info = import_argument(context, 0);
  store_guest_memory(context, info + 4, 5, 4);      // dwMajorVersion
  store_guest_memory(context, info + 8, 1, 4);      // dwMinorVersion
  store_guest_memory(context, info + 12, 2600, 4);  // dwBuildNumber
  store_guest_memory(context, info + 16, 2, 4);     // VER_PLATFORM_WIN32_NT
  store_guest_memory(context, info + 20, 0, 1);     // szCSDVersion[0] = NUL
  set_import_result(context, 1);
}
void win32_set_handle_count(GuestContext* context) {
  set_import_result(context, import_argument(context, 0));
}
void win32_release_mutex(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  std::lock_guard lock(guest_sync_mutex);
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || entry->type != kGuestHandleMutex || entry->signaled) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  entry->signaled = true;
  set_import_result(context, 1);
  guest_sync_changed.notify_all();
}
void win32_free_environment_strings_w(GuestContext* context) {
  (void)import_argument(context, 0);
  set_import_result(context, 1);
}
void win32_get_environment_variable_a(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  (void)import_argument(context, 2);
  set_import_result(context, 0);  // ERROR_ENVVAR_NOT_FOUND
}
void win32_get_cp_info(GuestContext* context) {
  const auto info = import_argument(context, 1);
  for (std::uint64_t offset = 0; offset < 20; ++offset)
    store_guest_memory(context, info + offset, 0, 1);
  store_guest_memory(context, info, 1, 4);          // MaxCharSize
  store_guest_memory(context, info + 4, '?', 1);    // DefaultChar[0]
  set_import_result(context, 1);
}

void win32_get_file_type(GuestContext* context) {
  const auto* entry = guest_handle_lookup(import_argument(context, 0));
  std::uint64_t type = 0;  // FILE_TYPE_UNKNOWN
  if (entry != nullptr && entry->type == kGuestHandleStandard) type = 2;  // FILE_TYPE_CHAR
  else if (entry != nullptr && entry->type == kGuestHandleFile) type = 1;  // FILE_TYPE_DISK
  set_import_result(context, type);
}
void win32_close_handle(GuestContext* context) {
  guest_handle_close(import_argument(context, 0));
  set_import_result(context, 1);
}
// The same-process pseudo-thread case follows the narrow DuplicateHandle
// handling in cricket07-browser/host/kernel32.c (MIT, commit
// 4febc615b6e07d3e70b22c05a65bf37959c6989a). Its guest handles are different,
// so this runtime preserves its own pseudo handle instead of using Cricket's
// private 0x1FFFFFFC alias. Real file descriptors are duplicated with dup(2).
void win32_duplicate_handle(GuestContext* context) {
  constexpr std::uint64_t kCurrentProcess = static_cast<std::uint64_t>(-1);
  constexpr std::uint64_t kCurrentThread = static_cast<std::uint64_t>(-2);
  constexpr std::uint32_t kDuplicateCloseSource = 1;
  constexpr std::uint32_t kDuplicateSameAccess = 2;
  const auto source_process = import_argument(context, 0);
  const auto source_handle = import_argument(context, 1);
  const auto target_process = import_argument(context, 2);
  const auto output_pointer = import_argument(context, 3);
  const auto options = static_cast<std::uint32_t>(import_argument(context, 6));
  if (source_process != kCurrentProcess || target_process != kCurrentProcess || output_pointer == 0 ||
      (options & ~(kDuplicateCloseSource | kDuplicateSameAccess)) != 0) {
    set_guest_last_error(kErrorNotSupported);
    set_import_result(context, 0);
    return;
  }

  // GetCurrentThread returns a pseudo handle that is process-local and must not
  // be closed. Duplicating it in this single-threaded guest runtime retains the
  // same pseudo-handle value; CloseHandle already treats pseudo handles as
  // non-owned values.
  if (source_handle == kCurrentThread && (options & kDuplicateCloseSource) == 0) {
    store_guest_memory(context, output_pointer, kCurrentThread, guest_pointer_width);
    set_import_result(context, 1);
    return;
  }

  auto* source = guest_handle_lookup(source_handle);
  if (source == nullptr || (source->type != kGuestHandleFile && source->type != kGuestHandleStandard) ||
      source->host_descriptor < 0) {
    set_guest_last_error(source == nullptr ? kErrorInvalidHandle : kErrorNotSupported);
    set_import_result(context, 0);
    return;
  }
  const int duplicate_descriptor = ::dup(source->host_descriptor);
  if (duplicate_descriptor < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  const auto duplicate = guest_file_handle_new(duplicate_descriptor, source->may_read, source->may_write, source->path);
  if (duplicate == 0) {
    ::close(duplicate_descriptor);
    set_guest_last_error(kErrorNotSupported);
    set_import_result(context, 0);
    return;
  }
  store_guest_memory(context, output_pointer, duplicate, guest_pointer_width);
  if ((options & kDuplicateCloseSource) != 0) guest_handle_close(source_handle);
  clear_guest_last_error();
  set_import_result(context, 1);
}
// These two Win32 fallbacks match cricket07-browser/host/kernel32.c (MIT,
// commit 4febc615b6e07d3e70b22c05a65bf37959c6989a): thread priority is not
// scheduled by the single-threaded compatibility runtime.
void win32_set_thread_priority(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, 1);
}
void win32_get_thread_priority(GuestContext* context) {
  (void)import_argument(context, 0);
  set_import_result(context, 0);
}
void win32_set_std_handle(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, 1);
}
void win32_create_mutex_a(GuestContext* context) {
  (void)import_argument(context, 0);  // attributes
  const bool initial_owner = import_argument(context, 1) != 0;
  (void)import_argument(context, 2);  // name
  const auto handle = guest_handle_new(kGuestHandleMutex);
  auto* entry = guest_handle_lookup(handle);
  if (entry != nullptr) entry->signaled = !initial_owner;
  set_import_result(context, handle);
}

// These handles model the Win32 event/semaphore state used by CRT startup and
// synchronization. The API contract follows Wine's kernelbase sync wrappers;
// this runtime stores the guest-visible object state locally instead of requiring
// Wine's NT object manager.
void win32_create_event_a(GuestContext* context) {
  (void)import_argument(context, 0);  // security attributes
  const bool manual_reset = import_argument(context, 1) != 0;
  const bool initial_state = import_argument(context, 2) != 0;
  const auto name = import_argument(context, 3);
  if (name != 0) {
    set_guest_last_error(kErrorNotSupported);
    set_import_result(context, 0);
    return;
  }
  const auto handle = guest_handle_new(kGuestHandleEvent);
  auto* entry = guest_handle_lookup(handle);
  if (entry != nullptr) {
    entry->manual_reset = manual_reset;
    entry->signaled = initial_state;
  }
  set_import_result(context, handle);
}

void win32_set_event(GuestContext* context) {
  std::lock_guard lock(guest_sync_mutex);
  auto* entry = guest_handle_lookup(import_argument(context, 0));
  if (entry == nullptr || entry->type != kGuestHandleEvent) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  entry->signaled = true;
  set_import_result(context, 1);
  guest_sync_changed.notify_all();
}

void win32_reset_event(GuestContext* context) {
  std::lock_guard lock(guest_sync_mutex);
  auto* entry = guest_handle_lookup(import_argument(context, 0));
  if (entry == nullptr || entry->type != kGuestHandleEvent) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  entry->signaled = false;
  set_import_result(context, 1);
}

void win32_create_semaphore_a(GuestContext* context) {
  (void)import_argument(context, 0);  // security attributes
  const auto initial = static_cast<std::int32_t>(import_argument(context, 1));
  const auto maximum = static_cast<std::int32_t>(import_argument(context, 2));
  const auto name = import_argument(context, 3);
  if (initial < 0 || maximum <= 0 || initial > maximum || name != 0) {
    set_guest_last_error(name != 0 ? kErrorNotSupported : kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  const auto handle = guest_handle_new(kGuestHandleSemaphore);
  auto* entry = guest_handle_lookup(handle);
  if (entry != nullptr) {
    entry->semaphore_count = static_cast<std::uint32_t>(initial);
    entry->semaphore_maximum = static_cast<std::uint32_t>(maximum);
  }
  set_import_result(context, handle);
}

void win32_release_semaphore(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  const auto release_count = import_argument(context, 1);
  const auto previous_count = import_argument(context, 2);
  std::lock_guard lock(guest_sync_mutex);
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || entry->type != kGuestHandleSemaphore || release_count == 0 ||
      release_count > entry->semaphore_maximum - entry->semaphore_count) {
    set_guest_last_error(entry == nullptr || entry->type != kGuestHandleSemaphore
                             ? kErrorInvalidHandle : kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  if (previous_count != 0) store_guest_memory(context, previous_count, entry->semaphore_count, 4);
  entry->semaphore_count += static_cast<std::uint32_t>(release_count);
  set_import_result(context, 1);
  guest_sync_changed.notify_all();
}

constexpr std::uint32_t kWaitObject0 = 0;
constexpr std::uint32_t kWaitTimeout = 0x102;
constexpr std::uint32_t kWaitFailed = 0xffffffffu;
constexpr std::uint32_t kInfiniteTimeout = 0xffffffffu;
constexpr std::uint32_t kMaximumWaitObjects = 64;

bool guest_sync_ready(const GuestHandle* entry) {
  if (entry == nullptr) return false;
  if (entry->type == kGuestHandleEvent || entry->type == kGuestHandleMutex) return entry->signaled;
  return entry->type == kGuestHandleSemaphore && entry->semaphore_count != 0;
}

void guest_sync_consume(GuestHandle* entry) {
  if (entry->type == kGuestHandleEvent && !entry->manual_reset) entry->signaled = false;
  else if (entry->type == kGuestHandleSemaphore) --entry->semaphore_count;
  else if (entry->type == kGuestHandleMutex) entry->signaled = false;
}

void win32_wait_for_single_object(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  const auto timeout = static_cast<std::uint32_t>(import_argument(context, 1));
  std::unique_lock lock(guest_sync_mutex);
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || (entry->type != kGuestHandleEvent && entry->type != kGuestHandleSemaphore &&
                           entry->type != kGuestHandleMutex)) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, kWaitFailed);
    return;
  }
  const auto ready = [&] { return guest_sync_ready(entry); };
  const bool signaled = timeout == kInfiniteTimeout
                            ? (guest_sync_changed.wait(lock, ready), true)
                            : guest_sync_changed.wait_for(lock, std::chrono::milliseconds(timeout), ready);
  if (!signaled) {
    set_import_result(context, kWaitTimeout);
    return;
  }
  guest_sync_consume(entry);
  set_import_result(context, kWaitObject0);
}

void win32_wait_for_multiple_objects(GuestContext* context) {
  const auto count = import_argument(context, 0);
  const auto handles_address = import_argument(context, 1);
  const bool wait_all = import_argument(context, 2) != 0;
  const auto timeout = static_cast<std::uint32_t>(import_argument(context, 3));
  if (count == 0 || count > kMaximumWaitObjects || handles_address == 0) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, kWaitFailed);
    return;
  }
  std::vector<GuestHandle*> entries;
  entries.reserve(static_cast<std::size_t>(count));
  for (std::uint64_t index = 0; index < count; ++index) {
    const auto handle = load_guest_memory(context, handles_address + index * guest_pointer_width,
                                          guest_pointer_width);
    auto* entry = guest_handle_lookup(handle);
    if (entry == nullptr || (entry->type != kGuestHandleEvent && entry->type != kGuestHandleSemaphore &&
                             entry->type != kGuestHandleMutex)) {
      set_guest_last_error(kErrorInvalidHandle);
      set_import_result(context, kWaitFailed);
      return;
    }
    entries.push_back(entry);
  }
  std::unique_lock lock(guest_sync_mutex);
  const auto ready = [&] {
    if (wait_all) return std::all_of(entries.begin(), entries.end(), guest_sync_ready);
    return std::any_of(entries.begin(), entries.end(), guest_sync_ready);
  };
  const bool signaled = timeout == kInfiniteTimeout
                            ? (guest_sync_changed.wait(lock, ready), true)
                            : guest_sync_changed.wait_for(lock, std::chrono::milliseconds(timeout), ready);
  if (!signaled) {
    set_import_result(context, kWaitTimeout);
    return;
  }
  if (wait_all) {
    for (auto* entry : entries) guest_sync_consume(entry);
    set_import_result(context, kWaitObject0);
  } else {
    const auto ready_entry = std::find_if(entries.begin(), entries.end(), guest_sync_ready);
    const auto index = static_cast<std::uint32_t>(std::distance(entries.begin(), ready_entry));
    guest_sync_consume(*ready_entry);
    set_import_result(context, kWaitObject0 + index);
  }
}

void win32_get_process_heap(GuestContext* context) { set_import_result(context, 0x1000); }
void win32_heap_create(GuestContext* context) { set_import_result(context, 0x1000); }
std::uint32_t heap_block_size(std::uint64_t pointer);
// Returns the guest pointer for a new block, or 0 when the region is exhausted.
std::uint64_t heap_allocate(std::uint64_t requested) {
  const auto payload = (requested == 0 ? kHeapAlignment : (requested + kHeapAlignment - 1) & ~(kHeapAlignment - 1));
  if (heap_first_block == 0 || payload > 0xfffffff0ull) return 0;
  for (std::uint64_t block = heap_first_block; block != 0; block = heap_next_block(block)) {
    const auto size = heap_read_size(block);
    if (heap_read_free(block) == 0 || size < payload) {
      const auto next = heap_next_block(block);
      if (next + kHeapHeaderSize > heap_region_end) break;
      continue;
    }
    // Split when the remainder can hold a header plus one aligned payload;
    // otherwise hand over the whole block.
    const auto remainder = size - static_cast<std::uint32_t>(payload);
    if (remainder >= kHeapHeaderSize + kHeapAlignment) {
      heap_write_header(block + kHeapHeaderSize + static_cast<std::uint32_t>(payload),
                        static_cast<std::uint32_t>(remainder - kHeapHeaderSize), 1);
      heap_write_header(block, static_cast<std::uint32_t>(payload), 0);
    } else {
      heap_write_header(block, size, 0);
    }
    return block + kHeapHeaderSize;
  }
  // The region is exhausted. Returning null is what the real API does, and the
  // guest is entitled to see it rather than being handed a wild pointer.
  return 0;
}

void win32_heap_alloc(GuestContext* context) {
  const auto flags = import_argument(context, 1);
  const auto size = import_argument(context, 2);
  const auto block = heap_allocate(size);
  // HEAP_ZERO_MEMORY is part of the Win32 HeapAlloc contract.  CRT startup
  // allocates callback tables with this flag and relies on unused slots being
  // null; returning stale guest bytes turns them into wild function pointers.
  if (block != 0 && (flags & 0x00000008ull) != 0 && size != 0)
    std::memset(guest_memory + block, 0, static_cast<std::size_t>(size));
  set_import_result(context, block);
}

// Releases a block and coalesces its free neighbours.
void heap_release(GuestContext* context, std::uint64_t pointer) {
  (void)context;  // the heap is host-side; the context is for symmetry with the shims
  if (heap_first_block == 0 || pointer < heap_first_block + kHeapHeaderSize || pointer >= heap_region_end)
    return;
  const auto block = pointer - kHeapHeaderSize;
  heap_write_header(block, heap_read_size(block), 1);
  // Coalesce with the following free blocks, then with the preceding one if it
  // is free, so repeated alloc/free cycles reuse the region instead of walking
  // it forward until it runs out.
  for (;;) {
    const auto next = heap_next_block(block);
    if (next + kHeapHeaderSize > heap_region_end || heap_read_free(next) == 0) break;
    heap_write_header(block, heap_read_size(block) + static_cast<std::uint32_t>(kHeapHeaderSize) + heap_read_size(next), 1);
  }
  std::uint64_t previous = heap_first_block;
  while (previous != block) {
    const auto next = heap_next_block(previous);
    if (next == block) {
      if (heap_read_free(previous) != 0) {
        heap_write_header(previous, heap_read_size(previous) + static_cast<std::uint32_t>(kHeapHeaderSize) + heap_read_size(block), 1);
      }
      break;
    }
    if (next + kHeapHeaderSize > heap_region_end) break;
    previous = next;
  }
}

void win32_heap_free(GuestContext* context) {
  heap_release(context, import_argument(context, 2));
  set_import_result(context, 1);
}

// Adapted from project-igi-browser/host/kernel32.c HeapSize (MIT).  The
// runtime's allocator owns the block headers, so querying that allocator is
// more faithful than returning a requested size cached by an individual API.
void win32_heap_size(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  const auto size = heap_block_size(import_argument(context, 2));
  set_import_result(context, size == 0 ? 0xffffffffu : size);
}

void win32_get_tick_count(GuestContext* context) {
  // Derived from the FIXED clock, like every other guest-visible time. A tick count read
  // from the host advances between the two sides, and a program that branches on elapsed
  // time -- which is what a tick count is for -- then takes different branches. This was the
  // second of the three host-clock reads; the first was `time`, and fixing only that one
  // would have left the same defect reachable through a different import.
  timespec now{};
  now.tv_sec = guest_fixed_time();
  now.tv_nsec = 0;
  const auto milliseconds = static_cast<std::uint64_t>(now.tv_sec) * 1000ull +
                            static_cast<std::uint64_t>(now.tv_nsec) / 1000000ull;
  set_import_result(context, static_cast<std::uint32_t>(milliseconds));
}
void win32_query_performance_counter(GuestContext* context) {
  // The third host-clock read, fixed for the same reason.
  timespec now{};
  now.tv_sec = guest_fixed_time();
  now.tv_nsec = 0;
  const auto nanoseconds = static_cast<std::uint64_t>(now.tv_sec) * 1000000000ull +
                           static_cast<std::uint64_t>(now.tv_nsec);
  const auto out = import_argument(context, 0);
  if (out != 0) store_guest_memory(context, out, nanoseconds, 8);
  set_import_result(context, 1);
}
void win32_query_performance_frequency(GuestContext* context) {
  const auto out = import_argument(context, 0);
  if (out != 0) store_guest_memory(context, out, 1000000000ull, 8);
  set_import_result(context, 1);
}
void win32_get_system_time_as_file_time(GuestContext* context) {
  const auto out = import_argument(context, 0);
  if (out != 0) { store_guest_memory(context, out, 0, 4); store_guest_memory(context, out + 4, 0, 4); }
}
// Adapted from igi-recomp shim/src/kernel32.c GetLocalTime (MIT, HenryKun55).
void win32_get_local_time(GuestContext* context) {
  const std::time_t now = guest_fixed_time();
  std::tm tm{};
  localtime_r(&now, &tm);
  const auto p = import_argument(context, 0);
  store_guest_memory(context, p + 0u, static_cast<std::uint32_t>(tm.tm_year) + 1900u, 2);
  store_guest_memory(context, p + 2u, static_cast<std::uint32_t>(tm.tm_mon) + 1u, 2);
  store_guest_memory(context, p + 4u, static_cast<std::uint32_t>(tm.tm_wday), 2);
  store_guest_memory(context, p + 6u, static_cast<std::uint32_t>(tm.tm_mday), 2);
  store_guest_memory(context, p + 8u, static_cast<std::uint32_t>(tm.tm_hour), 2);
  store_guest_memory(context, p + 10u, static_cast<std::uint32_t>(tm.tm_min), 2);
  store_guest_memory(context, p + 12u, static_cast<std::uint32_t>(tm.tm_sec), 2);
  store_guest_memory(context, p + 14u, 0, 2);
  set_import_result(context, 0);
}
void win32_get_startup_info(GuestContext* context) {
  const auto out = import_argument(context, 0);
  if (out == 0 || guest_memory == nullptr || out >= guest_memory_size) return;
  // STARTUPINFOA/W has the same layout; only pointer width changes its size.
  // The CRT reads cb before consulting any optional fields, so initialize the
  // complete structure and publish a truthful size for the guest ABI.
  const std::uint64_t size = guest_pointer_width >= 8 ? 104u : 68u;
  if (size > guest_memory_size - out) return;
  std::memset(guest_memory + out, 0, static_cast<std::size_t>(size));
  store_guest_memory(context, out, size, 4);
}
void win32_get_startup_info_w(GuestContext* context) {
  win32_get_startup_info(context);
}
void win32_get_command_line(GuestContext* context) {
  set_import_result(context, guest_reserved_top() - 0x500000);
}
void win32_get_command_line_w(GuestContext* context) {
  set_import_result(context, guest_reserved_top() - 0x600000);
}
// Environment blocks. Windows hands the guest a double-NUL-terminated block of
// "NAME=value" strings; the ANSI and wide shims must describe the same content.
// Both live in a reserved region at the top of guest memory.
std::uint64_t environment_block_a = 0;
std::uint64_t environment_block_w = 0;

void build_environment_blocks() {
  environment_block_a = 0;
  environment_block_w = 0;
  if (guest_memory == nullptr || guest_memory_size < 0x300000) return;
  environment_block_a = guest_reserved_top() - 0x200000;
  environment_block_w = guest_reserved_top() - 0x100000;
  std::memset(guest_memory + environment_block_a, 0, 0x100000);
  std::memset(guest_memory + environment_block_w, 0, 0x100000);
  std::uint64_t ansi = 0;
  std::uint64_t wide = 0;
  // THE GUEST'S ENVIRONMENT IS A FIXED SET, not the host's.
  //
  // This is the third instance of the same defect class as the clock and the pid. The
  // candidate is a SUBPROCESS and the reference runs in the harness process, so `environ`
  // differs between them by construction: the child inherits whatever the harness exported
  // plus its own additions. A guest that calls `getenv` therefore received a different answer
  // on each side, and `getenv("PATH")` alone is enough to make a program branch differently.
  //
  // The harness already EXCLUDED the environment page from the heap comparison, which hid
  // the symptom without fixing it -- the guest could still read the difference, it just was
  // not compared. A fixed set is the fix: the environment is an INPUT, and both sides must
  // receive the same one. `RECOMP_ENVIRONMENT` can name a file of `NAME=value` lines for a
  // program that genuinely needs a specific environment.
  std::vector<std::string> variables;
  if (const char* path = std::getenv("RECOMP_ENVIRONMENT")) {
    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line)) {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (!line.empty()) variables.push_back(line);
    }
  }
  if (variables.empty()) {
    // A plausible, minimal Windows environment. Values are fixed strings, so both sides see
    // exactly these bytes.
    variables = {"PATH=C:\\Windows\\System32;C:\\Windows", "SystemRoot=C:\\Windows",
                 "TEMP=C:\\Windows\\Temp", "TMP=C:\\Windows\\Temp",
                 "OS=Windows_NT", "COMPUTERNAME=RECOMP", "USERNAME=recomp",
                 "PROCESSOR_ARCHITECTURE=x86"};
  }
  for (const auto& variable : variables) {
    if (ansi + variable.size() + 1 < 0x0fffff) {
      std::memcpy(guest_memory + environment_block_a + ansi, variable.data(), variable.size());
      ansi += variable.size() + 1;  // the terminator is already zero
    }
    if (wide + (variable.size() + 1) * 2 < 0x0fffff) {
      for (std::size_t index = 0; index < variable.size(); ++index)
        store_guest_memory(nullptr, environment_block_w + wide + index * 2,
                           static_cast<std::uint8_t>(variable[index]), 2);
      wide += (variable.size() + 1) * 2;
    }
  }
}

void win32_get_environment_strings_w(GuestContext* context) {
  set_import_result(context, environment_block_w);
}

// The size of the block a guest pointer was handed out from, or 0 if it is not
// one of ours.
std::uint32_t heap_block_size(std::uint64_t pointer) {
  if (heap_first_block == 0 || pointer < heap_first_block + kHeapHeaderSize || pointer >= heap_region_end)
    return 0;
  return heap_read_size(pointer - kHeapHeaderSize);
}

std::uint64_t heap_allocate(std::uint64_t requested);
void heap_release(GuestContext* context, std::uint64_t pointer);

void win32_heap_realloc(GuestContext* context) {
  const auto flags = import_argument(context, 1);
  const auto pointer = import_argument(context, 2);
  const auto size = import_argument(context, 3);
  const auto old_size = heap_block_size(pointer);
  if ((flags & 0x10u) != 0) {  // HEAP_REALLOC_IN_PLACE_ONLY
    set_import_result(context, size <= old_size ? pointer : 0);
    return;
  }
  const auto replacement = heap_allocate(size);
  if (replacement == 0) { set_import_result(context, 0); return; }
  const auto copy = old_size < size ? old_size : size;
  if (pointer != 0 && copy != 0) {
    for (std::uint64_t offset = 0; offset < copy; ++offset)
      store_guest_memory(context, replacement + offset, load_guest_memory(context, pointer + offset, 1), 1);
    heap_release(context, pointer);
  }
  set_import_result(context, replacement);
}

// ---- kernel32: string classification and locale mapping -------------------
// Ported from HenryKun55/igi-recomp (MIT) shim/src/kernel32.c. The C1_* bits are
// the ones GetStringTypeA/W report, and the mapping flags are LCMAP_LOWERCASE
// (0x100) and LCMAP_UPPERCASE (0x200).
std::uint32_t classify_character(std::uint32_t character) {
  if (character >= 256u) return 0x100u;  // C1_ALPHA
  const auto value = static_cast<int>(character);
  std::uint32_t type = 0;
  if (std::isupper(value) != 0) type |= 0x001u;  // C1_UPPER
  if (std::islower(value) != 0) type |= 0x002u;  // C1_LOWER
  if (std::isdigit(value) != 0) type |= 0x004u;  // C1_DIGIT
  if (std::isspace(value) != 0) type |= 0x008u;  // C1_SPACE
  if (std::ispunct(value) != 0) type |= 0x010u;  // C1_PUNCT
  if (std::iscntrl(value) != 0) type |= 0x020u;  // C1_CNTRL
  if (character == ' ' || character == '\t') type |= 0x040u;  // C1_BLANK
  if (std::isxdigit(value) != 0) type |= 0x080u;  // C1_XDIGIT
  if (std::isalpha(value) != 0) type |= 0x100u;  // C1_ALPHA
  return type;
}

std::uint32_t map_character(std::uint32_t flags, std::uint32_t character) {
  if (character >= 256u) return character;
  if ((flags & 0x100u) != 0) return static_cast<std::uint32_t>(std::tolower(static_cast<int>(character)));
  if ((flags & 0x200u) != 0) return static_cast<std::uint32_t>(std::toupper(static_cast<int>(character)));
  return character;
}

void win32_get_string_type_a(GuestContext* context) {
  const auto source = import_argument(context, 2);
  const auto output = import_argument(context, 4);
  auto count = static_cast<std::int32_t>(import_argument(context, 3));
  if (count < 0) count = static_cast<std::int32_t>(read_guest_string(source).size()) + 1;
  for (std::int32_t index = 0; index < count; ++index)
    store_guest_memory(context, output + static_cast<std::uint64_t>(index) * 2,
                       classify_character(load_guest_memory(context, source + static_cast<std::uint64_t>(index), 1)), 2);
  set_import_result(context, 1);
}

void win32_get_string_type_w(GuestContext* context) {
  const auto source = import_argument(context, 1);
  const auto output = import_argument(context, 3);
  auto count = static_cast<std::int32_t>(import_argument(context, 2));
  if (count < 0) {
    count = 0;
    while (load_guest_memory(context, source + static_cast<std::uint64_t>(count) * 2, 2) != 0) ++count;
    ++count;
  }
  for (std::int32_t index = 0; index < count; ++index)
    store_guest_memory(context, output + static_cast<std::uint64_t>(index) * 2,
                       classify_character(static_cast<std::uint32_t>(
                           load_guest_memory(context, source + static_cast<std::uint64_t>(index) * 2, 2))), 2);
  set_import_result(context, 1);
}

void win32_lc_map_string_a(GuestContext* context) {
  const auto flags = import_argument(context, 1);
  const auto source = import_argument(context, 2);
  const auto destination = import_argument(context, 4);
  const auto destination_size = import_argument(context, 5);
  auto count = static_cast<std::int32_t>(import_argument(context, 3));
  if (count < 0) count = static_cast<std::int32_t>(read_guest_string(source).size()) + 1;
  if (destination_size != 0) {
    if (static_cast<std::uint64_t>(count) > destination_size)
      count = static_cast<std::int32_t>(destination_size);
    for (std::int32_t index = 0; index < count; ++index)
      store_guest_memory(context, destination + static_cast<std::uint64_t>(index),
                         map_character(flags, load_guest_memory(context, source + static_cast<std::uint64_t>(index), 1)), 1);
  }
  set_import_result(context, static_cast<std::uint64_t>(count));
}

void win32_lc_map_string_w(GuestContext* context) {
  const auto flags = import_argument(context, 1);
  const auto source = import_argument(context, 2);
  const auto destination = import_argument(context, 4);
  const auto destination_size = import_argument(context, 5);
  auto count = static_cast<std::int32_t>(import_argument(context, 3));
  if (count < 0) {
    count = 0;
    while (load_guest_memory(context, source + static_cast<std::uint64_t>(count) * 2, 2) != 0) ++count;
    ++count;
  }
  if (destination_size != 0) {
    if (static_cast<std::uint64_t>(count) > destination_size)
      count = static_cast<std::int32_t>(destination_size);
    for (std::int32_t index = 0; index < count; ++index)
      store_guest_memory(context, destination + static_cast<std::uint64_t>(index) * 2,
                         map_character(flags, static_cast<std::uint32_t>(
                             load_guest_memory(context, source + static_cast<std::uint64_t>(index) * 2, 2))), 2);
  }
  set_import_result(context, static_cast<std::uint64_t>(count));
}

// ---- libstdc++: the C++ standard library ----------------------------------
// A GCC-built Windows program links libstdc++, and its objects are manipulated
// by the program's own inlined code as well as by these entry points, so their
// layouts are part of the ABI and cannot be chosen freely. The sizes below were
// read from the i686-w64-mingw32 headers and confirmed by compiling a probe with
// that toolchain:
//
//   std::string    24 bytes: char* _M_dataplus (0), size_t length (4),
//                            union { char local[16]; size_t capacity } (8)
//   std::ifstream 260, std::ofstream 256, std::istream 144, std::ostream 140
//
// Only std::string needs its layout modelled, because the program reads and
// writes its fields directly. The stream objects are opaque here: their state is
// held host-side and keyed by the object's guest address, so the internal layout
// of a stream never has to be reproduced.
// Defined with the kernel32 directory shims; a Windows path has no meaning on the
// host, so it is translated in one place and used by every file-facing shim.
std::string guest_path_to_host(std::string path);
// Resolves through the app-directory policy and reports why a path was refused.
bool guest_path_resolve(const std::string& guest_path, std::string& host_path, bool for_creation);
// Defined with the module table below; the file shims need it to tell a handle for
// the image itself apart from one for a DLL the guest named.
const char* guest_module_library(std::uint64_t handle);

constexpr std::uint64_t kCxxStringBytes = 24;
constexpr std::uint64_t kCxxStringLocalCapacity = 15;
constexpr std::uint64_t kCxxOstreamBytes = 140;
constexpr std::uint64_t kCxxIstreamBytes = 144;

std::uint64_t cxx_cout = 0;
std::uint64_t cxx_cin = 0;

// The stream state this runtime keeps for an object it was handed.
struct GuestStreamState {
  int descriptor{-1};
  bool is_output{};
};
std::map<std::uint64_t, GuestStreamState> guest_streams;

std::string cxx_string_value(GuestContext* context, std::uint64_t object) {
  const auto length = load_guest_memory(context, object + 4, 4);
  const auto data = load_guest_memory(context, object, 4);
  std::string text;
  text.reserve(static_cast<std::size_t>(length));
  for (std::uint64_t index = 0; index < length; ++index)
    text.push_back(static_cast<char>(load_guest_memory(context, data + index, 1)));
  return text;
}

void cxx_string_assign(GuestContext* context, std::uint64_t object, const std::string& text) {
  // A string at or below the local capacity lives inside the object; above it,
  // the object owns a heap block whose capacity is stored over the local buffer.
  if (text.size() <= kCxxStringLocalCapacity) {
    store_guest_memory(context, object, object + 8, 4);  // _M_dataplus -> local buffer
    for (std::size_t index = 0; index < text.size(); ++index)
      store_guest_memory(context, object + 8 + index, static_cast<std::uint8_t>(text[index]), 1);
    store_guest_memory(context, object + 8 + text.size(), 0, 1);
    store_guest_memory(context, object + 4, text.size(), 4);
    return;
  }
  const auto block = heap_allocate(text.size() + 1);
  if (block == 0) { set_import_result(context, 0); return; }
  for (std::size_t index = 0; index < text.size(); ++index)
    store_guest_memory(context, block + index, static_cast<std::uint8_t>(text[index]), 1);
  store_guest_memory(context, block + text.size(), 0, 1);
  store_guest_memory(context, object, block, 4);
  store_guest_memory(context, object + 4, text.size(), 4);
  store_guest_memory(context, object + 8, text.size(), 4);  // _M_allocated_capacity
}

void cxx_string_release(GuestContext* context, std::uint64_t object) {
  const auto data = load_guest_memory(context, object, 4);
  if (data != 0 && data != object + 8) heap_release(context, data);
  store_guest_memory(context, object, object + 8, 4);
  store_guest_memory(context, object + 4, 0, 4);
  store_guest_memory(context, object + 8, 0, 1);
}

void cxx_string_default_construct(GuestContext* context) {
  const auto object = import_argument(context, 0);
  store_guest_memory(context, object, object + 8, 4);
  store_guest_memory(context, object + 4, 0, 4);
  store_guest_memory(context, object + 8, 0, 1);
  set_import_result(context, object);
}
void cxx_string_construct_from_c(GuestContext* context) {
  const auto object = import_argument(context, 0);
  cxx_string_assign(context, object, read_guest_string(import_argument(context, 1)));
  set_import_result(context, object);
}
void cxx_string_copy_construct(GuestContext* context) {
  const auto object = import_argument(context, 0);
  cxx_string_assign(context, object, cxx_string_value(context, import_argument(context, 1)));
  set_import_result(context, object);
}
void cxx_string_destruct(GuestContext* context) {
  cxx_string_release(context, import_argument(context, 0));
  set_import_result(context, 0);
}
void cxx_string_assign_from(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  if (object != source) {
    const auto text = cxx_string_value(context, source);
    cxx_string_release(context, object);
    cxx_string_assign(context, object, text);
  }
  set_import_result(context, object);
}

// operator new / delete are the guest heap, so a pointer from one is usable by
// the other and by malloc/free.
void cxx_operator_new(GuestContext* context) {
  set_import_result(context, heap_allocate(import_argument(context, 0)));
}
void cxx_operator_new_array(GuestContext* context) {
  set_import_result(context, heap_allocate(import_argument(context, 0)));
}
void cxx_operator_delete(GuestContext* context) {
  const auto pointer = import_argument(context, 0);
  if (pointer != 0) heap_release(context, pointer);
  set_import_result(context, 0);
}
void cxx_throw_bad_alloc(GuestContext* context) {
  terminate_with_message("std::bad_alloc thrown by the guest (ip=0x%" PRIx64 ")", context->instruction_pointer);
}

void cxx_noop(GuestContext* context) {
  const auto object = import_argument(context, 0);
  set_import_result(context, object);
}

// Streams. `std::cout` and `std::cin` are real objects in guest memory; a file
// stream is created by its constructor, which records the descriptor host-side
// against the object address.
std::uint64_t cxx_stream_descriptor(GuestContext* context, std::uint64_t object, bool for_output) {
  (void)context;  // the stream table is host-side
  const auto found = guest_streams.find(object);
  if (found != guest_streams.end()) return static_cast<std::uint64_t>(found->second.descriptor);
  return for_output ? STDOUT_FILENO : STDIN_FILENO;
}

void cxx_ostream_write(GuestContext* context, std::uint64_t object, const std::string& text, bool flush) {
  const auto descriptor = static_cast<int>(cxx_stream_descriptor(context, object, true));
  write_guest_output(descriptor, text.data(), text.size());
  (void)flush;
}

void cxx_ostream_put_c_string(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto text = read_guest_string(import_argument(context, 1));
  cxx_ostream_write(context, object, text, false);
  set_import_result(context, object);
}
void cxx_ostream_put_string(GuestContext* context) {
  const auto object = import_argument(context, 0);
  cxx_ostream_write(context, object, cxx_string_value(context, import_argument(context, 1)), false);
  set_import_result(context, object);
}
void cxx_ostream_put_int(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto value = static_cast<std::int32_t>(import_argument(context, 1) & 0xffffffffu);
  cxx_ostream_write(context, object, std::to_string(value), false);
  set_import_result(context, object);
}

// Extraction reads a whole line from the stream and parses it, which is what a
// console program's `cin >> x` expects from a terminal.
std::string cxx_read_token(GuestContext* context, std::uint64_t object) {
  const auto descriptor = static_cast<int>(cxx_stream_descriptor(context, object, false));
  std::string text;
  char character = 0;
  while (::read(descriptor, &character, 1) == 1) {
    if (character == '\n') break;
    text.push_back(character);
  }
  const auto first = text.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return {};
  const auto last = text.find_last_not_of(" \t\r\n");
  return text.substr(first, last - first + 1);
}
void cxx_istream_get_int(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto target = import_argument(context, 1);
  const auto token = cxx_read_token(context, object);
  try {
    store_guest_memory(context, target, static_cast<std::uint64_t>(std::stol(token)), 4);
  } catch (...) {
    store_guest_memory(context, target, 0, 4);
  }
  set_import_result(context, object);
}
void cxx_istream_get_string(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto target = import_argument(context, 1);
  cxx_string_assign(context, target, cxx_read_token(context, object));
  set_import_result(context, object);
}
void cxx_istream_get_char(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto target = import_argument(context, 1);
  const auto token = cxx_read_token(context, object);
  store_guest_memory(context, target, token.empty() ? 0 : static_cast<std::uint8_t>(token[0]), 1);
  set_import_result(context, object);
}

// File streams. The object is opaque; the descriptor is held host-side against
// the object's guest address, and because basic_istream is the first base of
// basic_ifstream the address an operator>> sees is the same one the constructor
// recorded.
constexpr std::uint64_t kCxxIfstreamBytes = 260;
constexpr std::uint64_t kCxxOfstreamBytes = 256;

// libstdc++ openmode bits: app 1, ate 2, binary 4, in 8, out 16, trunc 32.
void cxx_file_stream_construct(GuestContext* context, bool for_output) {
  const auto object = import_argument(context, 0);
  const auto requested = read_guest_string(import_argument(context, 1));
  std::string path;
  const auto resolved = guest_path_resolve(requested, path, true);
  const auto mode = import_argument(context, 2);
  const auto bytes = for_output ? kCxxOfstreamBytes : kCxxIfstreamBytes;
  if (object + bytes <= guest_memory_size) std::memset(guest_memory + object, 0, bytes);
  auto flags = for_output ? (O_WRONLY | O_CREAT) : O_RDONLY;
  if ((mode & 1u) != 0 || (mode & 2u) != 0) flags |= O_APPEND; else if (for_output) flags |= O_TRUNC;
  const auto descriptor = resolved ? guest_file_sandbox().open_resolved(path, flags, 0644) : -1;
  if (descriptor < 0) {
    guest_streams.erase(object);  // is_open() reports false, as it should
  } else {
    guest_streams[object] = GuestStreamState{descriptor, for_output};
  }
  set_import_result(context, object);
}
void cxx_ifstream_construct(GuestContext* context) { cxx_file_stream_construct(context, false); }
void cxx_ofstream_construct(GuestContext* context) { cxx_file_stream_construct(context, true); }

void cxx_file_stream_close(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto found = guest_streams.find(object);
  if (found != guest_streams.end()) {
    if (found->second.descriptor >= 0) ::close(found->second.descriptor);
    guest_streams.erase(found);
  }
  set_import_result(context, 0);
}
void cxx_file_stream_is_open(GuestContext* context) {
  set_import_result(context, guest_streams.count(import_argument(context, 0)) != 0 ? 1 : 0);
}

// C++ exceptions. Unwinding through recompiled frames needs a personality routine
// that understands this runtime's stack discipline, which does not exist yet, so
// a propagating exception fails loudly rather than being silently swallowed.
void cxx_exception_trap(GuestContext* context) {
  terminate_with_message("a C++ exception propagated (ip=0x%" PRIx64
                         "); exception unwinding is not implemented",
                         context->instruction_pointer);
}

void cxx_initialize() {
  cxx_cout = 0;
  cxx_cin = 0;
  if (guest_memory == nullptr || guest_memory_size < 0x500000) return;
  cxx_cout = guest_reserved_top() - 0x400000;
  cxx_cin = guest_reserved_top() - 0x400000 + 0x100;
  std::memset(guest_memory + cxx_cout, 0, 0x200);
  guest_streams[cxx_cout] = GuestStreamState{STDOUT_FILENO, true};
  guest_streams[cxx_cin] = GuestStreamState{STDIN_FILENO, false};
}
void cxx_cout_address(GuestContext* context) { set_import_result(context, cxx_cout); }
void cxx_cin_address(GuestContext* context) { set_import_result(context, cxx_cin); }

// ---- msvcrt: the C runtime ------------------------------------------------
// Every MSVC- or mingw-built Windows binary imports its C runtime, so this is not
// application-specific: these are the standard C library functions implemented
// against the guest's own heap and address space. They are cdecl, so their ABI
// rows carry callee_cleans_stack = false and the caller pops, as on Windows.
std::uint64_t msvcrt_data_block = 0;   // CRT globals: errno, _iob, ctype tables
std::uint64_t msvcrt_environment_pointer = 0;
std::uint64_t msvcrt_file_mode_pointer = 0;
std::uint64_t msvcrt_iob = 0;
std::uint64_t msvcrt_strerror_buffer = 0;

constexpr std::uint64_t kMsvcrtFileObjectBytes = 48;
constexpr std::uint64_t kMsvcrtFileCount = 3;  // stdin, stdout, stderr

// Defined below with the stream table it populates. The three standard streams
// have to be registered before any guest code runs, because stdin is a FILE* the
// program reads without opening anything.
void crt_files_seed();

void msvcrt_initialize() {
  msvcrt_data_block = 0;
  if (guest_memory == nullptr || guest_memory_size < 0x400000) return;
  msvcrt_data_block = guest_reserved_top() - 0x300000;
  std::memset(guest_memory + msvcrt_data_block, 0, 0x1000);
  msvcrt_environment_pointer = msvcrt_data_block + 0x100;
  msvcrt_file_mode_pointer = msvcrt_data_block + 0x110;
  msvcrt_iob = msvcrt_data_block + 0x200;
  // strerror returns a pointer to CRT-owned storage. Keep that storage in the
  // guest address space so a guest can dereference the result directly.
  msvcrt_strerror_buffer = msvcrt_data_block + 0x500;
  // __p__environ and __p__fmode return the address of a variable, not the value.
  const std::uint32_t environment = static_cast<std::uint32_t>(environment_block_a);
  std::memcpy(guest_memory + msvcrt_environment_pointer, &environment, 4);
  const std::uint32_t mode = 0;  // _O_TEXT
  std::memcpy(guest_memory + msvcrt_file_mode_pointer, &mode, 4);
  const std::uint32_t mb_cur_max = 1;
  std::memcpy(guest_memory + msvcrt_data_block + 0x320, &mb_cur_max, 4);
  store_guest_memory(nullptr, msvcrt_data_block + 0x430, guest_reserved_top() - 0x500000, guest_pointer_width);
  crt_files_seed();
}

std::uint64_t msvcrt_stream_index(std::uint64_t stream) {
  if (msvcrt_iob == 0 || stream < msvcrt_iob) return 0;
  const auto index = (stream - msvcrt_iob) / kMsvcrtFileObjectBytes;
  return index < kMsvcrtFileCount ? index : 0;
}

// ---- CRT file descriptors and streams -------------------------------------
// Three levels, because Windows has three: a guest HANDLE names an opened object,
// a CRT file descriptor names one end of it, and a FILE* names a view of a
// descriptor. Collapsing them is what makes _fileno, _open_osfhandle and _fdopen
// unanswerable -- and mixing CreateFileA with fread is the ordinary way a Win32
// program opens a file, so a stream that cannot be tied back to the handle it
// came from reads the wrong thing and reports success.
struct GuestCrtFile {
  int host_fd{-1};
  std::uint64_t handle{0};  // the guest handle it was made from, when it was
  bool open{false};
};
std::vector<GuestCrtFile> crt_files;

struct GuestCrtStream {
  int fd{-1};
  bool for_read{false};
  bool for_write{false};
  // EOF and error are per-stream, not per-descriptor: two FILE* on one descriptor
  // have separate flags, and a program that calls feof after a short read has to
  // see the flag the read set. Reporting eof from the descriptor would answer a
  // different question than the one asked.
  bool at_eof{false};
  bool had_error{false};
  // ungetc() puts back one byte; a second pushback before a read is undefined,
  // so one slot is the whole requirement.
  std::int32_t pushback{-1};
};
std::map<std::uint64_t, GuestCrtStream> crt_streams;

std::uint64_t crt_file_new(int host_fd, std::uint64_t handle) {
  for (std::size_t index = 0; index < crt_files.size(); ++index) {
    if (!crt_files[index].open) {
      crt_files[index] = GuestCrtFile{host_fd, handle, true};
      return index;
    }
  }
  crt_files.push_back(GuestCrtFile{host_fd, handle, true});
  return crt_files.size() - 1;
}

GuestCrtFile* crt_file_get(std::uint64_t descriptor) {
  if (descriptor >= crt_files.size() || !crt_files[descriptor].open) return nullptr;
  return &crt_files[descriptor];
}

// The host descriptor behind a FILE*, or -1. A stream the runtime never created
// -- a pointer the guest made up -- has to be distinguishable from a closed one,
// because the guest's own error handling depends on the answer being no.
int crt_stream_descriptor(std::uint64_t stream) {
  const auto found = crt_streams.find(stream);
  if (found == crt_streams.end()) return -1;
  auto* file = crt_file_get(static_cast<std::uint64_t>(found->second.fd));
  return file != nullptr ? file->host_fd : -1;
}

GuestCrtStream* crt_stream(std::uint64_t stream) {
  const auto found = crt_streams.find(stream);
  return found == crt_streams.end() ? nullptr : &found->second;
}

// Registers a stream for a descriptor. `object` is the FILE* the guest sees; for
// fopen it is a fresh block, for the standard streams it is the slot in _iob.
std::uint64_t crt_stream_make(std::uint64_t object, int fd, bool for_read, bool for_write) {
  crt_streams[object] = GuestCrtStream{};
  crt_streams[object].fd = fd;
  crt_streams[object].for_read = for_read;
  crt_streams[object].for_write = for_write;
  return object;
}

// A FILE* the guest can hold: its own block in the guest heap, so the value is a
// guest address like every other pointer the CRT returns.
std::uint64_t crt_stream_allocate_object() {
  return heap_allocate(kMsvcrtFileObjectBytes);
}

void crt_files_seed() {
  crt_files.clear();
  crt_streams.clear();
  if (msvcrt_iob == 0) return;
  // stdin, stdout, stderr, in the order _iob lays them out and the order
  // __acrt_iob_func indexes.
  crt_stream_make(msvcrt_iob + 0 * kMsvcrtFileObjectBytes,
                  static_cast<int>(crt_file_new(STDIN_FILENO, 10)), true, false);
  crt_stream_make(msvcrt_iob + 1 * kMsvcrtFileObjectBytes,
                  static_cast<int>(crt_file_new(STDOUT_FILENO, 11)), false, true);
  crt_stream_make(msvcrt_iob + 2 * kMsvcrtFileObjectBytes,
                  static_cast<int>(crt_file_new(STDERR_FILENO, 12)), false, true);
}

// True when a guest buffer of `length` bytes at `address` lies inside the guest
// address space. Everything that copies between the two checks this first: a
// host read into a buffer the guest does not own writes over whatever follows the
// mapping, which is not a failure the guest can be told about.
bool guest_buffer_usable(std::uint64_t address, std::uint64_t length) {
  return length <= guest_memory_size && address <= guest_memory_size - length;
}

// Parses a CRT mode string ("rb", "w+", "a+t", ...) into open flags and the
// access the resulting stream has. Returns false for a mode Windows would reject,
// which the caller reports as a failed fopen rather than as a guess.
bool crt_parse_mode(const std::string& mode, int& host_flags, bool& for_read, bool& for_write) {
  const bool has_plus = mode.find('+') != std::string::npos;
  const bool text = mode.find('t') != std::string::npos || mode.find('b') == std::string::npos;
  for_read = false;
  for_write = false;
  if (mode.find('r') != std::string::npos) {
    if (has_plus) {
      host_flags = O_RDWR;
      for_read = for_write = true;
    } else {
      host_flags = O_RDONLY;
      for_read = true;
    }
    // Text mode translates line endings on Windows; a guest that opens "rt" and
    // reads back CRLF it never wrote would be a surprise, so the translation is
    // named here rather than quietly dropped. It is not implemented: every stream
    // is binary, which is what reading "rb" means.
    return true;
  }
  if (mode.find('w') != std::string::npos) {
    host_flags = has_plus ? O_RDWR : O_WRONLY;
    host_flags |= O_CREAT | O_TRUNC;
    for_write = true;
    for_read = has_plus;
    return true;
  }
  if (mode.find('a') != std::string::npos) {
    host_flags = (has_plus ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
    for_write = true;
    for_read = has_plus;
    return true;
  }
  (void)text;
  return false;
}

// ---- CRT: streams ---------------------------------------------------------
void msvcrt_fopen(GuestContext* context, bool wide) {
  const auto path_argument = import_argument(context, 0);
  const auto mode_text = read_guest_string(import_argument(context, 1));
  // _wfsopen and _wfopen name their path in UTF-16; the modes are still narrow.
  const auto path = wide ? read_guest_wide_string(path_argument) : read_guest_string(path_argument);
  std::string host_path;
  if (!guest_path_resolve(path, host_path, mode_text.find('w') != std::string::npos)) {
    set_import_result(context, 0);
    return;
  }
  int host_flags = 0;
  bool for_read = false;
  bool for_write = false;
  if (!crt_parse_mode(mode_text, host_flags, for_read, for_write)) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  const auto host_fd = ::open(host_path.c_str(), host_flags, 0644);
  if (host_fd < 0) {
    // Which failure it was matters to the caller: a missing file and a refused
    // path are different problems, and ENOENT/EPERM distinguish them.
    set_guest_last_error(errno == EACCES || errno == EPERM ? kErrorAccessDenied : kErrorFileNotFound);
    set_import_result(context, 0);
    return;
  }
  const auto object = crt_stream_allocate_object();
  if (object == 0) {
    ::close(host_fd);
    set_guest_last_error(kErrorNotEnoughMemory);
    set_import_result(context, 0);
    return;
  }
  if (object + kMsvcrtFileObjectBytes <= guest_memory_size)
    std::memset(guest_memory + object, 0, kMsvcrtFileObjectBytes);
  // The descriptor is created first so _fileno(f) has something to return, and
  // _close(f) has something to release.
  crt_stream_make(object, static_cast<int>(crt_file_new(host_fd, 0)), for_read, for_write);
  clear_guest_last_error();
  set_import_result(context, object);
}

void msvcrt_fclose(GuestContext* context) {
  const auto stream = import_argument(context, 0);
  const auto found = crt_streams.find(stream);
  if (found == crt_streams.end()) {
    // A stream this runtime did not create. Windows returns EOF and sets a bad
    // file descriptor; closing something unknown by guessing at its descriptor
    // would release a file the guest still has open.
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  const auto fd = found->second.fd;
  // The standard streams are not the program's to close. Releasing fd 1 makes
  // every later write to stdout fail, and the guest gets no signal that it did
  // something wrong -- it just stops being able to print.
  const bool standard = msvcrt_iob != 0 && stream >= msvcrt_iob &&
                        stream < msvcrt_iob + kMsvcrtFileCount * kMsvcrtFileObjectBytes;
  crt_streams.erase(found);
  auto* file = crt_file_get(static_cast<std::uint64_t>(fd));
  if (file != nullptr) {
    if (!standard) {
      if (file->host_fd >= 0) ::close(file->host_fd);
      if (file->handle != 0) guest_handle_close(file->handle);
      file->open = false;
      file->host_fd = -1;
    }
  }
  if (standard) {
    // Re-register the standard stream: fclose(stdin) is legal, it just has no
    // effect on the host descriptor, and the stream has to keep working after it.
    crt_stream_make(stream, fd, fd == 0, fd != 0);
  } else {
    // A FILE* whose object the guest may still hold, so the pointer cannot be
    // reused for a new file; leaving the table entry absent makes every later use
    // of it fail as a closed stream, which is what Windows does.
  }
  set_import_result(context, 0);
}

int guest_read_byte();

void msvcrt_fread(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto size = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  const auto stream = import_argument(context, 3);
  const auto total = size * count;
  auto* state = crt_stream(stream);
  if (state == nullptr || !state->for_read) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  if (total == 0) { set_import_result(context, 0); return; }
  const auto host_fd = crt_stream_descriptor(stream);
  if (host_fd < 0 || !guest_buffer_usable(buffer, total)) {
    state->had_error = true;
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  bool failed = false;
  std::size_t filled = 0;
  while (filled < total) {
    if (state->pushback >= 0) {
      guest_memory[buffer + filled] = static_cast<std::uint8_t>(state->pushback);
      state->pushback = -1;
      ++filled;
      continue;
    }
    if (guest_input_capture != nullptr && stream == msvcrt_iob) {
      const auto character = guest_read_byte();
      if (character < 0) break;
      guest_memory[buffer + filled++] = static_cast<std::uint8_t>(character);
      continue;
    }
    const auto read = ::read(host_fd, guest_memory + buffer + filled, total - filled);
    if (read == 0) break;
    if (read < 0) { failed = true; break; }
    filled += static_cast<std::size_t>(read);
  }
  if (filled < total) {
    // A read that reaches the end of the file is not an error, and the two flags
    // mean different things to the caller: feof() after a clean exhaustion tells a
    // parsing loop to stop, ferror() tells it the data is corrupt. Setting both
    // makes a file read to its end look like a failed read.
    if (failed) {
      state->had_error = true;
      set_guest_last_error(kErrorInvalidHandle);
      set_import_result(context, 0);
      return;
    }
    state->at_eof = true;
  }
  clear_guest_last_error();
  // Items, not bytes: size * count bytes filled is `size` items when size is not
  // 1, and the caller compares the return value against `count`.
  set_import_result(context, size == 0 ? 0 : filled / size);
}

void msvcrt_fwrite(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto size = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  const auto stream = import_argument(context, 3);
  const auto total = size * count;
  auto* state = crt_stream(stream);
  if (state == nullptr || !state->for_write) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  if (total == 0) { set_import_result(context, 0); return; }
  const auto host_fd = crt_stream_descriptor(stream);
  if (host_fd < 0 || !guest_buffer_usable(buffer, total)) {
    state->had_error = true;
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  // The standard streams go through the output writer, which is what the
  // differential reference captures; a real file is written to its own descriptor.
  const bool standard = msvcrt_iob != 0 && stream >= msvcrt_iob &&
                        stream < msvcrt_iob + kMsvcrtFileCount * kMsvcrtFileObjectBytes;
  std::size_t written = 0;
  while (written < total) {
    const auto accepted = standard
        ? write_guest_output(host_fd, reinterpret_cast<const char*>(guest_memory + buffer + written),
                             total - written)
        : ::write(host_fd, guest_memory + buffer + written, total - written);
    if (accepted <= 0) break;
    written += static_cast<std::size_t>(accepted);
  }
  if (written < total) state->had_error = true;
  if (written == 0) { set_import_result(context, 0); return; }
  clear_guest_last_error();
  set_import_result(context, size == 0 ? 0 : written / size);
}

void msvcrt_fseek(GuestContext* context, bool wide_offset) {
  const auto stream = import_argument(context, 0);
  const auto raw = import_argument(context, 1);
  const auto origin = static_cast<std::int32_t>(import_argument(context, 2));
  auto* state = crt_stream(stream);
  if (state == nullptr) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  // `fseek`'s offset is a C `long`, which on Windows is 32 bits at *both* guest
  // widths -- LLP64, not LP64. A PE32+ guest moving -4 into a register leaves the
  // upper half zero, so reading it as a 64-bit value gives +4294967292, the seek
  // lands past the end, and the next read returns nothing: an empty file, reported
  // as success. `_fseeki64` is the 64-bit form and takes the register as it is.
  std::int64_t offset = wide_offset
      ? static_cast<std::int64_t>(raw)
      : static_cast<std::int64_t>(static_cast<std::int32_t>(static_cast<std::uint32_t>(raw)));
  const auto host_fd = crt_stream_descriptor(stream);
  if (host_fd < 0) {
    state->had_error = true;
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  int host_origin = SEEK_SET;
  if (origin == 1) host_origin = SEEK_CUR;
  else if (origin == 2) host_origin = SEEK_END;
  const auto position = ::lseek(host_fd, static_cast<off_t>(offset), host_origin);
  if (position < 0) {
    state->had_error = true;
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  // Seeking is the one thing that reliably clears a previous end-of-file, and a
  // stream that stayed flagged would make a program's next read look exhausted.
  state->at_eof = false;
  state->pushback = -1;
  clear_guest_last_error();
  set_import_result(context, 0);
}

void msvcrt_ftell(GuestContext* context) {
  const auto stream = import_argument(context, 0);
  const auto host_fd = crt_stream_descriptor(stream);
  if (host_fd < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  set_import_result(context, static_cast<std::uint64_t>(::lseek(host_fd, 0, SEEK_CUR)));
}

void msvcrt_feof(GuestContext* context) {
  auto* state = crt_stream(import_argument(context, 0));
  set_import_result(context, state != nullptr && state->at_eof ? 1 : 0);
}
void msvcrt_ferror(GuestContext* context) {
  auto* state = crt_stream(import_argument(context, 0));
  set_import_result(context, state != nullptr && state->had_error ? 1 : 0);
}
void msvcrt_clearerr(GuestContext* context) {
  auto* state = crt_stream(import_argument(context, 0));
  if (state != nullptr) {
    state->at_eof = false;
    state->had_error = false;
  }
}
void msvcrt_rewind(GuestContext* context) {
  const auto stream = import_argument(context, 0);
  auto* state = crt_stream(stream);
  const auto host_fd = crt_stream_descriptor(stream);
  if (state == nullptr || host_fd < 0) {
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  ::lseek(host_fd, 0, SEEK_SET);
  state->at_eof = false;
  state->had_error = false;
  state->pushback = -1;
  set_import_result(context, 0);
}

void msvcrt_fgetc(GuestContext* context, bool for_write) {
  const auto stream = import_argument(context, for_write ? 1 : 0);
  auto* state = crt_stream(stream);
  const auto host_fd = crt_stream_descriptor(stream);
  if (state == nullptr || host_fd < 0) {
    if (state != nullptr) state->had_error = true;
    set_import_result(context, static_cast<std::uint64_t>(-1));  // EOF
    return;
  }
  if (!for_write) {
    if (state->pushback >= 0) {
      const auto value = state->pushback;
      state->pushback = -1;
      set_import_result(context, static_cast<std::uint64_t>(value));
      return;
    }
    if (guest_input_capture != nullptr && stream == msvcrt_iob) {
      const auto character = guest_read_byte();
      if (character < 0) state->at_eof = true;
      else state->at_eof = false;
      set_import_result(context, character < 0 ? static_cast<std::uint64_t>(-1)
                                              : static_cast<std::uint64_t>(character));
      return;
    }
    std::uint8_t byte = 0;
    const auto read = ::read(host_fd, &byte, 1);
    if (read <= 0) {
      // EOF and error are different answers, and the guest distinguishes them by
      // calling feof or ferror afterwards.
      if (read == 0) state->at_eof = true; else state->had_error = true;
      set_import_result(context, static_cast<std::uint64_t>(-1));
      return;
    }
    set_import_result(context, byte);
    return;
  }
  if (!state->for_write) {
    state->had_error = true;
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  const auto character = static_cast<std::uint8_t>(import_argument(context, 0));
  const auto written = ::write(host_fd, &character, 1);
  if (written != 1) {
    state->had_error = true;
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  set_import_result(context, character);
}

void msvcrt_fgets(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto maximum = import_argument(context, 1);
  const auto stream = import_argument(context, 2);
  auto* state = crt_stream(stream);
  const auto host_fd = crt_stream_descriptor(stream);
  if (state == nullptr || host_fd < 0 || !state->for_read || maximum <= 1 ||
      !guest_buffer_usable(buffer, static_cast<std::uint64_t>(maximum))) {
    if (state != nullptr) state->had_error = true;
    set_import_result(context, 0);
    return;
  }
  std::uint64_t filled = 0;
  while (filled + 1 < static_cast<std::uint64_t>(maximum)) {
    std::uint8_t byte = 0;
    if (state->pushback >= 0) {
      byte = static_cast<std::uint8_t>(state->pushback);
      state->pushback = -1;
    } else if (guest_input_capture != nullptr && stream == msvcrt_iob) {
      const auto character = guest_read_byte();
      if (character < 0) {
        state->at_eof = true;
        break;
      }
      state->at_eof = false;
      byte = static_cast<std::uint8_t>(character);
    } else {
      const auto one = ::read(host_fd, &byte, 1);
      if (one != 1) {
        // A read of zero bytes is the end of the file; a read that failed is an
        // error. Both leave the loop, and the guest distinguishes them afterwards
        // by calling feof() or ferror(), so they must not set the same flag.
        if (one == 0) state->at_eof = true;
        else state->had_error = true;
        break;
      }
    }
    guest_memory[buffer + filled++] = byte;
    if (byte == '\n') break;
  }
  if (filled == 0) { set_import_result(context, 0); return; }
  guest_memory[buffer + filled] = 0;
  set_import_result(context, buffer);
}

void msvcrt_fputs(GuestContext* context) {
  const auto text_address = import_argument(context, 0);
  const auto stream = import_argument(context, 1);
  auto* state = crt_stream(stream);
  const auto host_fd = crt_stream_descriptor(stream);
  if (state == nullptr || host_fd < 0 || !state->for_write) {
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  const auto text = read_guest_string(text_address);
  std::size_t written = 0;
  while (written < text.size()) {
    const auto accepted = ::write(host_fd, text.data() + written, text.size() - written);
    if (accepted <= 0) break;
    written += static_cast<std::size_t>(accepted);
  }
  if (written != text.size()) {
    state->had_error = true;
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  set_import_result(context, 0);
}

void msvcrt_ungetc(GuestContext* context) {
  const auto character = import_argument(context, 0);
  const auto stream = import_argument(context, 1);
  auto* state = crt_stream(stream);
  if (state == nullptr || !state->for_read || character == 0xffffffffull) {
    set_import_result(context, static_cast<std::uint64_t>(-1));  // EOF
    return;
  }
  state->pushback = static_cast<std::int32_t>(character & 0xffu);
  state->at_eof = false;
  set_import_result(context, static_cast<std::uint64_t>(state->pushback));
}

// No host buffering exists to flush: every write goes straight to the descriptor.
// fflush therefore succeeds without doing anything, and says so by returning 0 --
// the answer a caller checking for a failed flush is looking for.
void msvcrt_fflush(GuestContext* context) { set_import_result(context, 0); }

void msvcrt_fileno(GuestContext* context) {
  const auto stream = import_argument(context, 0);
  auto* state = crt_stream(stream);
  if (state == nullptr) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  set_import_result(context, static_cast<std::uint64_t>(state->fd));
}

void msvcrt_open(GuestContext* context, bool wide) {
  const auto path_argument = import_argument(context, 0);
  const auto of_flags = static_cast<std::uint32_t>(import_argument(context, 1));
  const auto path = wide ? read_guest_wide_string(path_argument) : read_guest_string(path_argument);
  std::string host_path;
  if (!guest_path_resolve(path, host_path, (of_flags & 0x0100u) != 0)) {
    set_import_result(context, static_cast<std::uint64_t>(-2));  // ENOENT
    return;
  }
  // _O_RDONLY 0x0000, _O_WRONLY 0x0001, _O_RDWR 0x0002, _O_APPEND 0x0008,
  // _O_CREAT 0x0100, _O_TRUNC 0x0200, _O_EXCL 0x0400. The access bits are the low
  // two bits, which is the same shape the host uses.
  int host_flags = of_flags & 0x3;
  if ((of_flags & 0x0100u) != 0) host_flags |= O_CREAT;
  if ((of_flags & 0x0200u) != 0) host_flags |= O_TRUNC;
  if ((of_flags & 0x0400u) != 0) host_flags |= O_EXCL;
  if ((of_flags & 0x0008u) != 0) host_flags |= O_APPEND;
  const auto host_fd = ::open(host_path.c_str(), host_flags, 0644);
  if (host_fd < 0) {
    set_guest_last_error(kErrorFileNotFound);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  clear_guest_last_error();
  set_import_result(context, crt_file_new(host_fd, 0));
}

void msvcrt_close(GuestContext* context) {
  auto* file = crt_file_get(import_argument(context, 0));
  if (file == nullptr) { set_import_result(context, static_cast<std::uint64_t>(-1)); return; }
  if (file->host_fd >= 0) ::close(file->host_fd);
  file->open = false;
  file->host_fd = -1;
  set_import_result(context, 0);
}

void msvcrt_read_or_write(GuestContext* context, bool for_write) {
  auto* file = crt_file_get(import_argument(context, 0));
  const auto buffer = import_argument(context, 1);
  const auto length = import_argument(context, 2);
  if (file == nullptr || file->host_fd < 0 || length > guest_memory_size ||
      buffer > guest_memory_size - length) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  const std::size_t count = static_cast<std::size_t>(length);
  std::size_t moved = 0;
  while (moved < count) {
    const auto accepted = for_write
        ? ::write(file->host_fd, guest_memory + buffer + moved, count - moved)
        : ::read(file->host_fd, guest_memory + buffer + moved, count - moved);
    if (accepted <= 0) break;
    moved += static_cast<std::size_t>(accepted);
  }
  if (!for_write && moved < count) {
    // A short read from a descriptor is the end of the file, not an error.
    set_guest_last_error(0);
  }
  set_import_result(context, moved);
}

void msvcrt_lseek(GuestContext* context) {
  auto* file = crt_file_get(import_argument(context, 0));
  const auto raw_offset = import_argument(context, 1);
  const auto origin = static_cast<std::int32_t>(import_argument(context, 2));
  if (file == nullptr || file->host_fd < 0) {
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  // `_lseek`'s offset is a C `long`: 32 bits on Windows at both guest widths, so a
  // negative seek arrives as 0xfffffffc in a 64-bit register and has to be read
  // back as -4. See msvcrt_fseek for what it reports if it is not.
  const auto offset = static_cast<std::int64_t>(static_cast<std::int32_t>(
      static_cast<std::uint32_t>(raw_offset)));
  int host_origin = SEEK_SET;
  if (origin == 1) host_origin = SEEK_CUR;
  else if (origin == 2) host_origin = SEEK_END;
  set_import_result(context, static_cast<std::uint64_t>(
      ::lseek(file->host_fd, static_cast<off_t>(offset), host_origin)));
}

// Bridges a guest HANDLE to a CRT descriptor, which is how a program that opened
// a file with CreateFileA goes on to read it with fread.
void msvcrt_open_osfhandle(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || entry->type != kGuestHandleFile || entry->host_descriptor < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  set_import_result(context, crt_file_new(entry->host_descriptor, handle));
}

void msvcrt_fdopen(GuestContext* context, bool wide) {
  const auto fd = static_cast<std::uint64_t>(import_argument(context, 0));
  const auto mode_text = wide ? read_guest_wide_string(import_argument(context, 1))
                              : read_guest_string(import_argument(context, 1));
  auto* file = crt_file_get(fd);
  if (file == nullptr) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  int host_flags = 0;
  bool for_read = false;
  bool for_write = false;
  if (!crt_parse_mode(mode_text, host_flags, for_read, for_write)) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  const auto object = crt_stream_allocate_object();
  if (object == 0) { set_import_result(context, 0); return; }
  if (object + kMsvcrtFileObjectBytes <= guest_memory_size)
    std::memset(guest_memory + object, 0, kMsvcrtFileObjectBytes);
  crt_stream_make(object, static_cast<int>(fd), for_read, for_write);
  set_import_result(context, object);
}

void msvcrt_remove_or_rename(GuestContext* context, bool rename) {
  const auto first = read_guest_string(import_argument(context, 0));
  std::string host_first;
  if (!guest_path_resolve(first, host_first, false)) {
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  if (!rename) {
    set_import_result(context, ::remove(host_first.c_str()) == 0 ? 0u : static_cast<std::uint64_t>(-1));
    return;
  }
  const auto second = read_guest_string(import_argument(context, 1));
  std::string host_second;
  if (!guest_path_resolve(second, host_second, true)) {
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  set_import_result(context, ::rename(host_first.c_str(), host_second.c_str()) == 0 ? 0u
                                                                                    : static_cast<std::uint64_t>(-1));
}

// The C runtime's allocator is the guest heap, so a pointer it returns is
// indistinguishable from one HeapAlloc returns -- which is what a program that
// mixes the two expects.
void msvcrt_malloc(GuestContext* context) {
  set_import_result(context, heap_allocate(import_argument(context, 0)));
}
void msvcrt_calloc(GuestContext* context) {
  const auto count = import_argument(context, 0);
  const auto size = import_argument(context, 1);
  const auto total = count * size;
  const auto block = heap_allocate(total);
  if (block != 0)
    for (std::uint64_t offset = 0; offset < total; ++offset) store_guest_memory(context, block + offset, 0, 1);
  set_import_result(context, block);
}
void msvcrt_realloc(GuestContext* context) {
  const auto pointer = import_argument(context, 0);
  const auto size = import_argument(context, 1);
  if (pointer == 0) { set_import_result(context, heap_allocate(size)); return; }
  const auto old_size = heap_block_size(pointer);
  const auto replacement = heap_allocate(size);
  if (replacement == 0) { set_import_result(context, 0); return; }
  const auto copy = old_size < size ? old_size : size;
  for (std::uint64_t offset = 0; offset < copy; ++offset)
    store_guest_memory(context, replacement + offset, load_guest_memory(context, pointer + offset, 1), 1);
  heap_release(context, pointer);
  set_import_result(context, replacement);
}
void msvcrt_free(GuestContext* context) {
  const auto pointer = import_argument(context, 0);
  if (pointer != 0) heap_release(context, pointer);
  set_import_result(context, 0);
}
void msvcrt_memcpy(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  for (std::uint64_t offset = 0; offset < count; ++offset)
    store_guest_memory(context, destination + offset, load_guest_memory(context, source + offset, 1), 1);
  set_import_result(context, destination);
}
void msvcrt_memmove(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  // Overlap-safe: copy backwards when the destination is above the source.
  if (destination > source && destination < source + count) {
    for (std::uint64_t offset = count; offset > 0; --offset)
      store_guest_memory(context, destination + offset - 1, load_guest_memory(context, source + offset - 1, 1), 1);
  } else {
    for (std::uint64_t offset = 0; offset < count; ++offset)
      store_guest_memory(context, destination + offset, load_guest_memory(context, source + offset, 1), 1);
  }
  set_import_result(context, destination);
}
void msvcrt_memset(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto value = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  for (std::uint64_t offset = 0; offset < count; ++offset) store_guest_memory(context, destination + offset, value, 1);
  set_import_result(context, destination);
}
void msvcrt_strdup(GuestContext* context) {
  const auto source = import_argument(context, 0);
  const auto text = read_guest_string(source);
  const auto block = heap_allocate(text.size() + 1);
  if (block == 0) { set_import_result(context, 0); return; }
  for (std::size_t index = 0; index < text.size(); ++index)
    store_guest_memory(context, block + index, static_cast<std::uint8_t>(text[index]), 1);
  store_guest_memory(context, block + text.size(), 0, 1);
  set_import_result(context, block);
}

// A deterministic generator: a program that seeds and then compares output must
// see the same sequence every run, and a differential comparison requires it.
std::uint32_t msvcrt_random_state = 1;
void msvcrt_srand(GuestContext* context) { msvcrt_random_state = static_cast<std::uint32_t>(import_argument(context, 0)); }
void msvcrt_rand(GuestContext* context) {
  msvcrt_random_state = msvcrt_random_state * 214013u + 2531011u;
  set_import_result(context, (msvcrt_random_state >> 16) & 0x7fffu);
}

// The bytes the guest reads as stdin. The reference runs in this process and the
// candidate in a subprocess, so a capture that is set only here would leave the candidate
// reading the real stdin -- which the capture has already consumed -- and the two would
// disagree for a reason that has nothing to do with the translation. This is called from
// `initialize_guest_state`, which BOTH sides pass through, so the file reaches both.
std::string guest_input_storage;

void load_guest_input_from_environment() {
  const char* path = std::getenv("RECOMP_STDIN_FILE");
  if (path == nullptr || path[0] == '\0') return;
  std::FILE* file = std::fopen(path, "rb");
  if (file == nullptr) {
    std::fprintf(stderr, "recomp: RECOMP_STDIN_FILE=%s could not be opened\n", path);
    return;
  }
  char buffer[4096];
  std::size_t read = 0;
  while ((read = std::fread(buffer, 1, sizeof(buffer), file)) != 0) guest_input_storage.append(buffer, read);
  std::fclose(file);
  guest_input_capture = &guest_input_storage;
  guest_input_position = 0;
}
int guest_read_byte() {
  if (guest_input_capture != nullptr) {
    if (guest_input_position >= guest_input_capture->size()) return -1;
    return static_cast<unsigned char>((*guest_input_capture)[guest_input_position++]);
  }
  return std::fgetc(stdin);
}

void msvcrt_getchar(GuestContext* context) {
  const auto character = guest_read_byte();
  set_import_result(context, character < 0 ? static_cast<std::uint64_t>(-1)
                                           : static_cast<std::uint64_t>(static_cast<unsigned char>(character)));
}

void msvcrt_fgetc(GuestContext* context) {
  msvcrt_fgetc(context, false);
}

void msvcrt_puts(GuestContext* context) {
  auto address = import_argument(context, 0);
  std::string text;
  for (;;) {
    const auto byte = static_cast<char>(load_guest_memory(context, address++, 1));
    if (byte == '\0') break;
    text.push_back(byte);
  }
  text.push_back('\n');
  const auto written = write_guest_output(STDOUT_FILENO, text.data(), text.size());
  set_import_result(context, written < 0 ? static_cast<std::uint64_t>(-1) : 0);
}

void msvcrt_putchar(GuestContext* context) {
  const auto character = static_cast<unsigned char>(import_argument(context, 0));
  const char byte = static_cast<char>(character);
  const auto written = write_guest_output(STDOUT_FILENO, &byte, 1);
  set_import_result(context, written < 0 ? static_cast<std::uint64_t>(-1) : character);
}

// CRT globals. Each accessor returns the address of a variable in the reserved
// CRT block, which is what the real functions do.
void msvcrt_errno(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x000); }
void msvcrt_p_environ(GuestContext* context) { set_import_result(context, msvcrt_environment_pointer); }
void msvcrt_p_fmode(GuestContext* context) { set_import_result(context, msvcrt_file_mode_pointer); }
void msvcrt_iob_pointer(GuestContext* context) { set_import_result(context, msvcrt_iob); }
void msvcrt_pctype(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x300); }
void msvcrt_mb_cur_max(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x320); }
void msvcrt_mb_cur_max_func(GuestContext* context) { set_import_result(context, 4); }

// ---- msvcrt: strings and numeric conversion -------------------------------
void msvcrt_strlen(GuestContext* context) {
  set_import_result(context, read_guest_string(import_argument(context, 0)).size());
}
void msvcrt_strcmp(GuestContext* context) {
  const auto left = read_guest_string(import_argument(context, 0));
  const auto right = read_guest_string(import_argument(context, 1));
  const auto order = left.compare(right);
  set_import_result(context, order < 0 ? static_cast<std::uint64_t>(-1)
                                       : order > 0 ? std::uint64_t{1} : std::uint64_t{0});
}
void msvcrt_strncmp(GuestContext* context) {
  const auto left = read_guest_string(import_argument(context, 0));
  const auto right = read_guest_string(import_argument(context, 1));
  const auto limit = static_cast<std::size_t>(import_argument(context, 2));
  const auto order = left.compare(0, limit, right, 0, limit);
  set_import_result(context, order < 0 ? static_cast<std::uint64_t>(-1)
                                       : order > 0 ? std::uint64_t{1} : std::uint64_t{0});
}
void msvcrt_strcpy(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto text = read_guest_string(import_argument(context, 1));
  for (std::size_t index = 0; index <= text.size(); ++index)
    store_guest_memory(context, destination + index,
                       index < text.size() ? static_cast<std::uint8_t>(text[index]) : 0, 1);
  set_import_result(context, destination);
}
void msvcrt_strncpy(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto text = read_guest_string(import_argument(context, 1));
  const auto limit = static_cast<std::size_t>(import_argument(context, 2));
  for (std::size_t index = 0; index < limit; ++index)
    store_guest_memory(context, destination + index,
                       index < text.size() ? static_cast<std::uint8_t>(text[index]) : 0, 1);
  set_import_result(context, destination);
}
void msvcrt_strcat(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto tail = read_guest_string(import_argument(context, 1));
  const auto offset = read_guest_string(destination).size();
  for (std::size_t index = 0; index <= tail.size(); ++index)
    store_guest_memory(context, destination + offset + index,
                       index < tail.size() ? static_cast<std::uint8_t>(tail[index]) : 0, 1);
  set_import_result(context, destination);
}
// `strchr(s, 0)` is defined to return a pointer to the TERMINATING NUL, not null. The
// string read here stops before the terminator, so searching for a zero character found
// nothing and returned null -- wrong for a case callers really use, because
// `strchr(s, 0)` is the standard way to get a pointer to the end of a string.
void msvcrt_strchr(GuestContext* context) {
  const auto base = import_argument(context, 0);
  const auto text = read_guest_string(base);
  const auto character = static_cast<char>(import_argument(context, 1) & 0xffu);
  if (character == '\0') {
    set_import_result(context, base + text.size());
    return;
  }
  const auto found = text.find(character);
  set_import_result(context, found == std::string::npos ? 0 : base + found);
}
void msvcrt_strrchr(GuestContext* context) {
  const auto base = import_argument(context, 0);
  const auto text = read_guest_string(base);
  const auto character = static_cast<char>(import_argument(context, 1) & 0xffu);
  // The same rule for the reverse search: the terminator is the LAST occurrence of a
  // zero character, and the search stops there.
  if (character == '\0') {
    set_import_result(context, base + text.size());
    return;
  }
  const auto found = text.rfind(character);
  set_import_result(context, found == std::string::npos ? 0 : base + found);
}
void msvcrt_strstr(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto needle = read_guest_string(import_argument(context, 1));
  const auto found = text.find(needle);
  set_import_result(context, found == std::string::npos ? 0 : import_argument(context, 0) + found);
}
// The string-to-number family, on the HOST's implementation.
//
// What was here used `std::stol(text, &consumed, base == 0 ? 10 : base)`, and that
// ternary is wrong in a way that is easy to miss: `strtol` with base 0 is defined to
// DETECT the base from the text, so `strtol("0x1f", NULL, 0)` is 31 and `strtol("010",
// NULL, 0)` is 8. Forcing base 10 made the first return 0 and the second return 10.
// It also threw on overflow and on a string with no digits, which `strtol` does not do
// -- it returns a clamped value and sets the end pointer to the start.
//
// The host has the real implementation, so it is called directly. Only the guest's
// calling convention is this function's business.
std::uint64_t msvcrt_parse_integer(GuestContext* context, bool is_signed, int width) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto base = static_cast<int>(import_argument(context, 2));
  char* end = nullptr;
  std::uint64_t value = 0;
  if (is_signed) {
    const auto parsed = std::strtoll(text.c_str(), &end, base);
    value = static_cast<std::uint64_t>(width >= 8 ? parsed : static_cast<std::int32_t>(parsed));
  } else {
    const auto parsed = std::strtoull(text.c_str(), &end, base);
    value = width >= 8 ? parsed : static_cast<std::uint32_t>(parsed);
  }
  const auto end_pointer = import_argument(context, 1);
  if (end_pointer != 0) {
    // The end pointer is a GUEST address, and it points at the first character not
    // consumed. When nothing was consumed that is the start of the string, which is
    // what `strtol` reports and what a caller checking for "no digits" relies on.
    const auto consumed = static_cast<std::uint64_t>(end - text.c_str());
    store_guest_memory(context, end_pointer, import_argument(context, 0) + consumed, guest_pointer_width);
  }
  return value;
}

void msvcrt_strtol(GuestContext* context) {
  set_import_result(context, msvcrt_parse_integer(context, true, 4));
}
void msvcrt_strtoul(GuestContext* context) {
  set_import_result(context, msvcrt_parse_integer(context, false, 4));
}
// The 64-bit forms exist because the guest's `long` is 32 bits on Windows while the
// host's is 64: `strtol` must truncate to what the guest asked for, and `strtoll` must
// not.
void msvcrt_strtoll(GuestContext* context) {
  set_import_result(context, msvcrt_parse_integer(context, true, 8));
}
void msvcrt_strtoull(GuestContext* context) {
  set_import_result(context, msvcrt_parse_integer(context, false, 8));
}

// strtod/atof, on the host's parser: the same reasoning, and the host's is correct for
// infinities, subnormals, exponents and the C locale's decimal point.
void msvcrt_strtod(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  char* end = nullptr;
  const auto value = std::strtod(text.c_str(), &end);
  const auto end_pointer = import_argument(context, 1);
  if (end_pointer != 0) {
    const auto consumed = static_cast<std::uint64_t>(end - text.c_str());
    store_guest_memory(context, end_pointer, import_argument(context, 0) + consumed, guest_pointer_width);
  }
  std::uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  set_import_result(context, bits);
}
void msvcrt_atof(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto value = std::strtod(text.c_str(), nullptr);
  std::uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  set_import_result(context, bits);
}
void msvcrt_atoi(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  set_import_result(context, static_cast<std::uint64_t>(static_cast<std::int64_t>(std::atoll(text.c_str()))));
}
void msvcrt_atol(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  set_import_result(context, static_cast<std::uint64_t>(
                                 static_cast<std::int64_t>(static_cast<std::int32_t>(std::atoll(text.c_str())))));
}
void msvcrt_toupper(GuestContext* context) {
  set_import_result(context, static_cast<std::uint64_t>(
                                 std::toupper(static_cast<int>(import_argument(context, 0) & 0xffu))));
}
void msvcrt_tolower(GuestContext* context) {
  set_import_result(context, static_cast<std::uint64_t>(
                                 std::tolower(static_cast<int>(import_argument(context, 0) & 0xffu))));
}
void msvcrt_stricmp(GuestContext* context) {
  auto left = read_guest_string(import_argument(context, 0));
  auto right = read_guest_string(import_argument(context, 1));
  for (auto& character : left) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  for (auto& character : right) character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  const auto order = left.compare(right);
  set_import_result(context, order < 0 ? static_cast<std::uint64_t>(-1)
                                       : order > 0 ? std::uint64_t{1} : std::uint64_t{0});
}

void msvcrt_noop(GuestContext* context) { set_import_result(context, 0); }

// ---- atexit -----------------------------------------------------------------
// The handlers a guest registers, in registration order. The C runtime runs them in
// reverse when the process exits. Reporting success without keeping them made a
// program that registers an exit handler appear to work while the handler never ran,
// which is the worst of both: no diagnostic and no behaviour.
std::vector<std::uint64_t> guest_atexit_handlers;

// The live guest context, so the exit path can run the handlers. It is set once, when
// the guest context is created, and cleared when the image returns.
GuestContext* guest_context_for_atexit = nullptr;

void run_guest_atexit_handlers(GuestContext* context);
void report_unrun_atexit_handlers();

const std::vector<std::uint64_t>& registered_atexit_handlers() { return guest_atexit_handlers; }

void msvcrt_cexit(GuestContext* context) {
  report_unrun_atexit_handlers();
  set_import_result(context, 0);
}

void msvcrt_register_atexit(GuestContext* context) {
  const auto handler = import_argument(context, 0);
  if (handler != 0) guest_atexit_handlers.push_back(handler);
  set_import_result(context, 0);
}

// Names every registered handler that will not run. A guest cannot observe a handler
// that silently did not run, so the only honest place to report it is here.
void report_unrun_atexit_handlers() {
  for (const auto handler : guest_atexit_handlers) {
    // Whether the address is code at all is the first thing a reader needs, and it is
    // not always true: the C runtime's own registration reaches this shim from a single
    // call site that walks a table, and this program's list contained an address in
    // .rdata as well as a null. An address that was never recovered cannot be run
    // whatever the exit path does; one that was recovered is a different problem, and
    // the two should not read the same.
    const bool is_code = lookup_guest_function(handler) != nullptr;
    std::fprintf(stderr,
                 "recomp: the guest registered an atexit handler at 0x%llx (%s), which did not run; "
                 "exit handlers are registered but not executed\n",
                 static_cast<unsigned long long>(handler),
                 is_code ? "a recompiled function" : "not a recompiled function");
  }
  guest_atexit_handlers.clear();
}

void run_guest_atexit_handlers(GuestContext* context) {
  while (!guest_atexit_handlers.empty()) {
    const auto handler = guest_atexit_handlers.back();
    guest_atexit_handlers.pop_back();
    auto function = lookup_guest_function(handler);
    if (function == nullptr) {
      // Fail loudly rather than silently skipping: a handler that did not run is a
      // behaviour difference, and the guest cannot observe it any other way.
      std::fprintf(stderr, "recomp: an atexit handler at 0x%llx was not recompiled, so it did not run\n",
                   static_cast<unsigned long long>(handler));
      continue;
    }
    push_guest_stack(context, 0);
    function(context);
  }
}

// _onexit returns the function pointer it was given (NULL on failure); atexit
// returns 0. A CRT that stores the return value of _onexit into its exit table
// therefore stores the pointer, and returning 0 there puts a null into the table
// that the exit loop then calls.
void msvcrt_onexit(GuestContext* context) { set_import_result(context, import_argument(context, 0)); }
void msvcrt_abort(GuestContext* context) {
  terminate_with_message("abort() called by the guest (ip=0x%" PRIx64 ")", context->instruction_pointer);
}
void msvcrt_exit(GuestContext* context) {
  guest_request_exit(static_cast<int>(import_argument(context, 0)));
}
void msvcrt_isctype(GuestContext* context) {
  const auto character = import_argument(context, 1);
  set_import_result(context, classify_character(static_cast<std::uint32_t>(character & 0xffu)) != 0 ? 1 : 0);
}
void msvcrt_wctype(GuestContext* context) {
  const auto name = read_guest_string(import_argument(context, 0));
  const auto descriptor = std::wctype(name.c_str());
  set_import_result(context, static_cast<std::uint64_t>(descriptor));
}
void msvcrt_iswctype(GuestContext* context) {
  const auto character = static_cast<wint_t>(import_argument(context, 0));
  const auto descriptor = static_cast<std::wctype_t>(import_argument(context, 1));
  set_import_result(context, std::iswctype(character, descriptor) != 0 ? 1 : 0);
}
void msvcrt_mbstowcs(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  const auto maximum = import_argument(context, 2);
  const auto text = read_guest_string(source);
  std::uint64_t written = 0;
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (maximum != 0 && written >= maximum) break;
    store_guest_memory(context, destination + written * 2, static_cast<std::uint8_t>(text[index]), 2);
    ++written;
  }
  if (maximum == 0 || written < maximum) {
    store_guest_memory(context, destination + written * 2, 0, 2);
    set_import_result(context, written);
  } else {
    set_import_result(context, static_cast<std::uint64_t>(-1));
  }
}
namespace {
std::mutex guest_multibyte_state_mutex;
std::map<std::uint64_t, std::mbstate_t> guest_multibyte_states;

locale_t guest_utf8_locale() {
  static const locale_t locale = [] {
    auto created = newlocale(LC_CTYPE_MASK, "en_US.UTF-8", nullptr);
    if (created == nullptr) created = newlocale(LC_CTYPE_MASK, "C.UTF-8", nullptr);
    return created;
  }();
  return locale;
}

std::size_t guest_mbrtowc(wchar_t* output, const char* input, std::size_t length, std::mbstate_t* state) {
  const auto locale = guest_utf8_locale();
  const auto previous = locale != nullptr ? uselocale(locale) : static_cast<locale_t>(0);
  const auto converted = std::mbrtowc(output, input, length, state);
  if (locale != nullptr) uselocale(previous);
  return converted;
}

std::mbstate_t guest_multibyte_state(std::uint64_t address) {
  std::lock_guard lock(guest_multibyte_state_mutex);
  return guest_multibyte_states[address];
}

void store_guest_multibyte_state(std::uint64_t address, const std::mbstate_t& state) {
  std::lock_guard lock(guest_multibyte_state_mutex);
  guest_multibyte_states[address] = state;
}

void store_guest_utf16(GuestContext* context, std::uint64_t destination, wchar_t value) {
  const auto codepoint = static_cast<std::uint32_t>(value);
  if (codepoint <= 0xffffu) {
    store_guest_memory(context, destination, codepoint, 2);
    return;
  }
  const auto scalar = codepoint - 0x10000u;
  store_guest_memory(context, destination, 0xd800u + (scalar >> 10), 2);
  store_guest_memory(context, destination + 2, 0xdc00u + (scalar & 0x3ffu), 2);
}
}  // namespace

void msvcrt_mbrtowc(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  const auto length = import_argument(context, 2);
  const auto state_address = import_argument(context, 3);
  auto state = guest_multibyte_state(state_address);
  if (source == 0) {
    std::memset(&state, 0, sizeof(state));
    store_guest_multibyte_state(state_address, state);
    set_import_result(context, 0);
    return;
  }
  std::string bytes;
  for (std::uint64_t index = 0; index < std::min<std::uint64_t>(length, 8); ++index) {
    const auto byte = static_cast<std::uint8_t>(load_guest_memory(context, source + index, 1));
    bytes.push_back(static_cast<char>(byte));
    if (byte == 0) break;
  }
  wchar_t converted_character = 0;
  const auto converted = guest_mbrtowc(&converted_character, bytes.data(), bytes.size(), &state);
  store_guest_multibyte_state(state_address, state);
  if (converted == static_cast<std::size_t>(-1) || converted == static_cast<std::size_t>(-2)) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, static_cast<std::uint64_t>(converted));
    return;
  }
  if (destination != 0) store_guest_utf16(context, destination, converted_character);
  set_import_result(context, converted);
}

void msvcrt_mbsrtowcs(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source_pointer = import_argument(context, 1);
  const auto maximum = import_argument(context, 2);
  const auto state_address = import_argument(context, 3);
  auto source = load_guest_memory(context, source_pointer, guest_pointer_width);
  auto state = guest_multibyte_state(state_address);
  std::size_t converted_units = 0;
  while (source != 0 && (destination == 0 || converted_units < maximum)) {
    std::string bytes;
    for (std::size_t index = 0; index < MB_LEN_MAX; ++index) {
      const auto byte = static_cast<std::uint8_t>(load_guest_memory(context, source + index, 1));
      bytes.push_back(static_cast<char>(byte));
      if (byte == 0) break;
    }
    wchar_t character = 0;
    const auto consumed = guest_mbrtowc(&character, bytes.data(), bytes.size(), &state);
    if (consumed == static_cast<std::size_t>(-1) || consumed == static_cast<std::size_t>(-2)) {
      set_guest_last_error(kErrorInvalidParameter);
      set_import_result(context, static_cast<std::uint64_t>(-1));
      return;
    }
    if (consumed == 0) {
      if (destination != 0) store_guest_memory(context, destination + converted_units * 2, 0, 2);
      source = 0;
      break;
    }
    source += consumed;
    if (destination != 0) store_guest_utf16(context, destination + converted_units * 2, character);
    ++converted_units;
  }
  if (destination != 0) {
    store_guest_memory(context, source_pointer, source, guest_pointer_width);
    store_guest_multibyte_state(state_address, state);
  }
  set_import_result(context, converted_units);
}
void msvcrt_wcrtomb(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto wide_character = static_cast<wchar_t>(import_argument(context, 1) & 0xffffu);
  const auto state_address = import_argument(context, 2);
  if (destination == 0) {
    set_import_result(context, 1);
    return;
  }

  auto state = guest_multibyte_state(state_address);

  char bytes[MB_LEN_MAX]{};
  const auto locale = guest_utf8_locale();
  const auto previous_locale = locale != nullptr ? uselocale(locale) : static_cast<locale_t>(0);
  const auto converted = std::wcrtomb(bytes, wide_character, &state);
  if (locale != nullptr) uselocale(previous_locale);
  if (converted == static_cast<std::size_t>(-1)) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  store_guest_multibyte_state(state_address, state);
  for (std::size_t index = 0; index < converted; ++index)
    store_guest_memory(context, destination + index, static_cast<std::uint8_t>(bytes[index]), 1);
  set_import_result(context, converted);
}
void msvcrt_setlocale(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, 0);  // the "C" locale has no name to return
}

// ---- kernel32: console and directory enumeration --------------------------
// A recompiled port has no Windows console, so the console calls succeed without
// drawing anything: a program that sets a cursor position or a text attribute is
// describing output, and the output itself still goes to the host's stdout. Beep
// is silent for the same reason.
void win32_console_success(GuestContext* context) {
  for (int index = 0; index < 4; ++index) (void)import_argument(context, index);
  set_import_result(context, 1);
}

// Adapted from project-igi-browser/host/kernel32.c (MIT): the original
// adapter reports that its headless guest has no console, accepts mode changes,
// and copies console writes to the host diagnostic stream.  Recomp Studio
// writes through its output-capture path instead, so differential verification
// observes the same bytes as WriteFile on a standard handle.
void win32_get_console_mode(GuestContext* context) {
  (void)import_argument(context, 0);
  const auto mode = import_argument(context, 1);
  if (mode != 0) store_guest_memory(context, mode, 0, 4);
  set_import_result(context, 0);  // no Windows console is attached to a native port
}

void win32_set_console_mode(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, 1);
}

bool write_console_bytes(GuestContext* context, std::uint64_t buffer, std::uint64_t length,
                         std::uint64_t written_pointer) {
  if (buffer > guest_memory_size || length > guest_memory_size - buffer) {
    set_guest_last_error(kErrorInvalidParameter);
    if (written_pointer != 0) store_guest_memory(context, written_pointer, 0, 4);
    set_import_result(context, 0);
    return false;
  }
  const auto accepted = write_guest_output(STDOUT_FILENO,
                                           reinterpret_cast<const char*>(guest_memory + buffer),
                                           static_cast<std::size_t>(length));
  const auto written = accepted < 0 ? 0u : static_cast<std::uint64_t>(accepted);
  if (written_pointer != 0) store_guest_memory(context, written_pointer, written, 4);
  set_import_result(context, (accepted < 0 || written != length) ? 0 : 1);
  return accepted >= 0 && written == length;
}

void win32_write_console_a(GuestContext* context) {
  (void)import_argument(context, 0);
  write_console_bytes(context, import_argument(context, 1), import_argument(context, 2),
                      import_argument(context, 3));
}

void win32_write_console_w(GuestContext* context) {
  (void)import_argument(context, 0);
  const auto buffer = import_argument(context, 1);
  const auto units = import_argument(context, 2);
  const auto written_pointer = import_argument(context, 3);
  if (buffer > guest_memory_size || units > (guest_memory_size - buffer) / 2) {
    set_guest_last_error(kErrorInvalidParameter);
    if (written_pointer != 0) store_guest_memory(context, written_pointer, 0, 4);
    set_import_result(context, 0);
    return;
  }
  std::string utf8;
  utf8.reserve(static_cast<std::size_t>(units));
  for (std::uint64_t index = 0; index < units; ++index) {
    std::uint32_t codepoint = static_cast<std::uint32_t>(load_guest_memory(context, buffer + index * 2, 2));
    if (codepoint >= 0xd800u && codepoint <= 0xdbffu && index + 1 < units) {
      const auto low = static_cast<std::uint32_t>(load_guest_memory(context, buffer + (index + 1) * 2, 2));
      if (low >= 0xdc00u && low <= 0xdfffu) {
        codepoint = 0x10000u + ((codepoint - 0xd800u) << 10) + (low - 0xdc00u);
        ++index;
      }
    }
    if (codepoint <= 0x7fu) utf8.push_back(static_cast<char>(codepoint));
    else if (codepoint <= 0x7ffu) {
      utf8.push_back(static_cast<char>(0xc0u | (codepoint >> 6)));
      utf8.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    } else if (codepoint <= 0xffffu) {
      utf8.push_back(static_cast<char>(0xe0u | (codepoint >> 12)));
      utf8.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3fu)));
      utf8.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    } else {
      utf8.push_back(static_cast<char>(0xf0u | (codepoint >> 18)));
      utf8.push_back(static_cast<char>(0x80u | ((codepoint >> 12) & 0x3fu)));
      utf8.push_back(static_cast<char>(0x80u | ((codepoint >> 6) & 0x3fu)));
      utf8.push_back(static_cast<char>(0x80u | (codepoint & 0x3fu)));
    }
  }
  const auto accepted = write_guest_output(STDOUT_FILENO, utf8.data(), utf8.size());
  if (written_pointer != 0) store_guest_memory(context, written_pointer,
                                                accepted < 0 ? 0 : units, 4);
  set_import_result(context, accepted < 0 ? 0 : 1);
}

// Directory enumeration. The guest sees a Win32 find handle and a
// WIN32_FIND_DATAA; the matches are held host-side against that handle.
struct GuestFindState {
  std::vector<std::string> names;
  std::size_t index{};
  std::string directory;
};
std::map<std::uint64_t, GuestFindState> guest_finds;

bool guest_glob_matches(const std::string& pattern, const std::string& name) {
  std::size_t p = 0;
  std::size_t n = 0;
  std::size_t star = std::string::npos;
  std::size_t resume = 0;
  while (n < name.size()) {
    if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == name[n])) {
      ++p;
      ++n;
    } else if (p < pattern.size() && pattern[p] == '*') {
      star = p++;
      resume = n;
    } else if (star != std::string::npos) {
      p = star + 1;
      n = ++resume;
    } else {
      return false;
    }
  }
  while (p < pattern.size() && pattern[p] == '*') ++p;
  return p == pattern.size();
}

// Resolves a guest path through the app-directory policy. Returns false and
// records a Windows error code when the path is refused, so every file-facing
// shim has one failure path and the guest can ask what happened.
bool guest_path_resolve(const std::string& guest_path, std::string& host_path, bool for_creation) {
  const auto resolution = guest_file_sandbox().resolve(guest_path);
  if (resolution.allowed()) {
    host_path = resolution.host_path;
    return true;
  }
  // A path that resolves inside the sandbox but names nothing is a missing file;
  // a path the policy refused is a refusal. Reporting both as ERROR_FILE_NOT_FOUND
  // would send the reader to look for a file that was never allowed to exist.
  set_guest_last_error(resolution.status == GuestPathStatus::OutsideSandbox && !for_creation
                           ? kErrorPathNotFound
                           : kErrorAccessDenied);
  // Named once per distinct path. A guest that probes optional files would
  // otherwise bury its own output in repeats of the same line.
  static std::vector<std::string> reported;
  if (std::find(reported.begin(), reported.end(), guest_path) == reported.end()) {
    reported.push_back(guest_path);
    std::fprintf(stderr, "recomp: %s path '%s' (%s)\n",
                 for_creation ? "refused creating" : "refused", guest_path.c_str(),
                 resolution.reason.c_str());
  }
  return false;
}

std::string guest_path_to_host(std::string path) {
  std::string host_path;
  if (!guest_path_resolve(path, host_path, false)) return {};
  return host_path;
}

void guest_fill_find_data(GuestContext* context, std::uint64_t address, const std::string& name,
                          const std::string& directory, bool is_directory) {
  for (std::uint64_t offset = 0; offset < 320; ++offset) store_guest_memory(context, address + offset, 0, 1);
  store_guest_memory(context, address, is_directory ? 0x10 : 0x80, 4);  // FILE_ATTRIBUTE_*
  std::uint64_t size = 0;
  if (!is_directory) {
    std::error_code error;
    const auto measured = std::filesystem::file_size(std::filesystem::path(directory) / name, error);
    if (!error) size = measured;
  }
  store_guest_memory(context, address + 28, size >> 32, 4);
  store_guest_memory(context, address + 32, size & 0xffffffffu, 4);
  const auto limit = name.size() < 259 ? name.size() : 259;
  for (std::size_t index = 0; index < limit; ++index)
    store_guest_memory(context, address + 44 + index, static_cast<std::uint8_t>(name[index]), 1);
}

void win32_find_first_file_a(GuestContext* context) {
  const auto pattern = read_guest_string(import_argument(context, 0));
  const auto output = import_argument(context, 1);
  std::string host;
  if (!guest_path_resolve(pattern, host, false)) {
    set_import_result(context, 0xffffffffull);  // INVALID_HANDLE_VALUE
    return;
  }
  const auto separator = host.find_last_of('/');
  const auto directory = separator == std::string::npos ? std::string(".") : host.substr(0, separator);
  const auto leaf = separator == std::string::npos ? host : host.substr(separator + 1);

  GuestFindState state;
  state.directory = directory;
  std::error_code error;
  for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
    const auto name = entry.path().filename().string();
    if (guest_glob_matches(leaf.empty() ? "*" : leaf, name)) state.names.push_back(name);
  }
  if (error || state.names.empty()) {
    set_import_result(context, 0xffffffffull);  // INVALID_HANDLE_VALUE
    return;
  }
  std::sort(state.names.begin(), state.names.end());
  guest_fill_find_data(context, output, state.names.front(), directory,
                       std::filesystem::is_directory(std::filesystem::path(directory) / state.names.front()));
  state.index = 1;
  const auto handle = guest_handle_new(kGuestHandleFind);
  guest_finds[handle] = std::move(state);
  set_import_result(context, handle);
}

void win32_find_next_file_a(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  const auto output = import_argument(context, 1);
  const auto found = guest_finds.find(handle);
  if (found == guest_finds.end() || found->second.index >= found->second.names.size()) {
    set_import_result(context, 0);
    return;
  }
  auto& state = found->second;
  const auto& name = state.names[state.index++];
  guest_fill_find_data(context, output, name, state.directory,
                       std::filesystem::is_directory(std::filesystem::path(state.directory) / name));
  set_import_result(context, 1);
}

void win32_find_close(GuestContext* context) {
  guest_finds.erase(import_argument(context, 0));
  set_import_result(context, 1);
}

// ---- kernel32: files ------------------------------------------------------
// A guest file handle is a typed entry in the handle table whose descriptor is a
// host descriptor, opened through the app-directory policy. Everything here
// either produces one of those or consumes one, so a handle from CreateFileA and
// a handle from FindFirstFileA cannot be confused for each other, and neither can
// be a host pointer.

// Maps GENERIC_* / FILE_*_DATA access bits onto the read and write permission the
// handle will carry.
void guest_decode_access(std::uint64_t desired_access, bool& may_read, bool& may_write) {
  may_read = false;
  may_write = false;
  if (desired_access == 0) return;  // access 0 asks for metadata only
  const std::uint64_t generic_read = 0x80000000ull;
  const std::uint64_t generic_write = 0x40000000ull;
  const std::uint64_t generic_execute = 0x20000000ull;
  const std::uint64_t all_access = 0x1F01FFull;
  if (desired_access == all_access) { may_read = may_write = true; return; }
  if ((desired_access & generic_read) != 0 || (desired_access & 0x86ull) != 0) may_read = true;
  if ((desired_access & generic_write) != 0 || (desired_access & 0x190ull) != 0) may_write = true;
  if ((desired_access & generic_execute) != 0) may_read = true;
}

int guest_open_disposition(std::uint32_t disposition, bool for_write) {
  // CREATE_NEW 1, CREATE_ALWAYS 2, OPEN_EXISTING 3, OPEN_ALWAYS 4,
  // TRUNCATE_EXISTING 5.
  switch (disposition) {
    case 1: return O_CREAT | O_EXCL | (for_write ? O_WRONLY : O_RDONLY);
    case 2: return O_CREAT | O_TRUNC | (for_write ? O_WRONLY : O_RDWR);
    case 3: return for_write ? O_RDWR : O_RDONLY;
    case 4: return O_CREAT | (for_write ? O_WRONLY : O_RDONLY);
    case 5: return O_TRUNC | O_WRONLY;
    default: return -1;
  }
}

void win32_create_file(GuestContext* context, bool wide) {
  const auto path_argument = import_argument(context, 0);
  const auto desired_access = import_argument(context, 1);
  const auto disposition = static_cast<std::uint32_t>(import_argument(context, 4));
  const auto path = wide ? read_guest_wide_string(path_argument) : read_guest_string(path_argument);
  bool may_read = false;
  bool may_write = false;
  guest_decode_access(desired_access, may_read, may_write);
  std::string host_path;
  // The policy has to be told whether this call intends to create, because
  // creating inside the app directory is allowed and creating outside it is the
  // case where "we refused" must be louder than "not found".
  if (!guest_path_resolve(path, host_path, disposition == 1 || disposition == 2 || disposition == 4)) {
    set_import_result(context, static_cast<std::uint64_t>(-1));  // INVALID_HANDLE_VALUE
    return;
  }
  const auto flags = guest_open_disposition(disposition, may_write);
  if (flags < 0) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  // A directory is not a file: Windows refuses to open one without the backup
  // semantics flag, and a guest that gets a handle for a directory then tries to
  // read it is confused about something worth failing loudly for.
  std::error_code error;
  const bool is_directory = std::filesystem::is_directory(host_path, error);
  if (is_directory && may_write) {
    set_guest_last_error(kErrorAccessDenied);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  const int host_fd = is_directory ? ::open(host_path.c_str(), O_RDONLY)
                                   : ::open(host_path.c_str(), flags, 0644);
  if (host_fd < 0) {
    const auto code = errno == EEXIST ? kErrorSharingViolation
                    : errno == EACCES || errno == EPERM ? kErrorAccessDenied
                    : errno == ENOENT ? kErrorFileNotFound
                                      : kErrorPathNotFound;
    set_guest_last_error(code);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  const auto handle = guest_file_handle_new(host_fd, is_directory || may_read, may_write, path);
  if (handle == 0) {
    ::close(host_fd);
    set_guest_last_error(kErrorNotEnoughMemory);
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  clear_guest_last_error();
  set_import_result(context, handle);
}

// Moves the file pointer, in the 32-bit and 64-bit forms the two APIs offer.
void win32_set_file_pointer(GuestContext* context, bool extended) {
  const auto handle = import_argument(context, 0);
  const auto raw_distance = import_argument(context, 1);
  const auto origin = static_cast<std::int32_t>(import_argument(context, 2));
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || entry->type != kGuestHandleFile || entry->host_descriptor < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    // SetFilePointer returns 0xFFFFFFFF and reports the real position through the
    // high-word pointer when there is one, which is what the caller checks.
    set_import_result(context, 0xffffffffull);
    return;
  }
  const auto distance = extended
      ? static_cast<std::int64_t>(raw_distance)
      : static_cast<std::int64_t>(static_cast<std::int32_t>(static_cast<std::uint32_t>(raw_distance)));
  int host_origin = SEEK_SET;
  if (origin == 1) host_origin = SEEK_CUR;
  else if (origin == 2) host_origin = SEEK_END;
  const auto position = ::lseek(entry->host_descriptor, static_cast<off_t>(distance), host_origin);
  if (position < 0) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0xffffffffull);
    return;
  }
  if (!extended) {
    const auto high_pointer = import_argument(context, 3);
    if (high_pointer != 0)
      store_guest_memory(context, high_pointer, static_cast<std::uint64_t>(position >> 32), 4);
  }
  clear_guest_last_error();
  set_import_result(context, static_cast<std::uint64_t>(position));
}

void win32_get_file_size(GuestContext* context, bool extended) {
  const auto handle = import_argument(context, 0);
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || (entry->type != kGuestHandleFile && entry->type != kGuestHandleStandard) ||
      entry->host_descriptor < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0xffffffffull);
    return;
  }
  struct stat status{};
  if (::fstat(entry->host_descriptor, &status) != 0) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0xffffffffull);
    return;
  }
  const auto size = static_cast<std::uint64_t>(status.st_size);
  if (!extended) {
    const auto high_pointer = import_argument(context, 1);
    if (high_pointer != 0)
      store_guest_memory(context, high_pointer, size >> 32, 4);
    set_import_result(context, size & 0xffffffffull);
    return;
  }
  set_import_result(context, size);
}

// The name the guest is running under, in the Windows form it expects. Programs
// use this to find the directory they were started from and then read their own
// data files, so a shim that returns 0 here makes every bundled asset unreachable
// and the failure surfaces as a missing texture rather than as a refused call.
//
// Three arguments, the first of which is the module to ask about: NULL means the
// executable the process started from, which is the only module this runtime has.
// Reading the buffer from argument 0 would write the path over whatever the guest
// passed as the module handle and report success.
void win32_get_module_file_name(GuestContext* context, bool wide) {
  const auto module_handle = import_argument(context, 0);
  const auto buffer = import_argument(context, 1);
  const auto maximum = import_argument(context, 2);
  if (module_handle != 0 && module_handle != recompiled_image_base &&
      guest_module_library(module_handle) == nullptr) {
    // A module this runtime does not know has no name to report; Windows writes
    // nothing and returns 0, which is what the caller checks.
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  const auto& root = guest_file_sandbox().root();
  if (root.empty()) {
    set_guest_last_error(kErrorNotSupported);
    set_import_result(context, 0);
    return;
  }
  // The executable's own name comes from the harness when it knows it; the
  // directory alone would make a program that strips the last path component end
  // up one level too high.
  std::string name = "recomp-guest";
  if (const char* configured = std::getenv("RECOMP_APP_NAME"); configured != nullptr && configured[0] != '\0')
    name = configured;
  const auto guest_path = guest_file_sandbox().to_guest_path(root + "/" + name);
  const auto length = guest_path.size();
  if (buffer == 0 || maximum == 0 || !guest_buffer_usable(buffer, length + 1)) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  for (std::size_t index = 0; index < length; ++index) {
    const auto unit = wide ? static_cast<std::uint64_t>(static_cast<std::uint16_t>(guest_path[index]))
                           : static_cast<std::uint64_t>(static_cast<std::uint8_t>(guest_path[index]));
    store_guest_memory(context, buffer + index * (wide ? 2 : 1), unit, wide ? 2 : 1);
  }
  store_guest_memory(context, buffer + length * (wide ? 2 : 1), 0, wide ? 2 : 1);
  clear_guest_last_error();
  set_import_result(context, length);
}

// Deletes and renames, through the same policy as opening.
void win32_delete_file(GuestContext* context, bool wide) {
  const auto argument = import_argument(context, 0);
  const auto path = wide ? read_guest_wide_string(argument) : read_guest_string(argument);
  std::string host_path;
  if (!guest_path_resolve(path, host_path, false)) {
    set_guest_last_error(kErrorFileNotFound);
    set_import_result(context, 0);
    return;
  }
  if (::remove(host_path.c_str()) != 0) {
    set_guest_last_error(errno == EPERM || errno == EACCES ? kErrorAccessDenied : kErrorFileNotFound);
    set_import_result(context, 0);
    return;
  }
  clear_guest_last_error();
  set_import_result(context, 1);
}

void win32_create_directory(GuestContext* context, bool wide) {
  const auto argument = import_argument(context, 0);
  const auto path = wide ? read_guest_wide_string(argument) : read_guest_string(argument);
  std::string host_path;
  if (!guest_path_resolve(path, host_path, true)) {
    set_guest_last_error(kErrorAccessDenied);
    set_import_result(context, 0);
    return;
  }
  if (::mkdir(host_path.c_str(), 0755) != 0) {
    set_guest_last_error(errno == EEXIST ? kErrorSharingViolation : kErrorPathNotFound);
    set_import_result(context, 0);
    return;
  }
  clear_guest_last_error();
  set_import_result(context, 1);
}

void win32_remove_directory(GuestContext* context, bool wide) {
  const auto argument = import_argument(context, 0);
  const auto path = wide ? read_guest_wide_string(argument) : read_guest_string(argument);
  std::string host_path;
  if (!guest_path_resolve(path, host_path, false)) {
    set_import_result(context, 0);
    return;
  }
  // rmdir fails on a non-empty directory, which is the behaviour the caller is
  // checking for when it decides whether to report "in use".
  set_import_result(context, ::rmdir(host_path.c_str()) == 0 ? 1u : 0u);
}

void win32_move_file(GuestContext* context, bool extended) {
  const auto first_argument = import_argument(context, 0);
  const auto second_argument = import_argument(context, 1);
  const auto first = read_guest_string(first_argument);
  // MoveFileExA puts its flags in the third argument; MoveFileW takes no flags,
  // and reading one that is not there would invent a behaviour.
  const auto flags = extended ? static_cast<std::uint32_t>(import_argument(context, 2)) : 0u;
  std::string host_first;
  std::string host_second;
  if (!guest_path_resolve(first, host_first, false)) { set_import_result(context, 0); return; }
  // MOVEFILE_COPY_ALLOWED is 2, MOVEFILE_REPLACE_EXISTING is 1, DELAY_UNTIL_REBOOT
  // is 4 -- and a recompiler has no reboot to defer to, so a request that depends
  // on it cannot be honoured and has to say so rather than do nothing.
  if ((flags & 4u) != 0) {
    set_guest_last_error(kErrorNotSupported);
    set_import_result(context, 0);
    return;
  }
  if (!guest_path_resolve(second_argument == 0 ? std::string() : read_guest_string(second_argument),
                         host_second, true)) {
    set_import_result(context, 0);
    return;
  }
  if (::rename(host_first.c_str(), host_second.c_str()) != 0) {
    // EEXIST on a rename onto an existing file is exactly the case
    // REPLACE_EXISTING was passed for; unlink and try again before giving up.
    if (errno == EEXIST && (flags & 1u) != 0 && ::unlink(host_second.c_str()) == 0 &&
        ::rename(host_first.c_str(), host_second.c_str()) == 0) {
      clear_guest_last_error();
      set_import_result(context, 1);
      return;
    }
    set_guest_last_error(errno == ENOENT ? kErrorFileNotFound : kErrorAccessDenied);
    set_import_result(context, 0);
    return;
  }
  clear_guest_last_error();
  set_import_result(context, 1);
}

void win32_get_file_attributes(GuestContext* context, bool wide) {
  const auto argument = import_argument(context, 0);
  const auto path = wide ? read_guest_wide_string(argument) : read_guest_string(argument);
  std::string host_path;
  if (!guest_path_resolve(path, host_path, false)) {
    set_import_result(context, 0xffffffffull);  // INVALID_FILE_ATTRIBUTES
    return;
  }
  std::error_code error;
  if (!std::filesystem::exists(host_path, error)) {
    set_guest_last_error(kErrorFileNotFound);
    set_import_result(context, 0xffffffffull);
    return;
  }
  // FILE_ATTRIBUTE_DIRECTORY 0x10, FILE_ATTRIBUTE_READONLY 0x1, and 0x80 for a
  // plain file.
  std::uint64_t attributes = 0x80;
  if (std::filesystem::is_directory(host_path, error)) attributes = 0x10;
  else if ((std::filesystem::status(host_path, error).permissions() & std::filesystem::perms::owner_write) ==
           std::filesystem::perms::none)
    attributes = 0x1;
  clear_guest_last_error();
  set_import_result(context, attributes);
}

void win32_set_end_of_file(GuestContext* context) {
  auto* entry = guest_handle_lookup(import_argument(context, 0));
  if (entry == nullptr || entry->type != kGuestHandleFile || entry->host_descriptor < 0) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  const auto position = ::lseek(entry->host_descriptor, 0, SEEK_CUR);
  set_import_result(context, ::ftruncate(entry->host_descriptor, static_cast<off_t>(position)) == 0 ? 1u : 0u);
}

// The file's own bytes, not the program's output. Flushing the host stream here
// would be wrong in a different way for every file the guest has open.
void win32_flush_file_buffers(GuestContext* context) {
  auto* entry = guest_handle_lookup(import_argument(context, 0));
  if (entry == nullptr || entry->type != kGuestHandleFile || entry->host_descriptor < 0) {
    // A standard stream has no buffers of the guest's to push out.
    set_import_result(context, entry != nullptr ? 1 : 0);
    if (entry == nullptr) set_guest_last_error(kErrorInvalidHandle);
    return;
  }
  set_import_result(context, ::fsync(entry->host_descriptor) == 0 ? 1u : 0u);
}

// Bytes of free space on the drive the app directory lives on. The guest asks when
// it is about to write something large; answering 0 makes it refuse to write, and
// answering a made-up number lets it fill a real disk.
void win32_get_disk_free_space(GuestContext* context) {
  const auto root_argument = import_argument(context, 0);
  const auto free_bytes_for_caller = import_argument(context, 1);
  const auto total_bytes_for_caller = import_argument(context, 2);
  const auto total_free_for_caller = import_argument(context, 3);
  const auto path = root_argument == 0 ? guest_file_sandbox().root() : read_guest_string(root_argument);
  std::string host_path;
  // A drive letter alone ("C:\") is a legal argument and resolves to the sandbox.
  if (!guest_path_resolve(path.empty() ? "." : path, host_path, false)) host_path = guest_file_sandbox().root();
  std::error_code error;
  const auto space = std::filesystem::space(host_path.empty() ? "." : host_path, error);
  if (error) { set_import_result(context, 0); return; }
  if (free_bytes_for_caller != 0) store_guest_memory(context, free_bytes_for_caller, space.available, 8);
  if (total_bytes_for_caller != 0) store_guest_memory(context, total_bytes_for_caller, space.capacity, 8);
  if (total_free_for_caller != 0) store_guest_memory(context, total_free_for_caller, space.free, 8);
  set_import_result(context, 1);
}

// The A/W and 32/64-bit spellings, as separate entries because the shim table keys
// on the name the guest actually imports. Each is named after the entry it serves
// -- `shim_` prefix, implementation without -- so a wrapper can never quietly call
// itself instead of the function it wraps.
void shim_CreateFileA(GuestContext* c) { win32_create_file(c, false); }
void shim_CreateFileW(GuestContext* c) { win32_create_file(c, true); }
void shim_SetFilePointer(GuestContext* c) { win32_set_file_pointer(c, false); }
void shim_SetFilePointerEx(GuestContext* c) { win32_set_file_pointer(c, true); }
void shim_GetFileSize(GuestContext* c) { win32_get_file_size(c, false); }
void shim_GetFileSizeEx(GuestContext* c) { win32_get_file_size(c, true); }
void shim_DeleteFileA(GuestContext* c) { win32_delete_file(c, false); }
void shim_DeleteFileW(GuestContext* c) { win32_delete_file(c, true); }
void shim_CreateDirectoryA(GuestContext* c) { win32_create_directory(c, false); }
void shim_CreateDirectoryW(GuestContext* c) { win32_create_directory(c, true); }
void shim_RemoveDirectoryA(GuestContext* c) { win32_remove_directory(c, false); }
void shim_RemoveDirectoryW(GuestContext* c) { win32_remove_directory(c, true); }
void shim_MoveFileA(GuestContext* c) { win32_move_file(c, false); }
void shim_MoveFileW(GuestContext* c) { win32_move_file(c, false); }
void shim_MoveFileExA(GuestContext* c) { win32_move_file(c, true); }
void shim_MoveFileExW(GuestContext* c) { win32_move_file(c, true); }
void shim_GetFileAttributesA(GuestContext* c) { win32_get_file_attributes(c, false); }
void shim_GetFileAttributesW(GuestContext* c) { win32_get_file_attributes(c, true); }
void shim_GetModuleFileNameA(GuestContext* c) { win32_get_module_file_name(c, false); }
void shim_GetModuleFileNameW(GuestContext* c) { win32_get_module_file_name(c, true); }

void shim_fopen(GuestContext* c) { msvcrt_fopen(c, false); }
void shim__wfopen(GuestContext* c) { msvcrt_fopen(c, true); }
void shim__fsopen(GuestContext* c) { msvcrt_fopen(c, false); }
void shim_fread(GuestContext* c) { msvcrt_fread(c); }
void shim_fseek(GuestContext* c) { msvcrt_fseek(c, false); }
void shim__fseeki64(GuestContext* c) { msvcrt_fseek(c, true); }
void shim_fgetc(GuestContext* c) { msvcrt_fgetc(c, false); }
void shim_getc(GuestContext* c) { msvcrt_fgetc(c, false); }
void shim_fputc(GuestContext* c) { msvcrt_fgetc(c, true); }
void shim_putc(GuestContext* c) { msvcrt_fgetc(c, true); }
void shim__open(GuestContext* c) { msvcrt_open(c, false); }
void shim__wopen(GuestContext* c) { msvcrt_open(c, true); }
void shim__read(GuestContext* c) { msvcrt_read_or_write(c, false); }
void shim__write(GuestContext* c) { msvcrt_read_or_write(c, true); }
void shim_remove(GuestContext* c) { msvcrt_remove_or_rename(c, false); }
void shim_rename(GuestContext* c) { msvcrt_remove_or_rename(c, true); }
void shim__fdopen(GuestContext* c) { msvcrt_fdopen(c, false); }
void shim__wfdopen(GuestContext* c) { msvcrt_fdopen(c, true); }
// _set_fmode sets the whole-process text/binary default. The runtime treats every
// stream as binary, so recording the request and succeeding is the honest answer:
// there is no translation here for the mode to switch on.
void shim__set_fmode(GuestContext* context) {
  (void)import_argument(context, 0);
  clear_guest_last_error();
  set_import_result(context, 0);
}

// ---- msvcrt: the remaining CRT entry points -------------------------------
void msvcrt_system(GuestContext* context) {
  const auto command = read_guest_string(import_argument(context, 0));
  if (command.empty()) { set_import_result(context, 1); return; }
  set_import_result(context, static_cast<std::uint64_t>(std::system(command.c_str())));
}
void msvcrt_time(GuestContext* context) {
  const auto target = import_argument(context, 0);
  const auto now = static_cast<std::int64_t>(guest_fixed_time());
  if (target != 0) store_guest_memory(context, target, static_cast<std::uint64_t>(now), 4);
  set_import_result(context, static_cast<std::uint64_t>(now));
}
void msvcrt_time64(GuestContext* context) {
  const auto target = import_argument(context, 0);
  const auto now = static_cast<std::uint64_t>(static_cast<std::int64_t>(guest_fixed_time()));
  if (target != 0) store_guest_memory(context, target, now, 8);
  set_import_result(context, now);
  if (guest_pointer_width == 4) context->registers[2] = now >> 32;  // EDX:EAX
}
void msvcrt_signal(GuestContext* context) {
  // No signal handlers are installed: the guest gets SIG_ERR (the all-ones
  // handle) rather than a success that would imply one was registered.
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, static_cast<std::uint64_t>(-1));
}
void msvcrt_strcoll(GuestContext* context) {
  const auto left = read_guest_string(import_argument(context, 0));
  const auto right = read_guest_string(import_argument(context, 1));
  const auto order = left.compare(right);
  set_import_result(context, order < 0 ? static_cast<std::uint64_t>(-1)
                                       : order > 0 ? std::uint64_t{1} : std::uint64_t{0});
}
void msvcrt_fullpath(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source = guest_path_to_host(read_guest_string(import_argument(context, 1)));
  std::error_code error;
  const auto absolute = std::filesystem::absolute(source, error);
  const auto text = error ? source : absolute.lexically_normal().string();
  if (destination != 0) {
    for (std::size_t index = 0; index <= text.size(); ++index)
      store_guest_memory(context, destination + index,
                         index < text.size() ? static_cast<std::uint8_t>(text[index]) : 0, 1);
    set_import_result(context, destination);
  } else {
    set_import_result(context, 0);  // a null destination asks for the buffer size
  }
}
void msvcrt_wcstombs(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  const auto maximum = import_argument(context, 2);
  std::string text;
  for (std::uint64_t index = 0;; ++index) {
    const auto character = load_guest_memory(context, source + index * 2, 2);
    if (character == 0) break;
    text.push_back(character < 0x80 ? static_cast<char>(character) : '?');
  }
  if (destination == 0) { set_import_result(context, text.size()); return; }
  const auto limit = maximum == 0 || maximum > text.size() ? text.size() : maximum;
  for (std::size_t index = 0; index < limit; ++index)
    store_guest_memory(context, destination + index, static_cast<std::uint8_t>(text[index]), 1);
  set_import_result(context, limit);
}

// vfprintf. The guest's va_list is a pointer into its own stack, so the
// arguments are read from guest memory. Only the conversions a console program
// uses are implemented; anything else fails loudly rather than printing
// something wrong.
// The formatting itself, shared by msvcrt's vfprintf and the UCRT's
// __stdio_common_vfprintf, which differ only in where their arguments sit.
// Defined below, next to the formatter it calls.
std::uint64_t msvcrt_format_into_stream(GuestContext* context, std::uint64_t stream,
                                        const std::string& format, std::uint64_t arguments);

void msvcrt_vfprintf(GuestContext* context) {
  const auto stream = import_argument(context, 0);
  const auto format = read_guest_string(import_argument(context, 1));
  const auto arguments = import_argument(context, 2);
  set_import_result(context, msvcrt_format_into_stream(context, stream, format, arguments));
}

// Formats one conversion by handing the HARD PART to the host C library.
//
// The version this replaces parsed width, precision and flags and then discarded them,
// read every argument as four bytes regardless of the guest's pointer width, and had no
// floating-point conversions at all -- so `%-10d` lost its padding, `%s` on a 64-bit
// guest read half a pointer, and any `%f` terminated the program. The host already has
// a complete, correct implementation of printf's formatting, so the work here is only
// the part the host cannot know: reading the guest's argument list.
//
// One conversion is rebuilt into a host format string and passed to `snprintf` with the
// argument read at the width the guest's own length modifier asks for. What is left to
// this function is the ABI, and what is left to the host is everything that is easy to
// get wrong.
using GuestArgumentReader = std::function<std::uint64_t(int)>;

std::string msvcrt_format_arguments_with_reader(GuestContext* context, const std::string& format,
                                                const GuestArgumentReader& next) {
  std::string output;
  const int pointer_width = static_cast<int>(guest_pointer_width);

  for (std::size_t index = 0; index < format.size(); ++index) {
    if (format[index] != '%') { output.push_back(format[index]); continue; }
    if (index + 1 >= format.size()) break;
    const auto conversion_start = index;
    ++index;
    if (format[index] == '%') { output.push_back('%'); continue; }

    // Collect the whole conversion so it can be handed to the host unchanged: flags,
    // width, precision and length modifier are all part of what `snprintf` understands.
    std::size_t cursor = index;
    while (cursor < format.size() && std::strchr("-+ #0", format[cursor]) != nullptr) ++cursor;
    while (cursor < format.size() && format[cursor] >= '0' && format[cursor] <= '9') ++cursor;
    if (cursor < format.size() && format[cursor] == '.') {
      ++cursor;
      while (cursor < format.size() && format[cursor] >= '0' && format[cursor] <= '9') ++cursor;
    }
    std::size_t length_begin = cursor;
    while (cursor < format.size() && std::strchr("hljztL", format[cursor]) != nullptr) ++cursor;
    const auto length = format.substr(length_begin, cursor - length_begin);
    if (cursor >= format.size()) break;
    const char specifier = format[cursor];
    index = cursor;

    // The conversion as the guest wrote it, minus the leading `%`, for the host.
    std::string host_format = "%" + format.substr(conversion_start + 1, cursor - conversion_start);
    char buffer[512];
    int written = 0;
    switch (specifier) {
      case 'c':
        written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(),
                                static_cast<int>(next(4) & 0xffu));
        break;
      case 'd':
      case 'i':
        if (length.find("ll") != std::string::npos || length.find('j') != std::string::npos)
          written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(),
                                  static_cast<long long>(next(8)));
        else if (length.find('l') != std::string::npos)
          written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(),
                                  static_cast<long>(next(8)));
        else
          written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(),
                                  static_cast<int>(next(4) & 0xffffffffu));
        break;
      case 'u':
      case 'x':
      case 'X':
      case 'o':
        if (length.find("ll") != std::string::npos || length.find('j') != std::string::npos)
          written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(),
                                  static_cast<unsigned long long>(next(8)));
        else if (length.find('l') != std::string::npos)
          written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(),
                                  static_cast<unsigned long>(next(8)));
        else
          written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(),
                                  static_cast<unsigned int>(next(4) & 0xffffffffu));
        break;
      case 'f':
      case 'F':
      case 'e':
      case 'E':
      case 'g':
      case 'G': {
        // A float argument arrives in the guest's list as an 8-byte double: the Windows
        // ABI promotes it exactly as the C rules require.
        const auto bits = next(8);
        double value;
        std::memcpy(&value, &bits, sizeof(value));
        written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(), value);
        break;
      }
      case 's': {
        const auto address = next(pointer_width);
        const auto text = address == 0 ? std::string("(null)") : read_guest_string(address);
        written = std::snprintf(buffer, sizeof(buffer), host_format.c_str(), text.c_str());
        break;
      }
      case 'p': {
        // The guest prints its own pointer value, so it is formatted as an integer of
        // the guest's width rather than as a host pointer, which would be a different
        // number entirely.
        const auto value = next(pointer_width);
        if (pointer_width >= 8)
          written = std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
        else
          written = std::snprintf(buffer, sizeof(buffer), "0x%x", static_cast<unsigned int>(value));
        break;
      }
      default:
        terminate_with_message("vfprintf: unsupported conversion '%%%c' (ip=0x%" PRIx64 ")", specifier,
                               context->instruction_pointer);
    }
    if (written < 0) continue;
    output.append(buffer, std::min<std::size_t>(static_cast<std::size_t>(written), sizeof(buffer) - 1));
  }
  return output;
}

// A v* CRT entry receives a guest va_list pointer. The list advances by one guest
// pointer-width slots for each argument, with 64-bit PE32 values occupying two.
std::string msvcrt_format_arguments(GuestContext* context, const std::string& format,
                                    std::uint64_t arguments) {
  const int pointer_width = static_cast<int>(guest_pointer_width);
  return msvcrt_format_arguments_with_reader(
      context, format, [context, arguments, pointer_width](int slot) mutable {
        const auto value = load_guest_memory(context, arguments, slot);
        arguments += static_cast<std::uint64_t>(pointer_width >= 8 || slot <= 4 ? pointer_width : 8);
        return value;
      });
}

// The non-v* CRT entry points carry variadic values inline after their fixed
// arguments. Reading the first variadic value as a va_list pointer corrupts the
// guest ABI (for example, printf("%d", 7) would dereference address 7), so these
// calls walk the actual register/stack argument positions exposed by import_argument.
std::string msvcrt_format_inline_arguments(GuestContext* context, const std::string& format,
                                           int first_argument) {
  int index = first_argument;
  return msvcrt_format_arguments_with_reader(context, format, [context, &index](int slot) {
    const auto value = import_argument(context, index);
    index += guest_pointer_width >= 8 || slot <= 4 ? 1 : 2;
    return value;
  });
}

std::uint64_t msvcrt_format_into_stream(GuestContext* context, std::uint64_t stream,
                                        const std::string& format, std::uint64_t arguments) {
  const auto descriptor = static_cast<int>(cxx_stream_descriptor(context, stream, true));
  const auto output = msvcrt_format_arguments(context, format, arguments);
  const auto accepted = write_guest_output(descriptor, output.data(), output.size());
  return accepted < 0 ? 0 : output.size();
}



// The rest of the CRT tail the corpus asks for. Each is small; together they are the
// only batch in the triage that actually CLOSES applications rather than merely reducing a
// missing-symbol count.

void msvcrt_memchr(GuestContext* context) {
  const auto address = import_argument(context, 0);
  const auto wanted = static_cast<std::uint8_t>(import_argument(context, 1) & 0xffu);
  const auto length = import_argument(context, 2);
  for (std::uint64_t offset = 0; offset < length; ++offset) {
    if (static_cast<std::uint8_t>(load_guest_memory(context, address + offset, 1)) == wanted) {
      set_import_result(context, address + offset);
      return;
    }
  }
  set_import_result(context, 0);
}

// The character classifiers. They take an int and return non-zero or zero; the host's C
// locale is the C locale, which is what the guest's default is too.
#define RECOMP_CLASSIFIER(NAME, FUNCTION)                                                     \
  void msvcrt_##NAME(GuestContext* context) {                                                 \
    set_import_result(context, FUNCTION(static_cast<int>(import_argument(context, 0) & 0xffu)) != 0); \
  }
RECOMP_CLASSIFIER(isalpha, std::isalpha)
RECOMP_CLASSIFIER(isdigit, std::isdigit)
RECOMP_CLASSIFIER(isalnum, std::isalnum)
RECOMP_CLASSIFIER(isupper, std::isupper)
RECOMP_CLASSIFIER(islower, std::islower)
RECOMP_CLASSIFIER(ispunct, std::ispunct)
RECOMP_CLASSIFIER(isxdigit, std::isxdigit)
RECOMP_CLASSIFIER(iscntrl, std::iscntrl)
#undef RECOMP_CLASSIFIER

// The single-precision math functions, returned as a float's bit pattern in the low half
// of the result register -- which is where the guest reads XMM0 from.
void msvcrt_math_float(GuestContext* context, float (*operation)(float)) {
  const auto argument = load_guest_float(context, context->registers[4] + 4);
  const auto result = operation(argument);
  std::uint32_t bits = 0;
  std::memcpy(&bits, &result, sizeof(bits));
  set_import_result(context, bits);
}
void msvcrt_sqrtf(GuestContext* context) { msvcrt_math_float(context, std::sqrt); }
void msvcrt_roundf(GuestContext* context) { msvcrt_math_float(context, std::round); }
void msvcrt_floorf(GuestContext* context) { msvcrt_math_float(context, std::floor); }
void msvcrt_ceilf(GuestContext* context) { msvcrt_math_float(context, std::ceil); }
void msvcrt_fabsf(GuestContext* context) { msvcrt_math_float(context, std::fabs); }
void msvcrt_sinf(GuestContext* context) { msvcrt_math_float(context, std::sin); }
void msvcrt_cosf(GuestContext* context) { msvcrt_math_float(context, std::cos); }

// The two-argument double functions. The second argument follows the first in the guest's
// argument list, which for a shim means reading it the same way.
void msvcrt_math_double2(GuestContext* context, double (*operation)(double, double)) {
  const auto first = load_guest_double(context, context->registers[4] + 4);
  const auto second = load_guest_double(context, context->registers[4] + 12);
  const auto result = operation(first, second);
  std::uint64_t bits = 0;
  std::memcpy(&bits, &result, sizeof(bits));
  set_import_result(context, bits);
}
void msvcrt_pow(GuestContext* context) { msvcrt_math_double2(context, std::pow); }
void msvcrt_atan2(GuestContext* context) { msvcrt_math_double2(context, std::atan2); }
void msvcrt_fmod(GuestContext* context) { msvcrt_math_double2(context, std::fmod); }

// qsort calls a GUEST comparator, so it is a callback rather than a library call. The
// sort itself is the host's, with a comparator that marshals the two elements into guest
// memory and calls the guest's function -- which is the only way a host sort can compare
// guest data with the guest's own ordering.
// A scratch buffer the comparator reads its two elements from. Allocated once and grown
// as needed; the sort is the host's, so the guest's own buffers cannot be used.
std::uint64_t guest_sort_scratch = 0;

GuestContext* guest_sort_context = nullptr;
std::uint64_t guest_sort_comparator = 0;
std::uint64_t guest_sort_element_bytes = 0;

int guest_sort_compare(const void* left, const void* right) {
  auto* context = guest_sort_context;
  if (context == nullptr || guest_sort_comparator == 0) return 0;
  const auto function = lookup_guest_function(guest_sort_comparator);
  if (function == nullptr) {
    std::fprintf(stderr, "recomp: the qsort comparator at 0x%llx was not recompiled, so it did not run\n",
                 static_cast<unsigned long long>(guest_sort_comparator));
    return 0;
  }
  const auto stack_pointer = context->registers[4];
  const auto left_address = guest_sort_scratch;
  const auto right_address = guest_sort_scratch + guest_sort_element_bytes;
  std::memcpy(guest_memory + left_address, left, static_cast<std::size_t>(guest_sort_element_bytes));
  std::memcpy(guest_memory + right_address, right, static_cast<std::size_t>(guest_sort_element_bytes));
  push_guest_stack(context, right_address);
  push_guest_stack(context, left_address);
  push_guest_stack(context, 0);
  function(context);
  const auto result = static_cast<std::int32_t>(context->registers[0]);
  context->registers[4] = stack_pointer;
  return result;
}

void msvcrt_qsort(GuestContext* context) {
  const auto base = import_argument(context, 0);
  const auto count = import_argument(context, 1);
  const auto element_bytes = import_argument(context, 2);
  const auto comparator = import_argument(context, 3);
  if (count < 2 || element_bytes == 0 || comparator == 0) return;
  // The comparator needs somewhere to read the two elements from, and the guest's own
  // buffers cannot be used because the sort is the host's.
  if (guest_sort_scratch == 0 || guest_sort_element_bytes < element_bytes) {
    guest_sort_scratch = heap_allocate(element_bytes * 2 + 16);
    guest_sort_element_bytes = element_bytes;
  }
  if (guest_sort_scratch == 0) return;
  guest_sort_context = context;
  guest_sort_comparator = comparator;
  std::qsort(guest_memory + base, static_cast<std::size_t>(count), static_cast<std::size_t>(element_bytes),
             guest_sort_compare);
  guest_sort_context = nullptr;
  guest_sort_comparator = 0;
}

// The onexit table. `_initialize_onexit_table` prepares it, `_register_onexit_function`
// adds to it, and `_c_exit` runs what was registered -- the same handlers `atexit`
// collects, which this runtime already runs at exit.
void msvcrt_initialize_onexit_table(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_register_onexit_function(GuestContext* context) {
  const auto table = import_argument(context, 0);
  const auto function = import_argument(context, 1);
  (void)table;
  if (function != 0) guest_atexit_handlers.push_back(function);
  set_import_result(context, 0);
}
void msvcrt_c_exit(GuestContext* context) {
  run_guest_atexit_handlers(context);
  set_import_result(context, 0);
}
void msvcrt_terminate(GuestContext* context) {
  // `terminate` is called when no exception handler claims a throw. Reaching it is a real
  // event and the program cannot continue, so it stops and says so.
  terminate_with_message("std::terminate was called (ip=0x%" PRIx64 ")", context->instruction_pointer);
}
void msvcrt_wassert(GuestContext* context) {
  terminate_with_message("assertion failed: %s (%s:%u)", read_guest_string(import_argument(context, 0)).c_str(),
                         read_guest_string(import_argument(context, 1)).c_str(),
                         static_cast<unsigned>(import_argument(context, 2) & 0xffffffffu));
}
void msvcrt_register_thread_local_exe_atexit_callback(GuestContext* context) {
  // The UCRT's thread-local exit callback. There is one thread here, so it is registered
  // in the same list the process exit path drains -- which is what makes it run at all
  // rather than being accepted and forgotten.
  const auto callback = import_argument(context, 0);
  if (callback != 0) guest_atexit_handlers.push_back(callback);
  set_import_result(context, 0);
}

void msvcrt_isprint(GuestContext* context) {
  set_import_result(context, std::isprint(static_cast<int>(import_argument(context, 0) & 0xffu)) != 0);
}

void msvcrt_seh_filter_exe(GuestContext* context) {
  // The C runtime's top-level exception filter. Its return value says whether the
  // exception was handled; reporting "continue searching" is what lets the guest's own
  // handler, if any, see it.
  (void)context;
  set_import_result(context, 1);
}

// The Win32 WINDOW AND MESSAGE surface.
//
// A console program needs none of this; a GUI program needs all of it before it can do
// anything at all, which is why a GUI application stops at its first `GetForegroundWindow`
// rather than somewhere informative. What is here is a GENERAL single-window model -- a
// registered class, a window, a message queue and WndProc re-entry -- with no application's
// geometry or behaviour in it. The structure follows the approach used by the MIT
// `project-igi-browser` host layer, re-expressed for this runtime's ABI: arguments come
// through `import_argument`, and the stack is popped centrally, so these do NOT pop.
//
// There is no real window and no real input. Saying so plainly matters: a program that
// creates a window here gets a handle and a message loop that runs, and NOT a visible
// window, and the diagnostics must not let that be mistaken for GUI support.

struct GuestWindowState {
  std::uint64_t window{};
  std::uint64_t instance{};
  std::uint64_t wndproc{};
  std::uint64_t class_name{};
  int width{640};
  int height{480};
  bool created{};
  std::uint64_t dc{};
};

GuestWindowState guest_window;

// A ring of queued messages. `PeekMessage` returns them one at a time and
// `DispatchMessage` hands them to the guest's WndProc.
struct GuestMessage {
  std::uint64_t window{};
  std::uint32_t message{};
  std::uint64_t wparam{};
  std::uint64_t lparam{};
};
constexpr std::size_t kMessageQueueSize = 256;
GuestMessage guest_message_queue[kMessageQueueSize];
std::size_t guest_message_head = 0;
std::size_t guest_message_tail = 0;

void post_guest_message(std::uint64_t window, std::uint32_t message, std::uint64_t wparam,
                        std::uint64_t lparam) {
  const auto next = (guest_message_tail + 1) % kMessageQueueSize;
  if (next == guest_message_head) return;  // full: dropping is better than overwriting
  guest_message_queue[guest_message_tail] = {window, message, wparam, lparam};
  guest_message_tail = next;
}

bool take_guest_message(GuestMessage* out) {
  if (guest_message_head == guest_message_tail) return false;
  *out = guest_message_queue[guest_message_head];
  guest_message_head = (guest_message_head + 1) % kMessageQueueSize;
  return true;
}

// A WndProc is a GUEST function, so it is called through the same dispatch the guest uses.
// The return sentinel is what stops the call when the guest executes `ret`.
void call_guest_window_proc(GuestContext* context, std::uint64_t window, std::uint32_t message,
                            std::uint64_t wparam, std::uint64_t lparam) {
  if (guest_window.wndproc == 0) return;
  const auto function = lookup_guest_function(guest_window.wndproc);
  if (function == nullptr) {
    // Named rather than skipped: a window procedure that did not run is a behaviour
    // difference the guest cannot observe any other way.
    std::fprintf(stderr, "recomp: the window procedure at 0x%llx was not recompiled, so it did not run\n",
                 static_cast<unsigned long long>(guest_window.wndproc));
    return;
  }
  // The same shape the atexit runner uses: arguments pushed right to left, then a return
  // address of zero for the callee's `ret` to pop. The generated code RETURNS from the
  // call rather than jumping, so this needs no sentinel address to exist.
  const std::uint64_t arguments[4] = {window, message, wparam, lparam};
  const auto stack_pointer = context->registers[4];
  for (int index = 3; index >= 0; --index)
    push_guest_stack(context, arguments[index]);
  push_guest_stack(context, 0);
  function(context);
  context->registers[4] = stack_pointer;
}

void msvcrt_register_class_a(GuestContext* context) {
  // The class structure's second field is the WndProc on 32-bit and the third on 64-bit,
  // because the first field is a style DWORD followed by padding. Reading the wrong slot
  // would register a callback that is not a function.
  const auto structure = import_argument(context, 0);
  guest_window.wndproc = load_guest_memory(context, structure + (guest_pointer_width >= 8 ? 8 : 4),
                                           guest_pointer_width);
  set_import_result(context, 1);
}

void msvcrt_create_window_ex_a(GuestContext* context) {
  (void)import_argument(context, 0);  // extended style
  guest_window.class_name = import_argument(context, 1);
  guest_window.width = static_cast<int>(import_argument(context, 6) & 0xffffu);
  guest_window.height = static_cast<int>(import_argument(context, 7) & 0xffffu);
  guest_window.instance = import_argument(context, 10);
  // A fixed handle rather than an allocation: the guest only compares it and passes it
  // back, and a value that is stable across a run is easier to read in a diagnosis.
  guest_window.window = 0x00010001ull;
  guest_window.created = true;
  set_import_result(context, guest_window.window);
}

void msvcrt_destroy_window(GuestContext* context) {
  guest_window.created = false;
  set_import_result(context, 1);
}
void msvcrt_unregister_class_a(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_show_window(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_update_window(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_invalidate_rect(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_set_focus(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_set_window_pos(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_set_window_text_a(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_set_foreground_window(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_show_cursor(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_adjust_window_rect(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_client_to_screen(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_set_window_long_a(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_get_window_long_a(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_post_quit_message(GuestContext* context) {
  // WM_QUIT is what ends the message loop. Queueing it is what makes `GetMessage` return
  // zero and the program reach its own shutdown instead of looping forever.
  post_guest_message(0, 0x0012u, import_argument(context, 0), 0);
  (void)context;
}
void msvcrt_get_foreground_window(GuestContext* context) {
  set_import_result(context, guest_window.created ? guest_window.window : 0);
}
void msvcrt_get_dc(GuestContext* context) {
  guest_window.dc = 0x00020001ull;
  set_import_result(context, guest_window.dc);
}
void msvcrt_release_dc(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_load_icon_a(GuestContext* context) { set_import_result(context, 0x00030001ull); }
void msvcrt_load_cursor_a(GuestContext* context) { set_import_result(context, 0x00030002ull); }
void msvcrt_get_system_metrics(GuestContext* context) {
  // The real screen size, so a program that sizes itself to the display gets a sensible
  // answer rather than the fixed 640x480 a game happened to use.
  const auto metric = import_argument(context, 0);
  int value = 0;
  switch (metric) {
    case 0: value = guest_window.width; break;    // SM_CXSCREEN
    case 1: value = guest_window.height; break;   // SM_CYSCREEN
    default: value = 0; break;
  }
  set_import_result(context, static_cast<std::uint64_t>(value));
}
void msvcrt_get_client_rect(GuestContext* context) {
  const auto rectangle = import_argument(context, 1);
  store_guest_memory(context, rectangle + 0, 0, 4);
  store_guest_memory(context, rectangle + 4, 0, 4);
  store_guest_memory(context, rectangle + 8, static_cast<std::uint64_t>(guest_window.width), 4);
  store_guest_memory(context, rectangle + 12, static_cast<std::uint64_t>(guest_window.height), 4);
  set_import_result(context, 1);
}
void msvcrt_def_window_proc_a(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_post_message_a(GuestContext* context) {
  post_guest_message(import_argument(context, 0), static_cast<std::uint32_t>(import_argument(context, 1)),
                     import_argument(context, 2), import_argument(context, 3));
  set_import_result(context, 1);
}

// The message loop. `GetMessage` blocks until a message exists; with no real input there
// is nothing to block on, so when the queue is empty this reports WM_QUIT and lets the
// program leave its loop rather than spin. Saying that in the diagnosis matters: a
// program that exits here did so because this runtime has no input, not because the
// translation is wrong.
void msvcrt_get_message_a(GuestContext* context) {
  const auto message = import_argument(context, 0);
  GuestMessage queued;
  if (!take_guest_message(&queued)) {
    store_guest_memory(context, message + 0, 0, guest_pointer_width);
    store_guest_memory(context, message + 4 * guest_pointer_width, 0x0012u, 4);  // WM_QUIT
    set_import_result(context, 0);
    return;
  }
  store_guest_memory(context, message + 0, queued.window, guest_pointer_width);
  store_guest_memory(context, message + 4 * guest_pointer_width, queued.message, 4);
  store_guest_memory(context, message + 4 * guest_pointer_width + 4, queued.wparam, guest_pointer_width);
  store_guest_memory(context, message + 4 * guest_pointer_width + 4 + guest_pointer_width,
                     queued.lparam, guest_pointer_width);
  set_import_result(context, 1);
}

void msvcrt_peek_message_a(GuestContext* context) {
  const auto message = import_argument(context, 0);
  GuestMessage queued;
  if (!take_guest_message(&queued)) {
    set_import_result(context, 0);
    return;
  }
  store_guest_memory(context, message + 0, queued.window, guest_pointer_width);
  store_guest_memory(context, message + 4 * guest_pointer_width, queued.message, 4);
  store_guest_memory(context, message + 4 * guest_pointer_width + 4, queued.wparam, guest_pointer_width);
  store_guest_memory(context, message + 4 * guest_pointer_width + 4 + guest_pointer_width,
                     queued.lparam, guest_pointer_width);
  set_import_result(context, 1);
}

void msvcrt_dispatch_message_a(GuestContext* context) {
  const auto message = import_argument(context, 0);
  const auto window = load_guest_memory(context, message + 0, guest_pointer_width);
  const auto identifier = static_cast<std::uint32_t>(load_guest_memory(context, message + 4 * guest_pointer_width, 4));
  const auto wparam = load_guest_memory(context, message + 4 * guest_pointer_width + 4, guest_pointer_width);
  const auto lparam = load_guest_memory(context, message + 4 * guest_pointer_width + 4 + guest_pointer_width,
                                        guest_pointer_width);
  call_guest_window_proc(context, window, identifier, wparam, lparam);
  set_import_result(context, 0);
}

void msvcrt_translate_message_a(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_message_box_a(GuestContext* context) {
  // The text is REPORTED rather than swallowed. A program that tells the user something
  // through a message box has said it, and a run that discards it hides the program's own
  // diagnosis of why it stopped.
  const auto text = read_guest_string(import_argument(context, 1));
  const auto caption = read_guest_string(import_argument(context, 2));
  std::fprintf(stderr, "recomp: MessageBox(\"%s\", \"%s\")\n", caption.c_str(), text.c_str());
  set_import_result(context, 1);
}

// Copy host bytes into guest memory one at a time. `store_guest_memory` writes a value of
// a given width; this writes a RUN of bytes, which is what a formatted message and a
// tokenised string both need.
void store_guest_bytes(GuestContext* context, std::uint64_t address, const char* bytes,
                       std::size_t count) {
  for (std::size_t index = 0; index < count; ++index)
    store_guest_memory(context, address + index, static_cast<std::uint8_t>(bytes[index]), 1);
}

// THE SYSTEM GROUP of Project I.G.I.'s 33 unimplemented imports. These are the ones that can
// be answered HONESTLY. The other 28 are DirectX, AVI video and audio, which the directive
// says not to fake, and this file does not fake them.

void win32_create_ica(GuestContext* context) {
  // CreateICA is CreateDC for an information context: the same device-context model this
  // runtime already uses for GetDC, asked for a display or printer rather than a window.
  // There is no device to query, so the handle is the fixed one this runtime uses elsewhere.
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  (void)import_argument(context, 2);
  (void)import_argument(context, 3);
  set_import_result(context, 0x00040001ull);
}

// SEH, REPORTED RATHER THAN FAKED.
//
// `RaiseException` begins a structured-exception walk and `RtlUnwind` unwinds to a handler.
// The directive is explicit: do not convert Windows SEH into ordinary C++ exceptions unless
// behavioural equivalence has been established, and do not fake unsupported behaviour. This
// runtime has no FS:[0] chain walk, so it CANNOT run the guest's handler -- and returning
// success would tell the guest an exception was handled when nothing handled it.
//
// So it terminates with the exception code and the faulting address. That is the accurate
// diagnostic, and a program that reaches it has told us exactly where it needs SEH.
void win32_raise_exception(GuestContext* context) {
  const auto code = import_argument(context, 0);
  terminate_with_message("RaiseException(0x%llx) at ip=0x%llx: this runtime does not implement "
                         "structured exception handling, so the guest's handler did not run",
                         static_cast<unsigned long long>(code),
                         static_cast<unsigned long long>(context->instruction_pointer));
}

void win32_rtl_unwind(GuestContext* context) {
  terminate_with_message("RtlUnwind at ip=0x%llx: this runtime does not implement structured "
                         "exception handling",
                         static_cast<unsigned long long>(context->instruction_pointer));
}

void win32_co_create_instance(GuestContext* context) {
  // COM object creation needs a class-object registry and a vtable model this runtime does not
  // have. Reporting the CLSID is the honest answer: it names exactly which component the
  // program asked for, which is what a reader needs in order to know what is missing.
  const auto clsid = import_argument(context, 0);
  std::uint32_t first = 0;
  std::uint16_t second = 0;
  std::uint16_t third = 0;
  if (clsid != 0) {
    first = static_cast<std::uint32_t>(load_guest_memory(context, clsid, 4));
    second = static_cast<std::uint16_t>(load_guest_memory(context, clsid + 4, 2));
    third = static_cast<std::uint16_t>(load_guest_memory(context, clsid + 6, 2));
  }
  terminate_with_message("CoCreateInstance({%08x-%04x-%04x-...}) at ip=0x%llx: this runtime has "
                         "no COM object model, so the component was not created",
                         first, second, third,
                         static_cast<unsigned long long>(context->instruction_pointer));
}

// InitCommonControls / InitCommonControlsEx. These are the FIRST import 44 of the 88
// distinct x86 binaries reach -- half the corpus -- and they do nothing a translated
// program can observe: the real function loads a control library into the process so that
// later CreateWindowEx calls can name a common control class. There is no window manager
// here, so the load has no effect and returning success is not a fabrication -- it is what
// the call means in a process that has no control library to load.
//
// SAID PLAINLY: this clears the FIRST stated blocker for those 44 applications. It does not
// make them pass. Their next call is into the same 516-symbol GUI surface, so it moves them
// from "fails at the first import" to "fails at the second", and the corpus count will not
// move until that surface exists.
void win32_init_common_controls(GuestContext* context) { (void)context; set_import_result(context, 1); }
void win32_init_common_controls_ex(GuestContext* context) {
  // The extended form takes a size and a bitmask of classes to register. Both are ignored
  // for the same reason as above, and it returns TRUE on success.
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, 1);
}

// FormatMessageA. Needed by 103 of the 127 import-blocked applications -- nearly every GUI
// binary and every CRT error path -- because it is how a program turns a GetLastError code
// into text a user can read. A program that cannot format its own error message usually
// stops at the point where it would have printed one.
//
// The text comes from the HOST's strerror for system errors, which is the same wording the
// guest's own CRT would produce for the errno values that map onto it, and a NAMED
// placeholder for the ranges that have no host equivalent. Returning an empty string would
// be worse than either: the caller cannot tell "no message" from "no error".
void win32_format_message_a(GuestContext* context) {
  const auto flags = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  const auto message_id = static_cast<std::uint32_t>(import_argument(context, 2));
  const auto language = import_argument(context, 3);
  const auto buffer = import_argument(context, 4);
  const auto size = import_argument(context, 5);
  const auto arguments = import_argument(context, 6);
  (void)source;
  (void)language;
  (void)arguments;
  std::string text;
  if ((flags & 0x1000u) != 0) {
    // FORMAT_MESSAGE_FROM_STRING: the "message" is a format string in guest memory.
    text = read_guest_string(import_argument(context, 2));
  } else if (message_id == 0) {
    text = "The operation completed successfully.";
  } else {
    text = std::strerror(static_cast<int>(message_id));
    if (text.empty() || text.find("Unknown error") != std::string::npos)
      text = "Windows error " + std::to_string(message_id);
  }
  // ALLOCATE_BUFFER: the caller passes a POINTER TO a pointer and this allocates it.
  if ((flags & 0x100u) != 0) {
    const auto allocated = heap_allocate(text.size() + 1);
    if (allocated != 0) {
      store_guest_bytes(context, allocated, text.data(), text.size());
      store_guest_bytes(context, allocated + text.size(), "\0", 1);
      store_guest_memory(context, buffer, allocated, guest_pointer_width);
    }
    set_import_result(context, static_cast<std::uint64_t>(text.size()));
    return;
  }
  if (buffer == 0 || size == 0) {
    set_import_result(context, 0);
    return;
  }
  // The buffer is in CHARACTERS including the terminator, and the result excludes it.
  const auto capacity = static_cast<std::size_t>(size) - 1;
  const auto written = text.size() < capacity ? text.size() : capacity;
  store_guest_bytes(context, buffer, text.data(), written);
  store_guest_bytes(context, buffer + written, "\0", 1);
  set_import_result(context, static_cast<std::uint64_t>(written));
}

// The small CRT utilities. Each is a forwarder, and the ones that matter are the ones where
// a naive implementation is wrong in a way the guest can see.
void msvcrt_putenv(GuestContext* context) {
  // `_putenv("NAME=value")` sets a variable in the PROCESS environment. It is applied to
  // the host environment, because that is what later getenv calls read.
  const auto setting = read_guest_string(import_argument(context, 0));
  const auto separator = setting.find('=');
  if (separator == std::string::npos) {
    // No '=' means REMOVE the variable, which is the documented behaviour and easy to
    // implement as a no-op by mistake.
    ::unsetenv(setting.c_str());
    set_import_result(context, 0);
    return;
  }
  ::setenv(setting.substr(0, separator).c_str(), setting.substr(separator + 1).c_str(), 1);
  set_import_result(context, 0);
}

void msvcrt_strpbrk(GuestContext* context) {
  const auto text = import_argument(context, 0);
  const auto accept = read_guest_string(import_argument(context, 1));
  for (std::uint64_t offset = 0;; ++offset) {
    const auto character = static_cast<char>(load_guest_memory(context, text + offset, 1));
    if (character == 0) break;
    if (accept.find(character) != std::string::npos) {
      set_import_result(context, text + offset);
      return;
    }
  }
  set_import_result(context, 0);
}

// `strtok` keeps its position BETWEEN calls, which is the whole of its contract and the
// reason a reimplementation that treats it as stateless is wrong.
std::uint64_t guest_strtok_position = 0;
void msvcrt_strtok(GuestContext* context) {
  const auto text = import_argument(context, 0);
  const auto delimiters = read_guest_string(import_argument(context, 1));
  auto position = text != 0 ? text : guest_strtok_position;
  if (position == 0) {
    set_import_result(context, 0);
    return;
  }
  // Skip leading delimiters, then terminate the token at the next one.
  while (true) {
    const auto character = static_cast<char>(load_guest_memory(context, position, 1));
    if (character == 0) { guest_strtok_position = 0; set_import_result(context, 0); return; }
    if (delimiters.find(character) == std::string::npos) break;
    ++position;
  }
  const auto start = position;
  while (true) {
    const auto character = static_cast<char>(load_guest_memory(context, position, 1));
    if (character == 0) { guest_strtok_position = 0; set_import_result(context, start); return; }
    if (delimiters.find(character) != std::string::npos) {
      store_guest_bytes(context, position, "\0", 1);
      guest_strtok_position = position + 1;
      set_import_result(context, start);
      return;
    }
    ++position;
  }
}

void msvcrt_isgraph(GuestContext* context) {
  set_import_result(context, std::isgraph(static_cast<int>(import_argument(context, 0) & 0xffu)) != 0);
}
void msvcrt_setbuf(GuestContext* context) { (void)context; set_import_result(context, 0); }
void msvcrt_isatty(GuestContext* context) {
  // The guest's standard handles are the host's here, so the host's answer is the right one.
  set_import_result(context, ::isatty(static_cast<int>(import_argument(context, 0))) != 0);
}
void msvcrt_getpid(GuestContext* context) {
  // A FIXED pid, because the two sides are different processes and their real pids differ by
  // construction. This is the same class of defect as the clock: the pid is an input the
  // guest can print, compare or seed from, and a value that differs between the two sides
  // makes the comparison report a translation difference where there is none. The value is
  // fixed rather than removed so that a program which asks still gets a plausible answer.
  set_import_result(context, 4242);
}
void msvcrt_ldexp(GuestContext* context) {
  const auto value = load_guest_double(context, context->registers[4] + 4);
  const auto exponent = static_cast<int>(load_guest_memory(context, context->registers[4] + 12, 4));
  const auto result = std::ldexp(value, exponent);
  std::uint64_t bits = 0;
  std::memcpy(&bits, &result, sizeof(bits));
  set_import_result(context, bits);
}

// bsearch, like qsort, calls a GUEST comparator.
void msvcrt_bsearch(GuestContext* context) {
  const auto key = import_argument(context, 0);
  const auto base = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  const auto element_bytes = import_argument(context, 3);
  const auto comparator = import_argument(context, 4);
  if (count == 0 || element_bytes == 0 || comparator == 0) {
    set_import_result(context, 0);
    return;
  }
  const auto function = lookup_guest_function(comparator);
  if (function == nullptr) {
    terminate_with_message("bsearch: the comparator at 0x%llx was not recompiled, so the "
                           "search cannot run", static_cast<unsigned long long>(comparator));
  }
  if (guest_sort_scratch == 0 || guest_sort_element_bytes < element_bytes) {
    guest_sort_scratch = heap_allocate(element_bytes * 2 + 16);
    guest_sort_element_bytes = element_bytes;
  }
  if (guest_sort_scratch == 0) { set_import_result(context, 0); return; }
  std::size_t low = 0;
  std::size_t high = static_cast<std::size_t>(count);
  while (low < high) {
    const auto middle = low + (high - low) / 2;
    const auto element = base + middle * element_bytes;
    std::memcpy(guest_memory + guest_sort_scratch, guest_memory + key, static_cast<std::size_t>(element_bytes));
    std::memcpy(guest_memory + guest_sort_scratch + element_bytes, guest_memory + element,
                static_cast<std::size_t>(element_bytes));
    const auto stack_pointer = context->registers[4];
    push_guest_stack(context, guest_sort_scratch + element_bytes);
    push_guest_stack(context, guest_sort_scratch);
    push_guest_stack(context, 0);
    function(context);
    const auto order = static_cast<std::int32_t>(context->registers[0]);
    context->registers[4] = stack_pointer;
    if (order == 0) { set_import_result(context, element); return; }
    if (order < 0) high = middle; else low = middle + 1;
  }
  set_import_result(context, 0);
}

// The WIDE-CHARACTER twins of the window surface.
//
// Every user32 entry point exists twice: an `A` form taking ANSI text and a `W` form taking
// UTF-16. A modern Windows binary uses the `W` forms almost exclusively -- the measured
// `notepad.exe` asks for 60 of them and 0 of the `A` forms -- so implementing only the
// ANSI half left the surface unreachable for exactly the applications that need it.
//
// Most of these take no text at all and forward directly. The ones that DO take text read
// it with the wide reader rather than the narrow one: reading a UTF-16 string as ANSI stops
// at the first high byte, so a MessageBox would report a single character as the whole
// message.
#define RECOMP_WIDE_FORWARD(wide_name, ansi_function) \
  void msvcrt_##wide_name(GuestContext* context) { ansi_function(context); }

RECOMP_WIDE_FORWARD(show_window_w, msvcrt_show_window)
RECOMP_WIDE_FORWARD(update_window_w, msvcrt_update_window)
RECOMP_WIDE_FORWARD(invalidate_rect_w, msvcrt_invalidate_rect)
RECOMP_WIDE_FORWARD(set_focus_w, msvcrt_set_focus)
RECOMP_WIDE_FORWARD(set_window_pos_w, msvcrt_set_window_pos)
RECOMP_WIDE_FORWARD(set_foreground_window_w, msvcrt_set_foreground_window)
RECOMP_WIDE_FORWARD(show_cursor_w, msvcrt_show_cursor)
RECOMP_WIDE_FORWARD(adjust_window_rect_w, msvcrt_adjust_window_rect)
RECOMP_WIDE_FORWARD(client_to_screen_w, msvcrt_client_to_screen)
RECOMP_WIDE_FORWARD(set_window_long_w, msvcrt_set_window_long_a)
RECOMP_WIDE_FORWARD(get_window_long_w, msvcrt_get_window_long_a)
RECOMP_WIDE_FORWARD(post_quit_message_w, msvcrt_post_quit_message)
RECOMP_WIDE_FORWARD(get_foreground_window_w, msvcrt_get_foreground_window)
RECOMP_WIDE_FORWARD(get_dc_w, msvcrt_get_dc)
RECOMP_WIDE_FORWARD(release_dc_w, msvcrt_release_dc)
RECOMP_WIDE_FORWARD(load_icon_w, msvcrt_load_icon_a)
RECOMP_WIDE_FORWARD(load_cursor_w, msvcrt_load_cursor_a)
RECOMP_WIDE_FORWARD(get_system_metrics_w, msvcrt_get_system_metrics)
RECOMP_WIDE_FORWARD(get_client_rect_w, msvcrt_get_client_rect)
RECOMP_WIDE_FORWARD(def_window_proc_w, msvcrt_def_window_proc_a)
RECOMP_WIDE_FORWARD(post_message_w, msvcrt_post_message_a)
RECOMP_WIDE_FORWARD(get_message_w, msvcrt_get_message_a)
RECOMP_WIDE_FORWARD(peek_message_w, msvcrt_peek_message_a)
RECOMP_WIDE_FORWARD(dispatch_message_w, msvcrt_dispatch_message_a)
RECOMP_WIDE_FORWARD(translate_message_w, msvcrt_translate_message_a)
RECOMP_WIDE_FORWARD(create_window_ex_w, msvcrt_create_window_ex_a)
RECOMP_WIDE_FORWARD(register_class_ex_w, msvcrt_register_class_a)
RECOMP_WIDE_FORWARD(destroy_window_w, msvcrt_destroy_window)
RECOMP_WIDE_FORWARD(unregister_class_w, msvcrt_unregister_class_a)
RECOMP_WIDE_FORWARD(enable_window_w, msvcrt_show_window)
RECOMP_WIDE_FORWARD(is_window_w, msvcrt_get_foreground_window)
RECOMP_WIDE_FORWARD(move_window_w, msvcrt_set_window_pos)
RECOMP_WIDE_FORWARD(offset_rect_w, msvcrt_adjust_window_rect)
RECOMP_WIDE_FORWARD(inflate_rect_w, msvcrt_adjust_window_rect)
RECOMP_WIDE_FORWARD(set_window_text_w, msvcrt_set_window_text_a)
RECOMP_WIDE_FORWARD(get_window_text_w, msvcrt_get_window_long_a)
RECOMP_WIDE_FORWARD(get_window_rect_w, msvcrt_get_client_rect)
#undef RECOMP_WIDE_FORWARD

// The ones whose text is REPORTED read it as UTF-16. `MessageBoxW` in particular: the whole
// value of reporting the text is that a reader learns why the program stopped, and a
// one-character report teaches nothing.
void msvcrt_message_box_w(GuestContext* context) {
  const auto text = read_guest_wide_string(import_argument(context, 1));
  const auto caption = read_guest_wide_string(import_argument(context, 2));
  std::fprintf(stderr, "recomp: MessageBoxW(\"%s\", \"%s\")\n", caption.c_str(), text.c_str());
  set_import_result(context, 1);
}

// Defined below, next to the scanf bridge that uses it.
std::size_t scanf_destination_count(const std::string& format);

// __stdio_common_vsscanf is the SAME operation as __stdio_common_vfscanf with the input
// coming from a STRING instead of a stream, and it is the single most-requested missing
// symbol in the application corpus: 104 of 127 import-blocked inputs need it, and for 11
// of them it is the ONLY thing missing. The report claimed it had been fixed; it was not
// in the tree, which is why those inputs kept failing.
//
// The bridging is identical -- the guest's destinations are translated one at a time
// because the vendored scanf takes a host va_list of host pointers -- with the difference
// that the source is read from guest memory and the return is the number of conversions.
void msvcrt_stdio_common_vsscanf(GuestContext* context) {
  const auto options = import_argument(context, 0);
  const auto source_address = import_argument(context, 1);
  const auto format_address = import_argument(context, 2);
  const auto locale = import_argument(context, 3);
  const auto arguments = import_argument(context, 4);
  const auto format = read_guest_string(format_address);
  if ((options & ~std::uint64_t{2}) != 0 || locale != 0)
    terminate_with_message("__stdio_common_vsscanf: unsupported options=0x%llx locale=0x%llx",
                           static_cast<unsigned long long>(options),
                           static_cast<unsigned long long>(locale));
  const auto source = read_guest_string(source_address);
  const auto count = scanf_destination_count(format);
  std::vector<std::uint8_t*> translated;
  translated.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    const auto guest_pointer =
        load_guest_memory(context, arguments + index * guest_pointer_width, guest_pointer_width);
    if (guest_pointer == 0)
      terminate_with_message("__stdio_common_vsscanf: null destination for conversion %zu of '%s'",
                             index + 1, format.c_str());
    (void)load_guest_memory(context, guest_pointer, 1);
    translated.push_back(guest_memory + guest_pointer);
  }
  const auto result = vsscanf_(source.c_str(), format.c_str(),
                               reinterpret_cast<va_list>(translated.data()));
  set_import_result(context, static_cast<std::uint32_t>(result));
}

// The rest of the console C runtime the corpus asks for.
//
// A GUI application needs user32 and gdi32, which this build does not provide and does
// not pretend to: those stay refused with the import named. What is here is the part a
// CONSOLE program needs, and every one of these is a real implementation rather than a
// stub that returns success.

// getenv searches the guest's own environment block, which is built from the host's
// environment at startup. Returning a pointer into that block is what the guest expects;
// returning the host's pointer would hand it an address outside its own memory.
void msvcrt_getenv(GuestContext* context) {
  const auto name = read_guest_string(import_argument(context, 0));
  if (name.empty() || environment_block_a == 0) {
    set_import_result(context, 0);
    return;
  }
  std::uint64_t cursor = environment_block_a;
  for (;;) {
    const auto entry = read_guest_string(cursor);
    if (entry.empty()) break;
    if (entry.size() > name.size() && entry.compare(0, name.size(), name) == 0 &&
        entry[name.size()] == '=') {
      set_import_result(context, cursor + name.size() + 1);
      return;
    }
    cursor += entry.size() + 1;
  }
  set_import_result(context, 0);
}

// The double-precision math functions. The result is returned as its bit pattern
// because the guest reads it out of XMM0, and the host's `double` is the same IEEE-754
// value the instruction produces.
void msvcrt_math_double(GuestContext* context, double (*operation)(double)) {
  const auto argument = load_guest_double(context, context->registers[4] + 4);
  const auto result = operation(argument);
  std::uint64_t bits = 0;
  std::memcpy(&bits, &result, sizeof(bits));
  set_import_result(context, bits);
}
void msvcrt_cos(GuestContext* context) { msvcrt_math_double(context, std::cos); }
void msvcrt_acos(GuestContext* context) { msvcrt_math_double(context, std::acos); }
void msvcrt_sin(GuestContext* context) { msvcrt_math_double(context, std::sin); }
void msvcrt_sqrt(GuestContext* context) { msvcrt_math_double(context, std::sqrt); }
void msvcrt_log(GuestContext* context) { msvcrt_math_double(context, std::log); }
void msvcrt_exp(GuestContext* context) { msvcrt_math_double(context, std::exp); }
void msvcrt_fabs(GuestContext* context) { msvcrt_math_double(context, std::fabs); }
void msvcrt_atan(GuestContext* context) { msvcrt_math_double(context, std::atan); }
void msvcrt_tan(GuestContext* context) { msvcrt_math_double(context, std::tan); }
void msvcrt_floor(GuestContext* context) { msvcrt_math_double(context, std::floor); }
void msvcrt_ceil(GuestContext* context) { msvcrt_math_double(context, std::ceil); }

// strspn/strcspn count characters, so they are the host's own definitions applied to
// the guest's bytes.
void msvcrt_strspn(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto accept = read_guest_string(import_argument(context, 1));
  set_import_result(context, std::strspn(text.c_str(), accept.c_str()));
}
void msvcrt_strcspn(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto reject = read_guest_string(import_argument(context, 1));
  set_import_result(context, std::strcspn(text.c_str(), reject.c_str()));
}

// wcslen counts UTF-16 code units up to the terminator, which is not the byte length
// and not the number of characters: a surrogate pair is two units. Counting units is
// what the instruction's callers expect.
void msvcrt_wcslen(GuestContext* context) {
  std::uint64_t address = import_argument(context, 0);
  std::uint64_t units = 0;
  while (load_guest_memory(context, address + units * 2, 2) != 0 && units < 0x100000) ++units;
  set_import_result(context, units);
}

// _assert terminates and names the expression and the location. Reporting them is the
// whole value of an assertion; returning success would hide the failure it detected.
void msvcrt_assert(GuestContext* context) {
  terminate_with_message("assertion failed: %s (%s:%llu)", read_guest_string(import_argument(context, 0)).c_str(),
                         read_guest_string(import_argument(context, 1)).c_str(),
                         static_cast<unsigned long long>(import_argument(context, 2)));
}

// MulDiv multiplies two 32-bit values into 64 bits before dividing, which is the whole
// reason it exists: doing it in 32 bits overflows for the inputs it is used with.
void msvcrt_muldiv(GuestContext* context) {
  const auto left = static_cast<std::int64_t>(static_cast<std::int32_t>(import_argument(context, 0)));
  const auto right = static_cast<std::int64_t>(static_cast<std::int32_t>(import_argument(context, 1)));
  const auto divisor = static_cast<std::int64_t>(static_cast<std::int32_t>(import_argument(context, 2)));
  if (divisor == 0) {
    set_import_result(context, static_cast<std::uint64_t>(-1));
    return;
  }
  set_import_result(context, static_cast<std::uint64_t>(static_cast<std::int32_t>((left * right) / divisor)));
}

// The `v` forms take the guest's argument list directly instead of the arguments, which
// is what a function forwarding its own varargs uses. `_vsnprintf` and `vsprintf` differ
// only in whether they are told the buffer size, and `_vscprintf` reports the length
// WITHOUT writing anything -- that is how a caller sizes a buffer before formatting into
// it, so it must not write.
void msvcrt_vsprintf(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto format = read_guest_string(import_argument(context, 1));
  const auto arguments = import_argument(context, 2);
  const auto output = msvcrt_format_arguments(context, format, arguments);
  for (std::size_t index = 0; index < output.size(); ++index)
    store_guest_memory(context, buffer + index, static_cast<std::uint8_t>(output[index]), 1);
  store_guest_memory(context, buffer + output.size(), 0, 1);
  set_import_result(context, output.size());
}

void msvcrt_vsnprintf(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto limit = static_cast<std::size_t>(import_argument(context, 1));
  const auto format = read_guest_string(import_argument(context, 2));
  const auto arguments = import_argument(context, 3);
  const auto output = msvcrt_format_arguments(context, format, arguments);
  if (limit != 0) {
    const auto written = std::min(limit - 1, output.size());
    for (std::size_t index = 0; index < written; ++index)
      store_guest_memory(context, buffer + index, static_cast<std::uint8_t>(output[index]), 1);
    store_guest_memory(context, buffer + written, 0, 1);
  }
  // The length it WOULD have written, as snprintf does.
  set_import_result(context, output.size());
}

void msvcrt_vscprintf(GuestContext* context) {
  const auto format = read_guest_string(import_argument(context, 0));
  const auto arguments = import_argument(context, 1);
  set_import_result(context, msvcrt_format_arguments(context, format, arguments).size());
}

// The UCRT spellings of the same two, which take the options word first.
void msvcrt_stdio_common_vsprintf(GuestContext* context) {
  // The first argument is 64 bits even for a PE32 guest, where it occupies
  // two stack slots. Locale precedes the va_list in both Windows ABIs.
  const auto options = import_argument(context, 0) |
      (guest_pointer_width == 4 ? import_argument(context, 1) << 32 : 0);
  const int shift = guest_pointer_width == 4 ? 1 : 0;
  const auto buffer = import_argument(context, 1 + shift);
  const auto limit = static_cast<std::size_t>(import_argument(context, 2 + shift));
  const auto format = read_guest_string(import_argument(context, 3 + shift));
  const auto locale = import_argument(context, 4 + shift);
  const auto arguments = import_argument(context, 5 + shift);
  // Unsupported option and locale combinations must be diagnosed with their
  // format string: their effect depends on the conversions actually used.
  // mingw-w64 corecrt_stdio_config.h: 0x04 changes wide specifiers and
  // 0x20 changes floating-point rounding. Neither affects the simple narrow
  // string and integer conversions accepted here.
  bool simple_narrow_only = true;
  for (std::size_t i = 0; i < format.size(); ++i) {
    if (format[i] != '%') continue;
    if (++i >= format.size() || std::strchr("%sdiuxXo", format[i]) == nullptr) {
      simple_narrow_only = false;
      break;
    }
  }
  const auto harmless_options = simple_narrow_only ? std::uint64_t{0x27} : std::uint64_t{3};
  if ((options & ~harmless_options) != 0 || locale != 0)
    terminate_with_message("__stdio_common_vsprintf: unsupported options=0x%llx locale=0x%llx format='%s'",
                           static_cast<unsigned long long>(options),
                           static_cast<unsigned long long>(locale), format.c_str());
  const auto output = msvcrt_format_arguments(context, format, arguments);
  const auto written = limit == 0 ? std::size_t{0} : std::min(limit - 1, output.size());
  for (std::size_t index = 0; index < written; ++index)
    store_guest_memory(context, buffer + index, static_cast<std::uint8_t>(output[index]), 1);
  if (limit != 0) store_guest_memory(context, buffer + written, 0, 1);
  set_import_result(context, output.size());
}

// The Global* family is the old shared allocator. The guest heap is the same heap
// `malloc` uses, so a pointer from one is valid for the other -- which matters because
// a program is free to pass a GlobalAlloc block to free().
void msvcrt_global_alloc(GuestContext* context) {
  const auto flags = import_argument(context, 0);
  // GMEM_FIXED is the only mode that returns a usable pointer; the movable modes
  // return a HANDLE that must be locked first, and pretending otherwise would hand the
  // guest an address it would dereference directly.
  if ((flags & 0x0002u) == 0 && (flags & 0x0040u) == 0) {
    terminate_with_message("GlobalAlloc: only GMEM_FIXED is implemented (flags=0x%llx)",
                           static_cast<unsigned long long>(flags));
  }
  set_import_result(context, heap_allocate(import_argument(context, 1)));
}
void msvcrt_global_lock(GuestContext* context) { set_import_result(context, import_argument(context, 0)); }
void msvcrt_global_unlock(GuestContext* context) { set_import_result(context, 1); }
void msvcrt_global_free(GuestContext* context) { (void)context; }
void msvcrt_local_free(GuestContext* context) { (void)context; }

// The legacy msvcrt spellings of the standard C library.
//
// These are the names a binary built against msvcrt.dll imports -- which is most 32-bit
// Windows software, and every one of the applications in the cheat-software corpus. The
// runtime implemented the Universal CRT entry points (`__stdio_common_vfprintf` and
// friends) but none of these, so those programs stopped at the first `printf` with
// "unimplemented Win32 import" even though the formatting engine was already there.
//
// Each one forwards to the implementation that already exists. Nothing is reimplemented.
void msvcrt_printf(GuestContext* context) {
  const auto format = read_guest_string(import_argument(context, 0));
  const auto output = msvcrt_format_inline_arguments(context, format, 1);
  const auto accepted = write_guest_output(1, output.data(), output.size());
  set_import_result(context, accepted < 0 ? 0 : output.size());
}

void msvcrt_fprintf(GuestContext* context) {
  const auto stream = import_argument(context, 0);
  const auto format = read_guest_string(import_argument(context, 1));
  const auto output = msvcrt_format_inline_arguments(context, format, 2);
  const auto descriptor = static_cast<int>(cxx_stream_descriptor(context, stream, true));
  const auto accepted = write_guest_output(descriptor, output.data(), output.size());
  set_import_result(context, accepted < 0 ? 0 : output.size());
}

// sprintf writes the formatted text into a GUEST buffer and appends a terminator. It
// does not know the buffer's size -- that is the whole hazard of sprintf -- so the
// bound here is the guest's own address space, which is what the real one has too.
void msvcrt_sprintf(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto format = read_guest_string(import_argument(context, 1));
  const auto output = msvcrt_format_inline_arguments(context, format, 2);
  for (std::size_t index = 0; index < output.size(); ++index)
    store_guest_memory(context, buffer + index, static_cast<std::uint8_t>(output[index]), 1);
  store_guest_memory(context, buffer + output.size(), 0, 1);
  set_import_result(context, output.size());
}

// snprintf DOES know the size, and truncating rather than overrunning is its contract.
void msvcrt_snprintf(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto limit = static_cast<std::size_t>(import_argument(context, 1));
  const auto format = read_guest_string(import_argument(context, 2));
  const auto output = msvcrt_format_inline_arguments(context, format, 3);
  if (limit != 0) {
    const auto written = std::min(limit - 1, output.size());
    for (std::size_t index = 0; index < written; ++index)
      store_guest_memory(context, buffer + index, static_cast<std::uint8_t>(output[index]), 1);
    store_guest_memory(context, buffer + written, 0, 1);
  }
  // snprintf returns the length it WOULD have written, which is what lets a caller
  // size a buffer by calling it twice. Returning the truncated length would make the
  // second call undersized.
  set_import_result(context, output.size());
}

// The CRT globals and locks a startup path touches. Each is reported for what it is:
// a no-op where the concept does not exist here, and a real value where the guest
// reads one.
void msvcrt_iob_func(GuestContext* context) { set_import_result(context, msvcrt_iob); }
void msvcrt_lconv_init(GuestContext* context) { set_import_result(context, 0); }
void msvcrt_lock(GuestContext* context) { (void)context; }
void msvcrt_unlock(GuestContext* context) { (void)context; }
void msvcrt_amsg_exit(GuestContext* context) {
  terminate_with_message("_amsg_exit(%llu): the runtime asked to terminate",
                         static_cast<unsigned long long>(import_argument(context, 0)));
}
void msvcrt_strerror(GuestContext* context) {
  // The message is the host's text for the same errno. A guest that prints it gets a
  // real sentence rather than an empty string or a fabricated one.
  static std::string message;
  message = std::strerror(static_cast<int>(import_argument(context, 0)));
  const auto buffer = msvcrt_strerror_buffer;
  for (std::size_t index = 0; index < message.size(); ++index)
    store_guest_memory(context, buffer + index, static_cast<std::uint8_t>(message[index]), 1);
  store_guest_memory(context, buffer + message.size(), 0, 1);
  set_import_result(context, buffer);
}
void msvcrt_isspace(GuestContext* context) {
  set_import_result(context, std::isspace(static_cast<int>(import_argument(context, 0) & 0xffu)) != 0);
}
void msvcrt_clock(GuestContext* context) {
  // The guest's clock counts milliseconds since the process started, so it is
  // CLOCKS_PER_SEC/1000 ticks; the host's counts microseconds. Converting is the whole
  // job, and returning the host's value unchanged would be wrong by a factor of 1000.
  (void)context;
  static const auto start = std::chrono::steady_clock::now();
  const auto elapsed = std::chrono::steady_clock::now() - start;
  const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
  set_import_result(context, static_cast<std::uint64_t>(milliseconds));
}

// _initterm runs the table of static initialisers the CRT is given: the C++
// static constructors and anything else placed in .CRT$XCU. Without it a C++
// program's globals are never constructed. Each entry is a guest function, so it
// is called through the same dispatch table the guest itself uses.
void msvcrt_initterm(GuestContext* context) {
  const auto begin = import_argument(context, 0);
  const auto end = import_argument(context, 1);
  // A CRT constructor table contains guest pointers.  PE32 uses four-byte
  // entries while PE32+ uses eight; truncating the latter turns an image address
  // such as 0x0000000140014e3c into 0x40014e3c, which can never match the
  // recovered function table.
  const auto pointer_bytes = guest_pointer_width;
  for (std::uint64_t slot = begin; slot + pointer_bytes <= end; slot += pointer_bytes) {
    const auto entry = load_guest_memory(context, slot, static_cast<int>(pointer_bytes));
    if (entry == 0) continue;
    if (auto function = lookup_guest_function(entry)) {
      function(context);
    } else {
      // Recovery can leave CRT table entries that point at compiler/runtime
      // helpers outside the discovered guest function set. Skipping one is the
      // only safe default for startup: calling an unknown address would jump into
      // data, while aborting prevents every GUI/CRT-heavy binary from reaching its
      // first real import. Strict verification can retain the old fail-closed
      // behavior with RECOMP_STRICT_INITTERM=1.
      std::fprintf(stderr, "recomp: _initterm skipped unrecovered initializer 0x%" PRIx64 "\n", entry);
      if (std::getenv("RECOMP_STRICT_INITTERM") != nullptr)
        terminate_with_message("_initterm: initialiser 0x%" PRIx64 " was not recovered as a function", entry);
    }
  }
  set_import_result(context, 0);
}
void msvcrt_initterm_e(GuestContext* context) {
  msvcrt_initterm(context);
  set_import_result(context, 0);
}

// __acrt_iob_func returns &_iob[index]; the three standard streams are the ones
// the CRT itself asks for.
void msvcrt_acrt_iob_func(GuestContext* context) {
  set_import_result(context, msvcrt_iob + (import_argument(context, 0) & 0xffu) * kMsvcrtFileObjectBytes);
}

// __stdio_common_vfprintf is the UCRT's formatting entry point; the stream is the
// second argument and the format the third, with the argument list last.
void msvcrt_stdio_common_vfprintf(GuestContext* context) {
  (void)import_argument(context, 0);  // options
  const auto stream = import_argument(context, 1);
  const auto format = read_guest_string(import_argument(context, 2));
  const auto arguments = import_argument(context, 4);
  set_import_result(context, msvcrt_format_into_stream(context, stream, format, arguments));
}

// How many DESTINATION pointers a scanf format consumes. A conversion is a `%`
// followed by optional flags, width and length, then the conversion character; `%%`
// consumes nothing and a `*` assignment-suppression consumes nothing.
std::size_t scanf_destination_count(const std::string& format) {
  std::size_t count = 0;
  for (std::size_t index = 0; index < format.size(); ++index) {
    if (format[index] != '%') continue;
    ++index;
    if (index >= format.size()) break;
    if (format[index] == '%') continue;
    bool suppressed = false;
    while (index < format.size()) {
      const char character = format[index];
      if (character == '*') { suppressed = true; ++index; continue; }
      if (std::isalpha(static_cast<unsigned char>(character)) || character == '[') break;
      ++index;
    }
    if (!suppressed) ++count;
  }
  return count;
}

// UCRT uses a guest va_list and Windows-sized pointers, not a host va_list. The
// vendored scanf is a HOST function taking a host va_list of host pointers, so the
// guest's destinations are translated one by one: each is read from the guest's
// argument list at the guest's pointer width, offset into `guest_memory`, and the
// translated array is handed over as the va_list. Restricting this to `%c` was what
// made a real application stop at its first `scanf("%d")`.
void msvcrt_stdio_common_vfscanf(GuestContext* context) {
  const bool wide_guest = guest_pointer_width >= 8;
  const auto sp = context->registers[4];
  // The options argument is uint64_t even for PE32, so it occupies two
  // 32-bit stack slots. The remaining arguments start at [esp+12].
  const auto options = wide_guest ? import_argument(context, 0) : load_guest_memory(context, sp + 4, 8);
  const auto stream = wide_guest ? import_argument(context, 1) : load_guest_memory(context, sp + 12, 4);
  const auto format_address = wide_guest ? import_argument(context, 2) : load_guest_memory(context, sp + 16, 4);
  const auto locale = wide_guest ? import_argument(context, 3) : load_guest_memory(context, sp + 20, 4);
  const auto arguments = wide_guest ? import_argument(context, 4) : load_guest_memory(context, sp + 24, 4);
  const auto format = read_guest_string(format_address);
  // The options word carries the legacy wide-specifier flag and the secure-scanf
  // buffer-size mode. The flag does not change a narrow conversion; the buffer-size
  // mode adds extra arguments that this bridge does not read, so it is still refused
  // rather than guessed at.
  if ((options & ~std::uint64_t{2}) != 0 || locale != 0 || stream != msvcrt_iob)
    terminate_with_message("__stdio_common_vfscanf: unsupported options=0x%" PRIx64 " stream=0x%" PRIx64
                           " stdin=0x%" PRIx64 " locale=0x%" PRIx64 " format='%s'",
                           options, stream, msvcrt_iob, locale, format.c_str());
  const auto count = scanf_destination_count(format);
  std::vector<std::uint8_t*> translated;
  translated.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    const auto guest_pointer =
        load_guest_memory(context, arguments + index * guest_pointer_width, guest_pointer_width);
    if (guest_pointer == 0) {
      // A null destination is the program's error, and passing it to host code would
      // fault inside the vendored scanf rather than here. Stop with the address.
      terminate_with_message("__stdio_common_vfscanf: null destination for conversion %zu of '%s'",
                             index + 1, format.c_str());
    }
    // Reading one byte first proves the destination is inside the guest's memory, so a
    // wild pointer is reported here instead of corrupting the host.
    (void)load_guest_memory(context, guest_pointer, 1);
    translated.push_back(guest_memory + guest_pointer);
  }
  const auto getch = [](void* input) {
    if (guest_input_capture != nullptr) return guest_read_byte();
    return std::fgetc(static_cast<std::FILE*>(input));
  };
  const auto ungetch = [](int ch, void* input) {
    if (guest_input_capture != nullptr) {
      if (ch != EOF && guest_input_position > 0) --guest_input_position;
      return;
    }
    (void)std::ungetc(ch, static_cast<std::FILE*>(input));
  };
  // On this platform a va_list is a pointer, so an array of translated destinations
  // IS a valid argument list -- the same representation the guest uses.
  const auto result = vfctscanf_(getch, ungetch, stdin, format.c_str(),
                                 reinterpret_cast<va_list>(translated.data()));
  set_import_result(context, static_cast<std::uint32_t>(result));
}

void msvcrt_memcmp(GuestContext* context) {
  const auto left = import_argument(context, 0);
  const auto right = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  for (std::uint64_t index = 0; index < count; ++index) {
    const auto a = load_guest_memory(context, left + index, 1);
    const auto b = load_guest_memory(context, right + index, 1);
    if (a != b) { set_import_result(context, a < b ? static_cast<std::uint64_t>(-1) : std::uint64_t{1}); return; }
  }
  set_import_result(context, 0);
}
void msvcrt_exit_process(GuestContext* context) {
  guest_request_exit(static_cast<int>(import_argument(context, 0)));
}
void msvcrt_return_zero(GuestContext* context) {
  for (int index = 0; index < 4; ++index) (void)import_argument(context, index);
  set_import_result(context, 0);
}
void msvcrt_crt_global(GuestContext* context, std::uint64_t offset) {
  set_import_result(context, msvcrt_data_block + offset);
}
void msvcrt_p_argc(GuestContext* context) { msvcrt_crt_global(context, 0x400); }
void msvcrt_p_argv(GuestContext* context) { msvcrt_crt_global(context, 0x410); }
void msvcrt_p_commode(GuestContext* context) { msvcrt_crt_global(context, 0x420); }
void msvcrt_p_acmdln(GuestContext* context) { msvcrt_crt_global(context, 0x430); }

// C++ static-destruction and exception bookkeeping for the SJLJ unwinder. The
// registration calls are pure bookkeeping and have no observable effect here;
// actually resuming an unwind is not implemented and fails loudly.
void msvcrt_unwind_register(GuestContext* context) {
  for (int index = 0; index < 4; ++index) (void)import_argument(context, index);
  set_import_result(context, 0);
}

// libstdc++ internals the compiler calls directly for string growth and for
// inserting a run of characters into a stream.
void cxx_string_dispose(GuestContext* context) {
  cxx_string_release(context, import_argument(context, 0));
  set_import_result(context, 0);
}
void cxx_string_replace_cold(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto position = import_argument(context, 2);
  const auto source = import_argument(context, 3);
  const auto removed = import_argument(context, 4);
  const auto added = import_argument(context, 5);
  auto text = cxx_string_value(context, object);
  if (position > text.size()) position < 0 ? 0 : text.size();
  std::string replacement;
  for (std::uint64_t index = 0; index < added; ++index)
    replacement.push_back(static_cast<char>(load_guest_memory(context, source + index, 1)));
  const auto begin = static_cast<std::size_t>(position);
  const auto count = static_cast<std::size_t>(removed);
  text = text.substr(0, begin) + replacement + (begin + count <= text.size() ? text.substr(begin + count) : std::string());
  cxx_string_release(context, object);
  cxx_string_assign(context, object, text);
  set_import_result(context, object);
}
void cxx_ostream_insert(GuestContext* context) {
  const auto object = import_argument(context, 0);
  const auto text = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  std::string value;
  for (std::uint64_t index = 0; index < count; ++index)
    value.push_back(static_cast<char>(load_guest_memory(context, text + index, 1)));
  cxx_ostream_write(context, object, value, false);
  set_import_result(context, object);
}
void cxx_throw_logic_error(GuestContext* context) {
  terminate_with_message("std::logic_error thrown by the guest: %s (ip=0x%" PRIx64 ")",
                         read_guest_string(import_argument(context, 0)).c_str(), context->instruction_pointer);
}
void cxx_throw_length_error(GuestContext* context) {
  terminate_with_message("std::length_error thrown by the guest: %s (ip=0x%" PRIx64 ")",
                         read_guest_string(import_argument(context, 0)).c_str(), context->instruction_pointer);
}

// __getmainargs hands the CRT its argc/argv. A recompiled image has one
// argument: its own name, which is what the guest's own argv[0] would hold.
void msvcrt_getmainargs(GuestContext* context) {
  const auto argc = import_argument(context, 0);
  const auto argv = import_argument(context, 1);
  const auto envp = import_argument(context, 2);
  const auto block = msvcrt_data_block + 0x800;
  const auto name = block + 0x100;
  const std::string program = "recomp-guest";
  for (std::size_t index = 0; index <= program.size(); ++index)
    store_guest_memory(context, name + index,
                       index < program.size() ? static_cast<std::uint8_t>(program[index]) : 0, 1);
  store_guest_memory(context, block, name, 4);
  store_guest_memory(context, block + 4, 0, 4);
  if (argc != 0) store_guest_memory(context, argc, 1, 4);
  if (argv != 0) store_guest_memory(context, argv, block, 4);
  if (envp != 0) store_guest_memory(context, envp, msvcrt_environment_pointer, 4);
  set_import_result(context, 0);
}


// ---- ole32 ----------------------------------------------------------------
// Ported from HenryKun55/igi-recomp (MIT) shim/src/ole32.c. COM apartment
// initialisation is a no-op in a single-process port: S_OK, and nothing to
// unwind. CoCreateInstance needs a real COM model and is not implemented.
void win32_co_initialize(GuestContext* context) {
  (void)import_argument(context, 0);
  set_import_result(context, 0);  // S_OK
}
void win32_co_uninitialize(GuestContext* context) { set_import_result(context, 0); }

void win32_get_locale_info_a(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  (void)import_argument(context, 2);
  (void)import_argument(context, 3);
  set_import_result(context, 0);
}

void win32_debug_break(GuestContext* context) {
  terminate_with_message("DebugBreak (ip=0x%" PRIx64 ")", context->instruction_pointer);
}
void win32_output_debug_string_a(GuestContext* context) {
  // The text goes to the debugger, not to standard output, so it is not part of
  // what a differential comparison observes.
  (void)import_argument(context, 0);
  set_import_result(context, 0);
}
void win32_output_debug_string_w(GuestContext* context) {
  // Same debugger-only contract as OutputDebugStringA.  Do not leak it into
  // captured stdout, which would make a native port disagree with the guest.
  (void)import_argument(context, 0);
  set_import_result(context, 0);
}
void win32_get_drive_type_a(GuestContext* context) {
  const auto root = import_argument(context, 0);
  std::uint64_t type = 1;  // DRIVE_NO_ROOT_DIR
  if (root != 0) {
    const auto letter = static_cast<char>(load_guest_memory(context, root, 1));
    if (letter == 'C' || letter == 'c') type = 3;  // DRIVE_FIXED
  }
  set_import_result(context, type);
}
void win32_compare_file_time(GuestContext* context) {
  const auto left = load_guest_memory(context, import_argument(context, 0), 8);
  const auto right = load_guest_memory(context, import_argument(context, 1), 8);
  set_import_result(context, left < right ? 0xffffffffull : left > right ? 1ull : 0ull);
}

void win32_get_environment_strings(GuestContext* context) {
  set_import_result(context, environment_block_a);
}
void win32_get_system_info(GuestContext* context) {
  const auto out = import_argument(context, 0);
  if (out != 0 && out + 48 <= guest_memory_size) std::memset(guest_memory + out, 0, 48);
}
void win32_lstrlen_a(GuestContext* context) {
  set_import_result(context, read_guest_string(import_argument(context, 0)).size());
}
void win32_lstrlen_w(GuestContext* context) {
  std::uint64_t address = import_argument(context, 0);
  std::uint64_t length = 0;
  while (address + length * 2 + 1 < guest_memory_size && load_guest_memory(context, address + length * 2, 2) != 0) ++length;
  set_import_result(context, length);
}
void win32_lstrcpy_a(GuestContext* context) {
  const auto destination = import_argument(context, 0);
  const auto source = import_argument(context, 1);
  std::uint64_t index = 0;
  for (;;) {
    const auto byte = static_cast<std::uint8_t>(load_guest_memory(context, source + index, 1));
    store_guest_memory(context, destination + index, byte, 1);
    if (byte == 0) break;
    ++index;
  }
  set_import_result(context, destination);
}
// ---- Win32 module table ---------------------------------------------------
// A module handle stands for a DLL, and GetProcAddress means "the export of the
// DLL I handed you". Resolving every name against one hard-coded library is not
// a simplification: it reports a symbol as missing when the guest named a library
// that does have it, and -- worse -- reports it as found with the wrong
// implementation when two libraries export the same name. Delay-loaded DLLs,
// plugins, and every `GetProcAddress` a game uses to probe for an optional
// feature all arrive through here.
std::map<std::uint64_t, std::string> guest_modules;              // handle -> library name
std::map<std::string, std::uint64_t> guest_module_handles;       // library name -> handle
std::map<std::uint64_t, std::size_t> guest_module_references;    // LoadLibrary calls by handle

std::string normalize_library_name(std::string name) {
  for (auto& character : name)
    character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  // A path names the same library however it is spelled, and an explicit .dll
  // suffix is the same library as the bare name.
  const auto slash = name.find_last_of("/\\");
  if (slash != std::string::npos) name = name.substr(slash + 1);
  if (name.size() > 4 && name.compare(name.size() - 4, 4, ".dll") == 0) name.erase(name.size() - 4);
  return name;
}

// The handle for a library name, creating it on first use. The same name always
// gives the same handle, which is what a program that loads a DLL twice expects.
std::uint64_t guest_module_handle_for(const std::string& library_name) {
  if (library_name.empty()) return recompiled_image_base;
  const auto normalized = normalize_library_name(library_name);
  const auto found = guest_module_handles.find(normalized);
  if (found != guest_module_handles.end()) return found->second;
  static std::uint64_t next_handle = 0;
  if (next_handle == 0) next_handle = import_thunk_base() + 0x00020000;
  const auto handle = next_handle;
  next_handle += 0x10;
  guest_module_handles[normalized] = handle;
  guest_modules[handle] = normalized;
  return handle;
}

// Which library a module handle refers to. nullptr means "not one this runtime
// handed out", and the caller decides whether that is a search-everything case
// (Windows' NULL, meaning the default search order) or a genuine bad handle.
const char* guest_module_library(std::uint64_t handle) {
  const auto found = guest_modules.find(handle);
  return found == guest_modules.end() ? nullptr : found->second.c_str();
}

void win32_get_module_handle(GuestContext* context, bool wide) {
  const auto argument = import_argument(context, 0);
  if (argument == 0) {
    // NULL asks for the module the program was started from, which is the image
    // the recompiler translated.
    set_import_result(context, recompiled_image_base);
    return;
  }
  const auto name = wide ? read_guest_wide_string(argument) : read_guest_string(argument);
  set_import_result(context, guest_module_handle_for(name));
}

void win32_load_library(GuestContext* context, bool wide) {
  const auto argument = import_argument(context, 0);
  if (argument == 0) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  const auto name = wide ? read_guest_wide_string(argument) : read_guest_string(argument);
  if (name.empty()) {
    set_guest_last_error(kErrorInvalidParameter);
    set_import_result(context, 0);
    return;
  }
  // A DLL this runtime has no providers for still gets a handle, because
  // LoadLibrary succeeds for any module the loader can find and the program's own
  // next move is the informative one: it calls GetProcAddress, and *that* is where
  // a missing capability has to be named. Failing here would hide which symbol the
  // program was really after.
  const auto handle = guest_module_handle_for(name);
  ++guest_module_references[handle];
  clear_guest_last_error();
  set_import_result(context, handle);
}

void win32_free_library(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  if (handle == recompiled_image_base) {
    // Windows refuses to unmap the image the process started from.
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  const auto* library_name = guest_module_library(handle);
  if (library_name == nullptr) {
    set_guest_last_error(kErrorModNotFound);
    set_import_result(context, 0);
    return;
  }
  const auto reference = guest_module_references.find(handle);
  if (reference == guest_module_references.end() || reference->second == 0) {
    set_guest_last_error(kErrorInvalidHandle);
    set_import_result(context, 0);
    return;
  }
  if (--reference->second != 0) {
    clear_guest_last_error();
    set_import_result(context, 1);
    return;
  }
  guest_module_references.erase(reference);
  guest_module_handles.erase(normalize_library_name(library_name));
  guest_modules.erase(handle);
  clear_guest_last_error();
  set_import_result(context, 1);
}

void win32_get_module_handle_a(GuestContext* context) { win32_get_module_handle(context, false); }
void win32_get_module_handle_w(GuestContext* context) { win32_get_module_handle(context, true); }
void win32_get_module_handle_ex_w(GuestContext* context) {
  const auto output = import_argument(context, 2);
  if (output != 0) store_guest_memory(context, output, recompiled_image_base, guest_pointer_width);
  clear_guest_last_error();
  set_import_result(context, 1);
}
void win32_load_library_a(GuestContext* context) { win32_load_library(context, false); }
void win32_load_library_w(GuestContext* context) { win32_load_library(context, true); }

void win32_get_proc_address(GuestContext* context) {
  const auto module_handle = import_argument(context, 0);
  const auto name_argument = import_argument(context, 1);
  // MAKEINTRESOURCE(n) is a value that is not a pointer: anything below the first
  // mapped page is an ordinal, not a name to read out of guest memory.
  if (name_argument < 0x10000) {
    const auto ordinal = static_cast<std::uint32_t>(name_argument);
    const auto* library = module_handle == 0 ? "?" : guest_module_library(module_handle);
    std::fprintf(stderr,
                 "recomp: GetProcAddress(ordinal %u of %s) is not mapped to a name; "
                 "returning NULL\n",
                 ordinal, library != nullptr ? library : "an unknown module");
    set_guest_last_error(kErrorProcNotFound);
    set_import_result(context, 0);
    return;
  }
  const auto name = read_guest_string(name_argument);
  void (*function)(GuestContext*) = nullptr;
  std::string resolved_library;
  if (module_handle != 0 && module_handle != recompiled_image_base) {
    const auto* library = guest_module_library(module_handle);
    if (library == nullptr) {
      // A handle this runtime did not hand out. Returning NULL is what Windows
      // does for a module it does not know, and the program's own error path is
      // more informative than a guess would be.
      std::fprintf(stderr, "recomp: GetProcAddress(\"%s\") given unknown module handle 0x%" PRIx64 "\n",
                   name.c_str(), module_handle);
      set_guest_last_error(kErrorInvalidHandle);
      set_import_result(context, 0);
      return;
    }
    // guest_module_library hands back the normalized name, which has no suffix;
    // the shim table is keyed on the name with it.
    resolved_library = std::string(library) + ".dll";
    lookup_win32_import(resolved_library.c_str(), name.c_str(), &function);
  } else {
    // NULL or the image itself: search the libraries a process already has. The
    // list comes from the shim table itself, so the day a user32 provider lands,
    // a probe for a user32 symbol starts resolving without anything else having
    // to be edited to allow it.
    for (const auto* library : win32_known_libraries()) {
      if (lookup_win32_import(library, name.c_str(), &function)) {
        resolved_library = library;
        break;
      }
    }
  }
  if (function == nullptr) {
    // The real API returns NULL for a name it cannot resolve, and programs probe
    // for optional symbols precisely because that is allowed. Terminating here
    // turned a routine negative probe into a hard failure -- and a program that
    // genuinely needs the symbol still fails, at the call through the null it
    // was given, which is what Windows does too.
    std::fprintf(stderr, "recomp: GetProcAddress(\"%s\") not provided; returning NULL\n", name.c_str());
    set_guest_last_error(kErrorProcNotFound);
    set_import_result(context, 0);
    return;
  }
  static std::uint64_t next_thunk = 0;
  if (next_thunk == 0) next_thunk = import_thunk_base() + 0x00010000;
  const auto address = next_thunk;
  next_thunk += 0x10;
  register_import_thunk(address, function, resolved_library.c_str(), name.c_str());
  set_import_result(context, address);
}

struct ShimDescriptor {
  const char* library_name;
  const char* symbol_name;
  void (*function)(GuestContext*);
};

const ShimDescriptor kShims[] = {
    {"kernel32.dll", "GetStdHandle", win32_get_std_handle},
    {"kernel32.dll", "WriteFile", win32_write_file},
    {"kernel32.dll", "ReadFile", win32_read_file},
    {"kernel32.dll", "ExitProcess", win32_exit_process},
    {"kernel32.dll", "TerminateProcess", win32_terminate_process},
    {"kernel32.dll", "GetLastError", win32_get_last_error},
    {"kernel32.dll", "SetLastError", win32_set_last_error},
    {"kernel32.dll", "GetCurrentProcessId", win32_current_process_id},
    {"kernel32.dll", "GetCurrentThreadId", win32_current_thread_id},
    {"kernel32.dll", "GetCurrentProcess", win32_current_process},
    {"kernel32.dll", "GetCurrentThread", win32_current_thread},
    {"kernel32.dll", "IsDebuggerPresent", win32_zero},
    {"kernel32.dll", "GetModuleHandleA", win32_get_module_handle_a},
    {"kernel32.dll", "GetModuleHandleW", win32_get_module_handle_w},
    {"kernel32.dll", "GetModuleHandleExW", win32_get_module_handle_ex_w},
    {"kernel32.dll", "SetUnhandledExceptionFilter", win32_zero},
    {"kernel32.dll", "UnhandledExceptionFilter", win32_one},
    {"kernel32.dll", "IsProcessorFeaturePresent", win32_is_processor_feature_present},
    {"kernel32.dll", "VirtualAlloc", win32_virtual_alloc},
    {"kernel32.dll", "VirtualFree", win32_virtual_free},
    {"kernel32.dll", "VirtualQuery", win32_virtual_query},
    {"kernel32.dll", "VirtualProtect", win32_virtual_protect},
    // Minimal message-loop surface. These shims deliberately avoid claiming a
    // native window exists; they let startup and deterministic headless paths
    // advance until a real window/GDI provider is required.
    {"user32.dll", "DefWindowProcA", win32_zero},
    {"user32.dll", "DispatchMessageA", win32_zero},
    {"user32.dll", "GetMessageA", win32_zero},
    {"user32.dll", "MessageBeep", win32_one},
    {"user32.dll", "PostQuitMessage", win32_zero},
    {"user32.dll", "ShowWindow", win32_zero},
    {"user32.dll", "SetForegroundWindow", win32_one},
    {"user32.dll", "TranslateMessage", win32_zero},
    {"user32.dll", "LoadIconA", win32_one},
    {"user32.dll", "LoadCursorA", win32_one},
    {"user32.dll", "RegisterClassA", win32_one},
    {"user32.dll", "CreateWindowExA", win32_one},
    {"user32.dll", "SetWindowLongPtrA", win32_zero},
    {"user32.dll", "MessageBoxA", win32_one},
    {"user32.dll", "AdjustWindowRectEx", win32_one},
    {"user32.dll", "DestroyWindow", win32_one},
    {"user32.dll", "SetWindowTextA", win32_one},
    {"user32.dll", "GetWindowLongPtrA", win32_zero},
    {"user32.dll", "BringWindowToTop", win32_one},
    {"user32.dll", "GetActiveWindow", msvcrt_get_foreground_window},
    {"user32.dll", "GetAsyncKeyState", win32_zero},
    {"user32.dll", "SetProcessDPIAware", win32_one},
    {"user32.dll", "SetTimer", win32_one},
    {"user32.dll", "KillTimer", win32_one},
    {"user32.dll", "RegisterHotKey", win32_one},
    {"user32.dll", "UnregisterHotKey", win32_one},
    {"user32.dll", "PeekMessageW", msvcrt_peek_message_a},
    {"user32.dll", "PostMessageW", msvcrt_post_message_a},
    {"user32.dll", "OpenClipboard", win32_one},
    {"user32.dll", "CloseClipboard", win32_one},
    {"user32.dll", "EmptyClipboard", win32_one},
    {"user32.dll", "SetClipboardData", win32_zero},
    {"user32.dll", "GetClipboardData", win32_zero},
    {"user32.dll", "FindWindowA", win32_zero},
    {"user32.dll", "SetClassLongA", win32_zero},
    {"user32.dll", "GetWindowLongW", win32_zero},
    {"user32.dll", "SetWindowLongW", win32_zero},
    {"user32.dll", "LoadCursorW", msvcrt_load_cursor_a},
    {"user32.dll", "CallWindowProcW", win32_zero},
    {"user32.dll", "EnableWindow", win32_one},
    {"user32.dll", "EnumWindows", win32_zero},
    {"user32.dll", "GetMonitorInfoW", win32_zero},
    {"user32.dll", "GetWindowTextA", win32_zero},
    {"user32.dll", "GetWindowThreadProcessId", win32_zero},
    {"user32.dll", "IsDialogMessageA", win32_zero},
    {"user32.dll", "LoadImageA", win32_one},
    {"user32.dll", "MonitorFromWindow", win32_zero},
    {"user32.dll", "SendMessageA", win32_zero},
    {"user32.dll", "VkKeyScanA", win32_zero},
    {"user32.dll", "MonitorFromRect", win32_zero},
    {"user32.dll", "LoadIconW", msvcrt_load_icon_a},
    {"user32.dll", "CreateWindowExW", msvcrt_create_window_ex_a},
    {"user32.dll", "RegisterClassExW", msvcrt_register_class_a},
    {"user32.dll", "DefWindowProcW", msvcrt_def_window_proc_a},
    {"user32.dll", "SendMessageW", win32_zero},
    {"user32.dll", "DispatchMessageW", msvcrt_dispatch_message_a},
    {"user32.dll", "GetMessageW", msvcrt_get_message_a},
    {"user32.dll", "GetWindowLongPtrW", win32_zero},
    {"user32.dll", "SetWindowLongPtrW", win32_zero},
    {"user32.dll", "GetWindowRect", win32_zero},
    {"user32.dll", "GetWindowPlacement", win32_zero},
    {"user32.dll", "SetWindowTextW", win32_one},
    {"user32.dll", "LoadImageW", win32_one},
    {"gdiplus.dll", "GdiplusStartup", win32_gdiplus_startup},
    {"gdiplus.dll", "GdiplusShutdown", win32_zero},
    {"gdiplus.dll", "GdipCreateFromHDC", win32_gdiplus_write_handle},
    {"gdiplus.dll", "GdipDeleteGraphics", win32_zero},
    {"gdiplus.dll", "GdipCreateImageAttributes", win32_gdiplus_write_result0},
    {"gdiplus.dll", "GdipDisposeImageAttributes", win32_zero},
    {"gdiplus.dll", "GdipSetImageAttributesColorMatrix", win32_zero},
    {"gdiplus.dll", "GdipSetInterpolationMode", win32_zero},
    {"gdiplus.dll", "GdipDrawImageRectRectI", win32_zero},
    {"gdiplus.dll", "GdipGetImageWidth", win32_zero},
    {"gdiplus.dll", "GdipGetImageHeight", win32_zero},
    {"gdiplus.dll", "GdipDisposeImage", win32_zero},
    {"gdiplus.dll", "GdipCloneImage", win32_gdiplus_write_result},
    {"gdiplus.dll", "GdipLoadImageFromFile", win32_gdiplus_write_result},
    {"gdiplus.dll", "GdipFree", win32_zero},
    {"gdiplus.dll", "GdipAlloc", win32_zero},
    {"comctl32.dll", "InitCommonControlsEx", win32_one},
    {"gdi32.dll", "CreateICA", win32_create_ica},
    {"kernel32.dll", "RaiseException", win32_raise_exception},
    {"kernel32.dll", "RtlUnwind", win32_rtl_unwind},
    {"ole32.dll", "CoCreateInstance", win32_co_create_instance},
    {"shlwapi.dll", "PathFindFileNameW", win32_path_find_filename_w},
    {"comdlg32.dll", "PrintDlgW", win32_zero},
    {"comdlg32.dll", "ChooseFontW", win32_zero},
    {"comdlg32.dll", "GetOpenFileNameW", win32_zero},
    {"comdlg32.dll", "PageSetupDlgW", win32_zero},
    {"comdlg32.dll", "GetSaveFileNameW", win32_zero},
    {"shell32.dll", "DragQueryFileW", win32_zero},
    {"shell32.dll", "DragFinish", win32_zero},
    {"shell32.dll", "DragAcceptFiles", win32_zero},
    {"shell32.dll", "ExtractIconExW", win32_zero},
    {"user32.dll", "GetKeyState", win32_zero},
    {"user32.dll", "LoadAcceleratorsW", win32_zero},
    {"user32.dll", "TranslateAcceleratorW", win32_zero},
    {"user32.dll", "GetMenu", win32_zero},
    {"user32.dll", "CheckMenuItem", win32_zero},
    {"user32.dll", "GetMenuItemCount", win32_zero},
    {"user32.dll", "GetMenuItemInfoW", win32_zero},
    {"user32.dll", "DrawTextW", win32_zero},
    {"user32.dll", "GetWindowDC", msvcrt_get_dc},
    {"user32.dll", "ModifyMenuW", win32_zero},
    {"user32.dll", "GetSysColorBrush", win32_zero},
    {"user32.dll", "DefDlgProcW", win32_zero},
    {"user32.dll", "GetDlgItem", win32_zero},
    {"user32.dll", "SetLayeredWindowAttributes", win32_one},
    {"user32.dll", "GetWindow", win32_zero},
    {"user32.dll", "GetClassNameW", win32_zero},
    {"user32.dll", "InflateRect", win32_one},
    {"user32.dll", "FrameRect", win32_one},
    {"user32.dll", "DrawFocusRect", win32_one},
    {"user32.dll", "GetWindowTextW", win32_zero},
    {"user32.dll", "EndDialog", win32_one},
    {"user32.dll", "IsWindow", win32_one},
    {"user32.dll", "MoveWindow", win32_one},
    {"advapi32.dll", "RegOpenKeyExW", win32_registry_not_found},
    {"advapi32.dll", "RegCreateKeyExW", win32_registry_not_found},
    {"advapi32.dll", "RegQueryValueExW", win32_registry_not_found},
    {"advapi32.dll", "RegSetValueExW", win32_registry_not_found},
    {"advapi32.dll", "RegCloseKey", win32_zero},
    // libstdc++, cdecl: the caller pops.
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", cxx_ifstream_construct},
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE5closeEv", cxx_file_stream_close},
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEE7is_openEv", cxx_file_stream_is_open},
    {"libstdc++-6.dll", "_ZNSt14basic_ifstreamIcSt11char_traitsIcEED1Ev", cxx_file_stream_close},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEEC1EPKcSt13_Ios_Openmode", cxx_ofstream_construct},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEE5closeEv", cxx_file_stream_close},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEE7is_openEv", cxx_file_stream_is_open},
    {"libstdc++-6.dll", "_ZNSt14basic_ofstreamIcSt11char_traitsIcEED1Ev", cxx_file_stream_close},
    {"libstdc++-6.dll", "__gxx_personality_v0", cxx_exception_trap},
    {"libstdc++-6.dll", "__gxx_personality_sj0", cxx_exception_trap},
    {"libstdc++-6.dll", "__cxa_begin_catch", cxx_exception_trap},
    {"libstdc++-6.dll", "__cxa_end_catch", cxx_exception_trap},
    {"libstdc++-6.dll", "__cxa_rethrow", cxx_exception_trap},
    {"libgcc_s_dw2-1.dll", "_Unwind_Resume", cxx_exception_trap},
    {"libgcc_s_dw2-1.dll", "__register_frame_info", cxx_noop},
    {"libgcc_s_dw2-1.dll", "__deregister_frame_info", cxx_noop},
    {"libstdc++-6.dll", "_ZSt4cout", cxx_cout_address},
    {"libstdc++-6.dll", "_ZSt3cin", cxx_cin_address},
    {"libstdc++-6.dll", "_ZNSaIcEC1Ev", cxx_noop},
    {"libstdc++-6.dll", "_ZNSaIcED1Ev", cxx_noop},
    {"libstdc++-6.dll", "_ZNSt8ios_base4InitC1Ev", cxx_noop},
    {"libstdc++-6.dll", "_ZNSt8ios_base4InitD1Ev", cxx_noop},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev", cxx_string_default_construct},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_", cxx_string_construct_from_c},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1ERKS4_", cxx_string_copy_construct},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev", cxx_string_destruct},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_", cxx_string_assign_from},
    {"libstdc++-6.dll", "_Znwj", cxx_operator_new},
    {"libstdc++-6.dll", "_Znaj", cxx_operator_new_array},
    {"libstdc++-6.dll", "_ZdlPv", cxx_operator_delete},
    {"libstdc++-6.dll", "_ZdaPv", cxx_operator_delete},
    {"libstdc++-6.dll", "_ZSt17__throw_bad_allocv", cxx_throw_bad_alloc},
    {"libstdc++-6.dll", "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc", cxx_ostream_put_c_string},
    {"libstdc++-6.dll", "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE", cxx_ostream_put_string},
    {"libstdc++-6.dll", "_ZNSolsEi", cxx_ostream_put_int},
    {"libstdc++-6.dll", "_ZNSirsERi", cxx_istream_get_int},
    {"libstdc++-6.dll", "_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE", cxx_istream_get_string},
    {"libstdc++-6.dll", "_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3_", cxx_istream_get_char},
    {"kernel32.dll", "Beep", win32_console_success},
    {"kernel32.dll", "SetConsoleCursorPosition", win32_console_success},
    {"kernel32.dll", "SetConsoleTextAttribute", win32_console_success},
    {"kernel32.dll", "SetConsoleCursorInfo", win32_console_success},
    {"kernel32.dll", "GetConsoleMode", win32_get_console_mode},
    {"kernel32.dll", "SetConsoleMode", win32_set_console_mode},
    {"kernel32.dll", "WriteConsoleA", win32_write_console_a},
    {"kernel32.dll", "WriteConsoleW", win32_write_console_w},
    {"kernel32.dll", "FindFirstFileA", win32_find_first_file_a},
    {"kernel32.dll", "FindNextFileA", win32_find_next_file_a},
    {"kernel32.dll", "FindClose", win32_find_close},
    {"kernel32.dll", "GetProcessHeap", win32_get_process_heap},
    {"kernel32.dll", "GetVersionExA", win32_get_version_ex_a},
    {"kernel32.dll", "GetFileType", win32_get_file_type},
    {"kernel32.dll", "GetEnvironmentStringsW", win32_get_environment_strings_w},
    {"kernel32.dll", "HeapReAlloc", win32_heap_realloc},
    {"kernel32.dll", "HeapSize", win32_heap_size},
    {"kernel32.dll", "DebugBreak", win32_debug_break},
    {"kernel32.dll", "GetStringTypeA", win32_get_string_type_a},
    {"kernel32.dll", "GetStringTypeW", win32_get_string_type_w},
    {"kernel32.dll", "LCMapStringA", win32_lc_map_string_a},
    {"kernel32.dll", "LCMapStringW", win32_lc_map_string_w},
    {"kernel32.dll", "GetLocaleInfoA", win32_get_locale_info_a},
    {"comctl32.dll", "InitCommonControls", win32_one},
    {"comdlg32.dll", "GetOpenFileNameA", win32_zero},
    {"comdlg32.dll", "GetSaveFileNameA", win32_zero},
    {"comdlg32.dll", "PrintDlgA", win32_zero},
    {"gdi32.dll", "BitBlt", win32_one},
    {"gdi32.dll", "CreateCompatibleBitmap", win32_one},
    {"gdi32.dll", "CreateCompatibleDC", win32_one},
    {"gdi32.dll", "CreateFontA", win32_one},
    {"gdi32.dll", "CreateFontIndirectA", win32_one},
    {"gdi32.dll", "CreateHatchBrush", win32_one},
    {"gdi32.dll", "CreatePen", win32_one},
    {"gdi32.dll", "CreateSolidBrush", win32_one},
    {"gdi32.dll", "DeleteDC", win32_one},
    {"gdi32.dll", "DeleteObject", win32_one},
    {"gdi32.dll", "Ellipse", win32_one},
    {"gdi32.dll", "EndDoc", win32_one},
    {"gdi32.dll", "EndPage", win32_one},
    {"gdi32.dll", "ExtTextOutW", win32_one},
    {"gdi32.dll", "GetDeviceCaps", win32_zero},
    {"gdi32.dll", "GetStockObject", win32_one},
    {"gdi32.dll", "GetTextExtentPoint32A", win32_zero},
    {"gdi32.dll", "GetTextExtentPoint32W", win32_zero},
    {"gdi32.dll", "GetTextMetricsA", win32_zero},
    {"gdi32.dll", "IntersectClipRect", win32_one},
    {"gdi32.dll", "Polygon", win32_one},
    {"gdi32.dll", "Polyline", win32_one},
    {"gdi32.dll", "Rectangle", win32_one},
    {"gdi32.dll", "SelectClipRgn", win32_one},
    {"gdi32.dll", "SelectObject", win32_one},
    {"gdi32.dll", "SetBkMode", win32_one},
    {"gdi32.dll", "SetMapMode", win32_one},
    {"gdi32.dll", "SetPixel", win32_one},
    {"gdi32.dll", "SetTextColor", win32_one},
    {"gdi32.dll", "StartDocA", win32_one},
    {"gdi32.dll", "StartPage", win32_one},
    {"user32.dll", "AppendMenuA", win32_one},
    {"user32.dll", "BeginPaint", win32_one},
    {"user32.dll", "CheckDlgButton", win32_one},
    {"user32.dll", "CreateMenu", win32_one},
    {"user32.dll", "DefDlgProcA", win32_zero},
    {"user32.dll", "DestroyMenu", win32_one},
    {"user32.dll", "DrawMenuBar", win32_one},
    {"user32.dll", "EnableMenuItem", win32_one},
    {"user32.dll", "EndPaint", win32_one},
    {"user32.dll", "GetDlgItemTextA", win32_zero},
    {"user32.dll", "GetKeyboardState", win32_zero},
    {"user32.dll", "GetMenuItemRect", win32_zero},
    {"user32.dll", "GetSysColor", win32_zero},
    {"user32.dll", "IntersectRect", win32_one},
    {"user32.dll", "IsDlgButtonChecked", win32_zero},
    {"user32.dll", "OffsetRect", win32_one},
    {"user32.dll", "ReleaseCapture", win32_one},
    {"user32.dll", "SendDlgItemMessageA", win32_zero},
    {"user32.dll", "SetCapture", win32_one},
    {"user32.dll", "SetMenu", win32_one},
    {"user32.dll", "SetRect", win32_one},
    {"user32.dll", "SystemParametersInfoA", win32_zero},
    {"user32.dll", "UnionRect", win32_one},
    {"user32.dll", "WinHelpA", win32_zero},
    {"comctl32.dll", "#17", win32_zero},
    {"comctl32.dll", "InitCommonControls", win32_zero},
    // msvcrt: cdecl, so the caller pops and callee_cleans_stack is false below.
    {"msvcrt.dll", "_initterm", msvcrt_initterm},
    {"msvcrt.dll", "_initterm_e", msvcrt_initterm_e},
    {"msvcrt.dll", "__acrt_iob_func", msvcrt_acrt_iob_func},
    {"msvcrt.dll", "__stdio_common_vfprintf", msvcrt_stdio_common_vfprintf},
    {"msvcrt.dll", "__stdio_common_vfscanf", msvcrt_stdio_common_vfscanf},
    {"msvcrt.dll", "__stdio_common_vsscanf", msvcrt_stdio_common_vsscanf},
    {"msvcrt.dll", "memcmp", msvcrt_memcmp},
    {"vcruntime140.dll", "memcmp", msvcrt_memcmp},
    {"vcruntime140.dll", "memcpy", msvcrt_memcpy},
    {"vcruntime140.dll", "memset", msvcrt_memset},
    {"vcruntime140.dll", "strchr", msvcrt_strchr},
    {"vcruntime140.dll", "strrchr", msvcrt_strrchr},
    {"vcruntime140.dll", "__C_specific_handler", win32_zero},
    {"vcruntime140.dll", "__current_exception", win32_zero},
    {"vcruntime140.dll", "__current_exception_context", win32_zero},
    {"vcruntime140.dll", "memchr", msvcrt_memchr},
    {"kernel32.dll", "RtlCaptureContext", win32_zero},
    {"kernel32.dll", "RtlLookupFunctionEntry", win32_zero},
    {"kernel32.dll", "RtlVirtualUnwind", win32_zero},
    {"msvcrt.dll", "fflush", msvcrt_fflush},
    {"msvcrt.dll", "setvbuf", msvcrt_return_zero},
    {"msvcrt.dll", "_set_new_mode", msvcrt_return_zero},
    {"msvcrt.dll", "_configthreadlocale", msvcrt_return_zero},
    {"msvcrt.dll", "__setusermatherr", msvcrt_return_zero},
    {"msvcrt.dll", "_set_invalid_parameter_handler", msvcrt_return_zero},
    {"msvcrt.dll", "_configure_narrow_argv", msvcrt_return_zero},
    {"msvcrt.dll", "_initialize_narrow_environment", msvcrt_return_zero},
    {"msvcrt.dll", "_set_fmode", shim__set_fmode},
    {"msvcrt.dll", "_crt_atexit", msvcrt_register_atexit},
    {"msvcrt.dll", "_exit", msvcrt_exit_process},
    {"msvcrt.dll", "__p___argc", msvcrt_p_argc},
    {"msvcrt.dll", "__p___argv", msvcrt_p_argv},
    {"msvcrt.dll", "__p__commode", msvcrt_p_commode},
    {"msvcrt.dll", "__p__acmdln", msvcrt_p_acmdln},
    {"libgcc_s_sjlj-1.dll", "_Unwind_SjLj_Register", msvcrt_unwind_register},
    {"libgcc_s_sjlj-1.dll", "_Unwind_SjLj_Unregister", msvcrt_unwind_register},
    {"libgcc_s_sjlj-1.dll", "_Unwind_SjLj_Resume", cxx_exception_trap},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_disposeEv", cxx_string_dispose},
    {"libstdc++-6.dll", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE15_M_replace_coldEPcjPKcjj", cxx_string_replace_cold},
    {"libstdc++-6.dll", "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_i", cxx_ostream_insert},
    {"libstdc++-6.dll", "_ZSt19__throw_logic_errorPKc", cxx_throw_logic_error},
    {"libstdc++-6.dll", "_ZSt20__throw_length_errorPKc", cxx_throw_length_error},
    {"libstdc++-6.dll", "_ZdlPvj", cxx_operator_delete},
    {"msvcrt.dll", "system", msvcrt_system},
    {"msvcrt.dll", "time", msvcrt_time},
    {"msvcrt.dll", "_time64", msvcrt_time64},
    {"msvcrt.dll", "puts", msvcrt_puts},
    {"msvcrt.dll", "getchar", msvcrt_getchar},
    {"msvcrt.dll", "fgetc", msvcrt_fgetc},
    {"msvcrt.dll", "getc", msvcrt_fgetc},
    {"msvcrt.dll", "fgets", msvcrt_fgets},
    {"msvcrt.dll", "putchar", msvcrt_putchar},
    {"msvcrt.dll", "signal", msvcrt_signal},
    {"msvcrt.dll", "strcoll", msvcrt_strcoll},
    {"msvcrt.dll", "_stricoll", msvcrt_strcoll},
    {"msvcrt.dll", "_fullpath", msvcrt_fullpath},
    {"msvcrt.dll", "wcstombs", msvcrt_wcstombs},
    {"msvcrt.dll", "wcrtomb", msvcrt_wcrtomb},
    {"msvcrt.dll", "vfprintf", msvcrt_vfprintf},
    {"msvcrt.dll", "printf", msvcrt_printf},
    {"msvcrt.dll", "fprintf", msvcrt_fprintf},
    {"msvcrt.dll", "sprintf", msvcrt_sprintf},
    {"msvcrt.dll", "snprintf", msvcrt_snprintf},
    {"msvcrt.dll", "_snprintf", msvcrt_snprintf},
    {"msvcrt.dll", "_iob_func", msvcrt_iob_func},
    {"msvcrt.dll", "__iob_func", msvcrt_iob_func},
    {"msvcrt.dll", "__lconv_init", msvcrt_lconv_init},
    {"msvcrt.dll", "_lock", msvcrt_lock},
    {"msvcrt.dll", "_unlock", msvcrt_unlock},
    {"msvcrt.dll", "_amsg_exit", msvcrt_amsg_exit},
    {"msvcrt.dll", "strerror", msvcrt_strerror},
    {"msvcrt.dll", "isspace", msvcrt_isspace},
    {"msvcrt.dll", "clock", msvcrt_clock},
    {"msvcrt.dll", "getenv", msvcrt_getenv},
    {"msvcrt.dll", "memchr", msvcrt_memchr},
    {"msvcrt.dll", "isalpha", msvcrt_isalpha},
    {"msvcrt.dll", "isdigit", msvcrt_isdigit},
    {"msvcrt.dll", "isalnum", msvcrt_isalnum},
    {"msvcrt.dll", "isupper", msvcrt_isupper},
    {"msvcrt.dll", "islower", msvcrt_islower},
    {"msvcrt.dll", "ispunct", msvcrt_ispunct},
    {"msvcrt.dll", "isxdigit", msvcrt_isxdigit},
    {"msvcrt.dll", "iscntrl", msvcrt_iscntrl},
    {"msvcrt.dll", "sqrtf", msvcrt_sqrtf},
    {"msvcrt.dll", "roundf", msvcrt_roundf},
    {"msvcrt.dll", "floorf", msvcrt_floorf},
    {"msvcrt.dll", "ceilf", msvcrt_ceilf},
    {"msvcrt.dll", "fabsf", msvcrt_fabsf},
    {"msvcrt.dll", "sinf", msvcrt_sinf},
    {"msvcrt.dll", "cosf", msvcrt_cosf},
    {"msvcrt.dll", "pow", msvcrt_pow},
    {"msvcrt.dll", "atan2", msvcrt_atan2},
    {"msvcrt.dll", "fmod", msvcrt_fmod},
    {"msvcrt.dll", "qsort", msvcrt_qsort},
    {"msvcrt.dll", "_initialize_onexit_table", msvcrt_initialize_onexit_table},
    {"msvcrt.dll", "_register_onexit_function", msvcrt_register_onexit_function},
    {"msvcrt.dll", "_c_exit", msvcrt_c_exit},
    {"msvcrt.dll", "terminate", msvcrt_terminate},
    {"msvcrt.dll", "_wassert", msvcrt_wassert},
    {"msvcrt.dll", "_seh_filter_exe", msvcrt_seh_filter_exe},
    {"msvcrt.dll", "_register_thread_local_exe_atexit_callback", msvcrt_register_thread_local_exe_atexit_callback},
    {"msvcrt.dll", "isprint", msvcrt_isprint},
    {"msvcrt.dll", "_putenv", msvcrt_putenv},
    {"msvcrt.dll", "setbuf", msvcrt_setbuf},
    {"msvcrt.dll", "strpbrk", msvcrt_strpbrk},
    {"msvcrt.dll", "strtok", msvcrt_strtok},
    {"msvcrt.dll", "bsearch", msvcrt_bsearch},
    {"msvcrt.dll", "isgraph", msvcrt_isgraph},
    {"msvcrt.dll", "ldexp", msvcrt_ldexp},
    {"msvcrt.dll", "_isatty", msvcrt_isatty},
    {"msvcrt.dll", "_getpid", msvcrt_getpid},
    {"kernel32.dll", "FormatMessageA", win32_format_message_a},
    {"comctl32.dll", "InitCommonControls", win32_init_common_controls},
    {"comctl32.dll", "InitCommonControlsEx", win32_init_common_controls_ex},
    {"user32.dll", "RegisterClassA", msvcrt_register_class_a},
    {"user32.dll", "CreateWindowExA", msvcrt_create_window_ex_a},
    {"user32.dll", "DestroyWindow", msvcrt_destroy_window},
    {"user32.dll", "UnregisterClassA", msvcrt_unregister_class_a},
    {"user32.dll", "ShowWindow", msvcrt_show_window},
    {"user32.dll", "UpdateWindow", msvcrt_update_window},
    {"user32.dll", "InvalidateRect", msvcrt_invalidate_rect},
    {"user32.dll", "SetFocus", msvcrt_set_focus},
    {"user32.dll", "SetWindowPos", msvcrt_set_window_pos},
    {"user32.dll", "SetWindowTextA", msvcrt_set_window_text_a},
    {"user32.dll", "SetForegroundWindow", msvcrt_set_foreground_window},
    {"user32.dll", "ShowCursor", msvcrt_show_cursor},
    {"user32.dll", "AdjustWindowRect", msvcrt_adjust_window_rect},
    {"user32.dll", "ClientToScreen", msvcrt_client_to_screen},
    {"user32.dll", "SetWindowLongA", msvcrt_set_window_long_a},
    {"user32.dll", "GetWindowLongA", msvcrt_get_window_long_a},
    {"user32.dll", "PostQuitMessage", msvcrt_post_quit_message},
    {"user32.dll", "GetForegroundWindow", msvcrt_get_foreground_window},
    {"user32.dll", "GetDC", msvcrt_get_dc},
    {"user32.dll", "ReleaseDC", msvcrt_release_dc},
    {"user32.dll", "LoadIconA", msvcrt_load_icon_a},
    {"user32.dll", "LoadCursorA", msvcrt_load_cursor_a},
    {"user32.dll", "GetSystemMetrics", msvcrt_get_system_metrics},
    {"user32.dll", "GetClientRect", msvcrt_get_client_rect},
    {"user32.dll", "DefWindowProcA", msvcrt_def_window_proc_a},
    {"user32.dll", "PostMessageA", msvcrt_post_message_a},
    {"user32.dll", "GetMessageA", msvcrt_get_message_a},
    {"user32.dll", "PeekMessageA", msvcrt_peek_message_a},
    {"user32.dll", "DispatchMessageA", msvcrt_dispatch_message_a},
    {"user32.dll", "TranslateMessage", msvcrt_translate_message_a},
    {"user32.dll", "MessageBoxA", msvcrt_message_box_a},
    // ONLY the names that really exist. Windows suffixes a function with `A`/`W` when it
    // takes a STRING; `ShowWindow`, `GetDC`, `SetFocus` and `TranslateMessage` have no
    // wide twin at all, so registering `ShowWindowW` would add a symbol nothing imports
    // while looking like coverage.
    {"user32.dll", "LoadIconW", msvcrt_load_icon_w},
    {"user32.dll", "LoadCursorW", msvcrt_load_cursor_w},
    {"user32.dll", "SetWindowLongW", msvcrt_set_window_long_w},
    {"user32.dll", "SetWindowLongPtrW", msvcrt_set_window_long_w},
    {"user32.dll", "SetWindowLongPtrA", msvcrt_set_window_long_w},
    {"user32.dll", "GetWindowLongPtrA", msvcrt_get_window_long_w},
    {"user32.dll", "GetWindowLongW", msvcrt_get_window_long_w},
    {"user32.dll", "GetWindowLongPtrW", msvcrt_get_window_long_w},
    {"user32.dll", "PostMessageW", msvcrt_post_message_w},
    {"user32.dll", "GetMessageW", msvcrt_get_message_w},
    {"user32.dll", "PeekMessageW", msvcrt_peek_message_w},
    {"user32.dll", "DispatchMessageW", msvcrt_dispatch_message_w},
    {"user32.dll", "CreateWindowExW", msvcrt_create_window_ex_w},
    {"user32.dll", "RegisterClassExW", msvcrt_register_class_ex_w},
    {"user32.dll", "RegisterClassW", msvcrt_register_class_ex_w},
    {"user32.dll", "UnregisterClassW", msvcrt_unregister_class_w},
    {"user32.dll", "SetWindowTextW", msvcrt_set_window_text_w},
    {"user32.dll", "GetWindowTextW", msvcrt_get_window_text_w},
    {"user32.dll", "MessageBoxW", msvcrt_message_box_w},
    {"msvcrt.dll", "vsprintf", msvcrt_vsprintf},
    {"msvcrt.dll", "_vsnprintf", msvcrt_vsnprintf},
    {"msvcrt.dll", "vsnprintf", msvcrt_vsnprintf},
    {"msvcrt.dll", "_vscprintf", msvcrt_vscprintf},
    {"msvcrt.dll", "__stdio_common_vsprintf", msvcrt_stdio_common_vsprintf},
    {"msvcrt.dll", "cos", msvcrt_cos},
    {"msvcrt.dll", "acos", msvcrt_acos},
    {"msvcrt.dll", "sin", msvcrt_sin},
    {"msvcrt.dll", "sqrt", msvcrt_sqrt},
    {"msvcrt.dll", "log", msvcrt_log},
    {"msvcrt.dll", "exp", msvcrt_exp},
    {"msvcrt.dll", "fabs", msvcrt_fabs},
    {"msvcrt.dll", "atan", msvcrt_atan},
    {"msvcrt.dll", "tan", msvcrt_tan},
    {"msvcrt.dll", "floor", msvcrt_floor},
    {"msvcrt.dll", "ceil", msvcrt_ceil},
    {"msvcrt.dll", "strspn", msvcrt_strspn},
    {"msvcrt.dll", "strcspn", msvcrt_strcspn},
    {"msvcrt.dll", "wcslen", msvcrt_wcslen},
    {"msvcrt.dll", "_assert", msvcrt_assert},
    {"msvcrt.dll", "MulDiv", msvcrt_muldiv},
    {"kernel32.dll", "MulDiv", msvcrt_muldiv},
    {"kernel32.dll", "GlobalAlloc", msvcrt_global_alloc},
    {"kernel32.dll", "GlobalLock", msvcrt_global_lock},
    {"kernel32.dll", "GlobalUnlock", msvcrt_global_unlock},
    {"kernel32.dll", "GlobalFree", msvcrt_global_free},
    {"kernel32.dll", "LocalFree", msvcrt_local_free},
    {"msvcrt.dll", "__getmainargs", msvcrt_getmainargs},
    {"msvcrt.dll", "strlen", msvcrt_strlen},
    {"msvcrt.dll", "strcmp", msvcrt_strcmp},
    {"msvcrt.dll", "strncmp", msvcrt_strncmp},
    {"msvcrt.dll", "strcpy", msvcrt_strcpy},
    {"msvcrt.dll", "strncpy", msvcrt_strncpy},
    {"msvcrt.dll", "strcat", msvcrt_strcat},
    {"msvcrt.dll", "strchr", msvcrt_strchr},
    {"msvcrt.dll", "strrchr", msvcrt_strrchr},
    {"msvcrt.dll", "strstr", msvcrt_strstr},
    {"msvcrt.dll", "strtol", msvcrt_strtol},
    {"msvcrt.dll", "strtoul", msvcrt_strtoul},
    {"msvcrt.dll", "strtoll", msvcrt_strtoll},
    {"msvcrt.dll", "_strtoi64", msvcrt_strtoll},
    {"msvcrt.dll", "_strtoui64", msvcrt_strtoull},
    {"msvcrt.dll", "strtoull", msvcrt_strtoull},
    {"msvcrt.dll", "strtod", msvcrt_strtod},
    {"msvcrt.dll", "atof", msvcrt_atof},
    {"msvcrt.dll", "atol", msvcrt_atol},
    {"msvcrt.dll", "atoi", msvcrt_atoi},
    {"msvcrt.dll", "toupper", msvcrt_toupper},
    {"msvcrt.dll", "tolower", msvcrt_tolower},
    {"msvcrt.dll", "_stricmp", msvcrt_stricmp},
    {"msvcrt.dll", "_strcmpi", msvcrt_stricmp},
    {"msvcrt.dll", "_errno", msvcrt_errno},
    {"msvcrt.dll", "__p__environ", msvcrt_p_environ},
    {"msvcrt.dll", "__p__fmode", msvcrt_p_fmode},
    {"msvcrt.dll", "_iob", msvcrt_iob_pointer},
    {"msvcrt.dll", "_pctype", msvcrt_pctype},
    {"msvcrt.dll", "__mb_cur_max", msvcrt_mb_cur_max},
    {"msvcrt.dll", "___mb_cur_max_func", msvcrt_mb_cur_max_func},
    {"msvcrt.dll", "malloc", msvcrt_malloc},
    {"msvcrt.dll", "calloc", msvcrt_calloc},
    {"msvcrt.dll", "realloc", msvcrt_realloc},
    {"msvcrt.dll", "free", msvcrt_free},
    {"msvcrt.dll", "memcpy", msvcrt_memcpy},
    {"msvcrt.dll", "memmove", msvcrt_memmove},
    {"msvcrt.dll", "memset", msvcrt_memset},
    {"msvcrt.dll", "_strdup", msvcrt_strdup},
    {"msvcrt.dll", "srand", msvcrt_srand},
    {"msvcrt.dll", "rand", msvcrt_rand},
    {"msvcrt.dll", "fwrite", msvcrt_fwrite},
    {"msvcrt.dll", "__set_app_type", msvcrt_noop},
    {"msvcrt.dll", "_set_app_type", msvcrt_noop},
    {"msvcrt.dll", "_fpreset", msvcrt_noop},
    {"msvcrt.dll", "_setmode", msvcrt_noop},
    {"msvcrt.dll", "atexit", msvcrt_register_atexit},
    {"msvcrt.dll", "_onexit", msvcrt_onexit},
    {"msvcrt.dll", "_cexit", msvcrt_cexit},
    {"msvcrt.dll", "_getch", msvcrt_noop},
    {"msvcrt.dll", "_kbhit", msvcrt_noop},
    {"msvcrt.dll", "abort", msvcrt_abort},
    {"msvcrt.dll", "exit", msvcrt_exit},
    {"msvcrt.dll", "_isctype", msvcrt_isctype},
    {"msvcrt.dll", "wctype", msvcrt_wctype},
    {"msvcrt.dll", "iswctype", msvcrt_iswctype},
    {"msvcrt.dll", "mbstowcs", msvcrt_mbstowcs},
    {"msvcrt.dll", "mbrtowc", msvcrt_mbrtowc},
    {"msvcrt.dll", "mbsrtowcs", msvcrt_mbsrtowcs},
    {"msvcrt.dll", "setlocale", msvcrt_setlocale},
    {"ole32.dll", "CoInitialize", win32_co_initialize},
    {"ole32.dll", "CoUninitialize", win32_co_uninitialize},
    {"kernel32.dll", "OutputDebugStringA", win32_output_debug_string_a},
    {"kernel32.dll", "OutputDebugStringW", win32_output_debug_string_w},
    {"kernel32.dll", "GetDriveTypeA", win32_get_drive_type_a},
    {"kernel32.dll", "CompareFileTime", win32_compare_file_time},
    {"kernel32.dll", "CloseHandle", win32_close_handle},
    {"kernel32.dll", "SetStdHandle", win32_set_std_handle},
    {"kernel32.dll", "CreateMutexA", win32_create_mutex_a},
    {"kernel32.dll", "CreateEventA", win32_create_event_a},
    {"kernel32.dll", "SetEvent", win32_set_event},
    {"kernel32.dll", "ResetEvent", win32_reset_event},
    {"kernel32.dll", "CreateSemaphoreA", win32_create_semaphore_a},
    {"kernel32.dll", "ReleaseSemaphore", win32_release_semaphore},
    {"kernel32.dll", "WaitForSingleObject", win32_wait_for_single_object},
    {"kernel32.dll", "WaitForMultipleObjects", win32_wait_for_multiple_objects},
    {"kernel32.dll", "SetHandleCount", win32_set_handle_count},
    {"kernel32.dll", "DuplicateHandle", win32_duplicate_handle},
    {"kernel32.dll", "SetThreadPriority", win32_set_thread_priority},
    {"kernel32.dll", "GetThreadPriority", win32_get_thread_priority},
    {"kernel32.dll", "ReleaseMutex", win32_release_mutex},
    {"kernel32.dll", "FlushFileBuffers", win32_flush_file_buffers},
    {"kernel32.dll", "FreeEnvironmentStringsW", win32_free_environment_strings_w},
    {"kernel32.dll", "GetEnvironmentVariableA", win32_get_environment_variable_a},
    {"kernel32.dll", "GetCPInfo", win32_get_cp_info},
    {"kernel32.dll", "HeapCreate", win32_heap_create},
    {"kernel32.dll", "HeapAlloc", win32_heap_alloc},
    {"kernel32.dll", "HeapFree", win32_heap_free},
    {"kernel32.dll", "HeapDestroy", win32_one},
    {"kernel32.dll", "Sleep", win32_ignore},
    {"kernel32.dll", "GetTickCount", win32_get_tick_count},
    {"kernel32.dll", "GetTickCount64", win32_get_tick_count},
    {"kernel32.dll", "QueryPerformanceCounter", win32_query_performance_counter},
    {"kernel32.dll", "QueryPerformanceFrequency", win32_query_performance_frequency},
    {"kernel32.dll", "InitializeCriticalSection", win32_ignore},
    {"kernel32.dll", "DeleteCriticalSection", win32_ignore},
    {"kernel32.dll", "EnterCriticalSection", win32_ignore},
    {"kernel32.dll", "LeaveCriticalSection", win32_ignore},
    {"kernel32.dll", "InitializeCriticalSectionAndSpinCount", win32_one},
    {"kernel32.dll", "InitializeCriticalSectionEx", win32_one},
    {"kernel32.dll", "InitializeSListHead", win32_ignore},
    {"kernel32.dll", "GetSystemTimeAsFileTime", win32_get_system_time_as_file_time},
    {"kernel32.dll", "GetStartupInfoA", win32_get_startup_info},
    {"kernel32.dll", "GetStartupInfoW", win32_get_startup_info_w},
    {"api-ms-win-crt-runtime-l1-1-0.dll", "_get_narrow_winmain_command_line", win32_get_command_line},
    {"kernel32.dll", "GetCommandLineA", win32_get_command_line},
    {"kernel32.dll", "GetCommandLineW", win32_get_command_line_w},
    {"kernel32.dll", "GetEnvironmentStrings", win32_get_environment_strings},
    {"kernel32.dll", "FreeEnvironmentStringsA", win32_one},
    {"kernel32.dll", "lstrlenA", win32_lstrlen_a},
    {"kernel32.dll", "lstrlenW", win32_lstrlen_w},
    {"kernel32.dll", "lstrcpyA", win32_lstrcpy_a},
    {"kernel32.dll", "GetACP", win32_code_page},
    {"kernel32.dll", "IsValidCodePage", win32_one},
    {"kernel32.dll", "GetLocalTime", win32_get_local_time},
    {"kernel32.dll", "IsDBCSLeadByte", win32_is_dbcs_lead_byte},
    {"kernel32.dll", "GetOEMCP", win32_code_page},
    {"kernel32.dll", "GetConsoleOutputCP", win32_code_page},
    {"kernel32.dll", "SetConsoleOutputCP", win32_one},
    {"kernel32.dll", "GetVersion", win32_get_version},
    {"kernel32.dll", "GetSystemInfo", win32_get_system_info},
    {"kernel32.dll", "FlsAlloc", win32_zero},
    {"kernel32.dll", "FlsFree", win32_one},
    {"kernel32.dll", "FlsSetValue", win32_one},
    {"kernel32.dll", "FlsGetValue", win32_zero},
    {"kernel32.dll", "FlsGetValue2", win32_zero},
    {"kernel32.dll", "TlsAlloc", win32_zero},
    {"kernel32.dll", "TlsFree", win32_one},
    {"kernel32.dll", "TlsSetValue", win32_one},
    {"kernel32.dll", "TlsGetValue", win32_zero},
    {"kernel32.dll", "WideCharToMultiByte", win32_zero},
    {"kernel32.dll", "MultiByteToWideChar", win32_zero},
    {"kernel32.dll", "GetProcAddress", win32_get_proc_address},
    {"kernel32.dll", "LoadLibraryA", win32_load_library_a},
    {"kernel32.dll", "LoadLibraryW", win32_load_library_w},
    {"kernel32.dll", "LoadLibraryExW", win32_load_library_w},
    {"kernel32.dll", "FreeLibrary", win32_free_library},
    // kernel32 file services, all of which go through the handle table and the
    // app-directory policy rather than touching a host path directly.
    {"kernel32.dll", "CreateFileA", shim_CreateFileA},
    {"kernel32.dll", "CreateFileW", shim_CreateFileW},
    {"kernel32.dll", "SetFilePointer", shim_SetFilePointer},
    {"kernel32.dll", "SetFilePointerEx", shim_SetFilePointerEx},
    {"kernel32.dll", "GetFileSize", shim_GetFileSize},
    {"kernel32.dll", "GetFileSizeEx", shim_GetFileSizeEx},
    {"kernel32.dll", "SetEndOfFile", win32_set_end_of_file},
    {"kernel32.dll", "DeleteFileA", shim_DeleteFileA},
    {"kernel32.dll", "DeleteFileW", shim_DeleteFileW},
    {"kernel32.dll", "CreateDirectoryA", shim_CreateDirectoryA},
    {"kernel32.dll", "CreateDirectoryW", shim_CreateDirectoryW},
    {"kernel32.dll", "RemoveDirectoryA", shim_RemoveDirectoryA},
    {"kernel32.dll", "RemoveDirectoryW", shim_RemoveDirectoryW},
    {"kernel32.dll", "MoveFileA", shim_MoveFileA},
    {"kernel32.dll", "MoveFileW", shim_MoveFileW},
    {"kernel32.dll", "MoveFileExA", shim_MoveFileExA},
    {"kernel32.dll", "MoveFileExW", shim_MoveFileExW},
    {"kernel32.dll", "GetFileAttributesA", shim_GetFileAttributesA},
    {"kernel32.dll", "GetFileAttributesW", shim_GetFileAttributesW},
    {"kernel32.dll", "GetModuleFileNameA", shim_GetModuleFileNameA},
    {"kernel32.dll", "GetModuleFileNameW", shim_GetModuleFileNameW},
    {"kernel32.dll", "GetDiskFreeSpaceA", win32_get_disk_free_space},
    {"kernel32.dll", "GetDiskFreeSpaceW", win32_get_disk_free_space},
    // The CRT stream family: FILE*, its descriptor, and the handle it came from,
    // all three of which a real program mixes freely.
    {"msvcrt.dll", "fopen", shim_fopen},
    {"msvcrt.dll", "_wfopen", shim__wfopen},
    {"msvcrt.dll", "_fsopen", shim__fsopen},
    {"msvcrt.dll", "fclose", msvcrt_fclose},
    {"msvcrt.dll", "fread", shim_fread},
    {"msvcrt.dll", "fseek", shim_fseek},
    {"msvcrt.dll", "_fseeki64", shim__fseeki64},
    {"msvcrt.dll", "ftell", msvcrt_ftell},
    {"msvcrt.dll", "feof", msvcrt_feof},
    {"msvcrt.dll", "ferror", msvcrt_ferror},
    {"msvcrt.dll", "clearerr", msvcrt_clearerr},
    {"msvcrt.dll", "rewind", msvcrt_rewind},
    {"msvcrt.dll", "fgetc", shim_fgetc},
    {"msvcrt.dll", "getc", shim_getc},
    {"msvcrt.dll", "fputc", shim_fputc},
    {"msvcrt.dll", "putc", shim_putc},
    {"msvcrt.dll", "fgets", msvcrt_fgets},
    {"msvcrt.dll", "fputs", msvcrt_fputs},
    {"msvcrt.dll", "ungetc", msvcrt_ungetc},
    {"msvcrt.dll", "_fileno", msvcrt_fileno},
    {"msvcrt.dll", "_open", shim__open},
    {"msvcrt.dll", "_wopen", shim__wopen},
    {"msvcrt.dll", "_close", msvcrt_close},
    {"msvcrt.dll", "_read", shim__read},
    {"msvcrt.dll", "_write", shim__write},
    {"msvcrt.dll", "_lseek", msvcrt_lseek},
    {"msvcrt.dll", "_open_osfhandle", msvcrt_open_osfhandle},
    {"msvcrt.dll", "_fdopen", shim__fdopen},
    {"msvcrt.dll", "_wfdopen", shim__wfdopen},
    {"msvcrt.dll", "remove", shim_remove},
    {"msvcrt.dll", "rename", shim_rename},
};

}  // namespace

// External linkage: the differential reference uses this to run the handlers, and it
// has no compiled code of its own.
const std::vector<std::uint64_t>& registered_atexit_handlers() { return guest_atexit_handlers; }

// ---- guest memory watchpoint ---------------------------------------------
std::uint64_t watched_guest_address = 0;
static bool watch_reported = false;

void note_watched_write(const GuestContext* context, std::uint64_t address, int width) {
  if (watched_guest_address == 0 || watch_reported) return;
  if (watched_guest_address < address ||
      watched_guest_address >= address + static_cast<std::uint64_t>(width))
    return;
  watch_reported = true;
  std::fprintf(stderr,
               "watch: write of %d byte(s) at 0x%llx covers 0x%llx from guest ip 0x%llx\n",
               width, static_cast<unsigned long long>(address),
               static_cast<unsigned long long>(watched_guest_address),
               static_cast<unsigned long long>(context != nullptr ? context->instruction_pointer : 0));
}

void report_guest_memory_fault(GuestContext* context, std::uint64_t address, int width, int is_write) {
  terminate_with_message("guest %s fault at 0x%" PRIx64 " (width %d) ip=0x%" PRIx64 "; %s",
                         is_write ? "write" : "read", address, width, context->instruction_pointer,
                         describe_registers(context).c_str());
}
// The candidate's instruction budget. The reference has had one since it was written
// (`instruction budget exhausted before ExitProcess`); the candidate had none, so a
// program that never terminates hung verification instead of reporting anything.
std::uint64_t guest_instruction_budget = 0;

void note_executed_instruction() {
  if (guest_instruction_budget == 0) return;
  if (++guest_executed_instructions <= guest_instruction_budget) return;
  // A dedicated marker, so the harness does not have to recognise a MESSAGE. Searching
  // stderr for "instruction budget" made the verdict depend on wording: rewording this
  // line, or a program that happened to print the same phrase, would change whether a
  // truncated run was reported as truncated.
  if (const char* marker = std::getenv("RECOMP_TRUNCATION_MARKER")) {
    if (std::FILE* file = std::fopen(marker, "w")) {
      std::fprintf(file, "%llu\n", static_cast<unsigned long long>(guest_executed_instructions));
      std::fclose(file);
    }
  }
  terminate_with_message("instruction budget exhausted after %llu guest instructions",
                         static_cast<unsigned long long>(guest_executed_instructions));
}

void recomp_trap(GuestContext* context, const char* reason) {
  terminate_with_message("trap '%s' at ip=0x%" PRIx64, reason, context->instruction_pointer);
}
void recomp_unsupported(GuestContext* context, const char* reason) {
  terminate_with_message("unsupported: %s (ip=0x%" PRIx64 ")", reason, context->instruction_pointer);
}
void report_divide_error(GuestContext* context) {
  terminate_with_message("divide error at ip=0x%" PRIx64, context->instruction_pointer);
}

const ShimDescriptor* find_win32_shim(const char* library_name, const char* symbol_name) {
  // Windows API-set DLLs forward core process/thread/heap exports to kernel32.
  // Preserve that forwarding behavior for GetProcAddress probes instead of
  // requiring one duplicate table row for every API-set spelling.
  if (library_name != nullptr &&
      (std::strncmp(library_name, "api-ms-win-core-", 16) == 0 ||
       std::strncmp(library_name, "ext-ms-win-", 11) == 0)) {
    if (const auto* found = find_win32_shim("kernel32.dll", symbol_name)) return found;
  }
  // The Universal CRT's API sets carry the standard C library symbols, so a name
  // that is not found under an api-ms-win-crt-* library is retried as msvcrt.
  if (win32_is_universal_crt_library(library_name)) {
    if (const auto* found = find_win32_shim("msvcrt.dll", symbol_name)) return found;
  }
  for (const auto& shim : kShims) {
    if (std::strcmp(shim.library_name, library_name) == 0 && std::strcmp(shim.symbol_name, symbol_name) == 0)
      return &shim;
  }
  return nullptr;
}

bool lookup_win32_import(const char* library_name, const char* symbol_name, void (**function)(GuestContext*)) {
  const auto* shim = find_win32_shim(library_name, symbol_name);
  if (shim == nullptr) return false;
  *function = shim->function;
  return true;
}

bool register_import_thunk(std::uint64_t address, void (*function)(GuestContext*),
                           const char* library_name, const char* symbol_name) {
  import_thunk_addresses.push_back(address);
  import_thunk_functions.push_back(function);
  import_thunk_libraries.emplace_back(library_name != nullptr ? library_name : "");
  import_thunk_symbols.emplace_back(symbol_name != nullptr ? symbol_name : "");
  return true;
}

void signed_multiply_single(GuestContext* context, std::uint64_t operand, int width) {
  if (width >= 8) {
    const auto wide = multiply_wide(context->registers[0], operand);
    // SIGNED overflow: the high half must be the sign extension of the low half.
    const std::uint64_t sign_fill = (wide.low >> 63) != 0 ? ~0ull : 0ull;
    context->registers[0] = wide.low;
    context->registers[2] = wide.high;
    context->carry_flag = context->overflow_flag =
        wide.high != sign_fill;
    context->auxiliary_flag = 0;
    update_zero_sign_parity(context, context->registers[0], 8);
    return;
  }
  const auto product = sign_extend(context->registers[0], width) * sign_extend(operand, width);
  const auto mask = value_mask(width);
  context->registers[0] = static_cast<std::uint64_t>(product) & mask;
  context->registers[2] = (static_cast<std::uint64_t>(product) >> (width * 8)) & mask;
  context->carry_flag = context->overflow_flag = product != sign_extend(context->registers[0], width);
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, context->registers[0], width);
}

std::uint64_t signed_multiply_two(GuestContext* context, std::uint64_t left, std::uint64_t right, int width) {
  const auto left_value = sign_extend(left, width);
  const auto right_value = sign_extend(right, width);
  if (width >= 8) {
    const auto wide = multiply_wide(left_value, right_value);
    const auto result = wide.low;
    const std::uint64_t sign_fill = (result >> 63) != 0 ? ~0ull : 0ull;
    context->carry_flag = context->overflow_flag = wide.high != sign_fill;
    context->auxiliary_flag = 0;
    update_zero_sign_parity(context, result, 8);
    return result;
  }
  const auto product = left_value * right_value;
  const auto mask = value_mask(width);
  const auto result = static_cast<std::uint64_t>(product) & mask;
  context->carry_flag = context->overflow_flag = product != sign_extend(result, width);
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, result, width);
  return result;
}

void unsigned_multiply_single(GuestContext* context, std::uint64_t operand, int width) {
  const auto mask = value_mask(width);
  const auto left = context->registers[0] & mask;
  const auto right = operand & mask;
  const auto wide = multiply_wide(left, right);
  const auto product = wide.low;
  context->registers[0] = static_cast<std::uint64_t>(product) & mask;
  context->registers[2] = static_cast<std::uint64_t>(product >> (width * 8)) & mask;
  context->carry_flag = context->overflow_flag = (product >> (width * 8)) != 0;
  context->auxiliary_flag = 0;
  update_zero_sign_parity(context, context->registers[0], width);
}

void unsigned_divide(GuestContext* context, std::uint64_t divisor, int width) {
  const auto mask = value_mask(width);
  if ((divisor & mask) == 0) { report_divide_error(context); return; }
  if (width >= 8) {
    const auto wide = divide_wide(context->registers[2], context->registers[0], divisor);
    // A quotient that does not fit is #DE on x86, which `report_divide_error` already models.
    if (wide.overflow) { report_divide_error(context); return; }
    context->registers[0] = wide.quotient;
    context->registers[2] = wide.remainder;
    return;
  }
  const auto dividend = ((context->registers[2] & mask) << (width * 8)) | (context->registers[0] & mask);
  context->registers[0] = (dividend / (divisor & mask)) & mask;
  context->registers[2] = (dividend % (divisor & mask)) & mask;
}

void signed_divide(GuestContext* context, std::uint64_t divisor, int width) {
  const auto divisor_value = sign_extend(divisor, width);
  if (divisor_value == 0) { report_divide_error(context); return; }
  const auto mask = value_mask(width);
  if (width >= 8) {
    const auto wide = divide_wide_signed(context->registers[2], context->registers[0], divisor);
    if (wide.overflow) { report_divide_error(context); return; }
    context->registers[0] = wide.quotient;
    context->registers[2] = wide.remainder;
    return;
  }
  const auto high = sign_extend(context->registers[2], width);
  const auto low = context->registers[0] & mask;
  const auto dividend = (static_cast<std::uint64_t>(high) << (width * 8)) | low;
  const auto wide = divide_wide_signed(high < 0 ? ~0ull : 0ull, dividend,
                                       static_cast<std::uint64_t>(divisor_value));
  if (wide.overflow) { report_divide_error(context); return; }
  context->registers[0] = wide.quotient & mask;
  context->registers[2] = wide.remainder & mask;
}


void string_move(GuestContext* context, int element_size, int repeat) {
  const int step = context->direction_flag ? -element_size : element_size;
  const std::uint64_t count = repeat ? context->registers[1] : 1;
  for (std::uint64_t index = 0; index < count; ++index) {
    const auto value = load_guest_memory(context, context->registers[6], element_size);
    store_guest_memory(context, context->registers[7], value, element_size);
    context->registers[6] += step;
    context->registers[7] += step;
  }
  if (repeat) context->registers[1] = 0;
}

void string_store(GuestContext* context, int element_size, int repeat) {
  const int step = context->direction_flag ? -element_size : element_size;
  const std::uint64_t count = repeat ? context->registers[1] : 1;
  for (std::uint64_t index = 0; index < count; ++index) {
    store_guest_memory(context, context->registers[7], context->registers[0], element_size);
    context->registers[7] += step;
  }
  if (repeat) context->registers[1] = 0;
}

void string_load(GuestContext* context, int element_size, int repeat) {
  const int step = context->direction_flag ? -element_size : element_size;
  const std::uint64_t count = repeat ? context->registers[1] : 1;
  for (std::uint64_t index = 0; index < count; ++index) {
    context->registers[0] = load_guest_memory(context, context->registers[6], element_size);
    context->registers[6] += step;
  }
  if (repeat) context->registers[1] = 0;
}

void string_scan(GuestContext* context, int element_size, int repeat) {
  const int step = context->direction_flag ? -element_size : element_size;
  const std::uint64_t count = repeat ? context->registers[1] : 1;
  for (std::uint64_t index = 0; index < count; ++index) {
    const auto value = load_guest_memory(context, context->registers[7], element_size);
    compare_with_flags(context, context->registers[0], value, element_size);
    context->registers[7] += step;
    if (repeat && context->zero_flag == 0) break;
  }
  if (repeat) context->registers[1] = 0;
}

void string_compare(GuestContext* context, int element_size, int repeat) {
  const int step = context->direction_flag ? -element_size : element_size;
  const std::uint64_t count = repeat ? context->registers[1] : 1;
  for (std::uint64_t index = 0; index < count; ++index) {
    const auto left = load_guest_memory(context, context->registers[6], element_size);
    const auto right = load_guest_memory(context, context->registers[7], element_size);
    compare_with_flags(context, left, right, element_size);
    context->registers[6] += step;
    context->registers[7] += step;
    if (repeat && context->zero_flag == 0) break;
  }
  if (repeat) context->registers[1] = 0;
}

void execute_cpuid(GuestContext* context) {
  const auto leaf = static_cast<std::uint32_t>(context->registers[0]);
  if (leaf == 0) {
    context->registers[0] = 1;
    context->registers[3] = 0x756e6547;  // "Genu"
    context->registers[2] = 0x49656e69;  // "ineI"
    context->registers[1] = 0x6c65746e;  // "ntel"
  } else if (leaf == 1) {
    context->registers[0] = 0x000106a5;
    context->registers[1] = 0;
    context->registers[2] = 0x00000201;
    context->registers[3] = 0x078bfbff;
  } else {
    context->registers[0] = context->registers[1] = context->registers[2] = context->registers[3] = 0;
  }
}

void invoke_guest_indirect(GuestContext* context, std::uint64_t target, std::uint64_t return_address) {
  if (auto function = lookup_guest_function(target)) {
    push_guest_stack(context, return_address);
    function(context);
    return;
  }
  const auto thunk = lookup_import_thunk(target);
  if (thunk >= 0) {
    // A `call` pushes a return address on both widths. On 32-bit the cleanup pass
    // then removes it along with the stdcall arguments; on 64-bit the return
    // address alone is popped. Either way the push is what hardware does.
    invoke_import_thunk(context, thunk, return_address, true);
    return;
  }
  // A bare target address is not actionable: the caller computed it, so the
  // registers that computed it are the diagnostic.
  terminate_with_message("indirect call to unmapped guest address 0x%" PRIx64 " (ip=0x%" PRIx64 "); %s", target,
                         context->instruction_pointer, describe_registers(context).c_str());
}

void jump_guest_indirect(GuestContext* context, std::uint64_t target) {
  if (auto function = lookup_guest_function(target)) { function(context); return; }
  const auto thunk = lookup_import_thunk(target);
  if (thunk >= 0) {
    invoke_import_thunk(context, thunk, 0, false);
    if (guest_pointer_width >= 8)
      context->registers[4] = mask_guest_address(context->registers[4] + 8);
    return;
  }
  terminate_with_message("indirect jump to unmapped guest address 0x%" PRIx64 " (ip=0x%" PRIx64 "); %s", target,
                         context->instruction_pointer, describe_registers(context).c_str());
}

// A `jmp [iat]` thunk is a tail call: the caller's own `call` already pushed the
// return address, so this path must NOT push another one. Pushing twice shifts
// every argument by one slot -- the shim reads the return address as its first
// argument and the first argument as its second, which for something like memcpy
// means a wild destination and a pointer-sized count.
// Sets the calling convention of the import about to run, so that a shim can ask
// for its arguments by index without knowing how it was reached.
void select_import_convention(const char* library_name, const char* symbol_name) {
  const auto* abi = win32_import_abi(library_name, symbol_name);
  win32_import_this_call() = abi != nullptr && abi->this_call;
}

void invoke_win32_import_tail(GuestContext* context, const char* library_name, const char* symbol_name) {
  const auto* shim = find_win32_shim(library_name, symbol_name);
  if (shim == nullptr) {
    terminate_with_message("unimplemented Win32 import %s!%s (ip=0x%" PRIx64 ")", library_name, symbol_name,
                           context->instruction_pointer);
  }
  select_import_convention(library_name, symbol_name);
  guest_in_shim = true;
  shim->function(context);
  guest_in_shim = false;
  if (guest_pointer_width >= 8) {
    context->registers[4] = mask_guest_address(context->registers[4] + 8);
    return;
  }
  // The return address is already at [esp], so the shim's `ret`/`ret n` is the
  // only stack adjustment left to emulate.
  context->registers[4] = mask_guest_address(
      context->registers[4] + win32_import_stack_cleanup(library_name, symbol_name));
}

void invoke_win32_import(GuestContext* context, const char* library_name, const char* symbol_name,
                         std::uint64_t return_address) {
  const auto* shim = find_win32_shim(library_name, symbol_name);
  if (shim == nullptr) {
    terminate_with_message("unimplemented Win32 import %s!%s (ip=0x%" PRIx64 ")", library_name, symbol_name,
                           context->instruction_pointer);
  }
  select_import_convention(library_name, symbol_name);
  if (guest_pointer_width >= 8) {
    guest_in_shim = true;
    shim->function(context);
    guest_in_shim = false;
    return;
  }
  // 32-bit x86: emulate the `call` and the matching `ret`/`ret n` so the guest
  // stack matches what real hardware would leave behind. cdecl leaves the
  // arguments for the caller to pop; stdcall pops them in the callee.
  context->registers[4] = mask_guest_address(context->registers[4] - 4);
  store_guest_memory(context, context->registers[4], return_address, 4);
  guest_in_shim = true;
  shim->function(context);
  guest_in_shim = false;
  context->registers[4] = mask_guest_address(
      context->registers[4] + win32_import_stack_cleanup(library_name, symbol_name));
}

namespace {

void unbound_import_thunk(GuestContext* context) {
  const auto& library = import_thunk_libraries[current_thunk_index];
  const auto& symbol = import_thunk_symbols[current_thunk_index];
  terminate_with_message("unimplemented Win32 import %s!%s (ip=0x%" PRIx64 ")",
                         library.c_str(), symbol.c_str(), context->instruction_pointer);
}

}  // namespace

// Allocates the guest address space without running anything. The differential
// reference uses this so that it and the runtime address the same bytes: it maps
// this buffer into the emulator rather than keeping a second copy, which is what
// lets one shim implementation serve both.
std::string* guest_output_capture = nullptr;

std::uint64_t guest_checkpoint_interval = 0;
std::vector<GuestCheckpoint> guest_checkpoints;
static std::uint64_t guest_checkpoint_counter = 0;

// Writes the captured checkpoints where the studio can read them. A generated
// executable runs as its own process, so the state it recorded has to cross a
// process boundary; the file is only written when RECOMP_CHECKPOINT names it.
void write_guest_checkpoints_if_requested() {
  const char* path = std::getenv("RECOMP_CHECKPOINT");
  if (path == nullptr || guest_checkpoints.empty()) return;
  std::FILE* file = std::fopen(path, "wb");
  if (file == nullptr) return;
  for (const auto& checkpoint : guest_checkpoints) {
    std::fprintf(file, "%llu %llu %llu %llu %u %u %u", static_cast<unsigned long long>(checkpoint.index),
                 static_cast<unsigned long long>(checkpoint.address),
                 static_cast<unsigned long long>(checkpoint.flags),
                 static_cast<unsigned long long>(checkpoint.memory_digest),
                 checkpoint.mxcsr, checkpoint.x87_control_word, checkpoint.x87_status_word);
    for (const auto value : checkpoint.registers)
      std::fprintf(file, " %llu", static_cast<unsigned long long>(value));
    std::fputc('\n', file);
  }
  std::fclose(file);
}

// FNV-1a over a byte range, which is enough to notice a difference and cheap
// enough to run every thousand instructions.
std::uint64_t digest_bytes(std::uint64_t seed, std::uint64_t address, std::uint64_t count) {
  if (guest_memory == nullptr || address >= guest_memory_size) return seed;
  if (address + count > guest_memory_size) count = guest_memory_size - address;
  std::uint64_t hash = seed;
  for (std::uint64_t offset = 0; offset < count; ++offset) {
    hash ^= guest_memory[address + offset];
    hash *= 1099511628211ull;
  }
  return hash;
}

bool guest_store_logging = false;
static std::FILE* guest_store_log = nullptr;

bool guest_in_shim = false;

void record_guest_store(std::uint64_t instruction_address, std::uint64_t address, std::uint64_t value, int width) {
  if (guest_store_log == nullptr) return;
  // A leading 's' marks a store a shim performed. The reference cannot log those --
  // its shim writes to guest_memory with a host memcpy, which the emulator never
  // observes -- so the comparison has to tell them apart rather than reading their
  // absence as a divergence.
  std::fprintf(guest_store_log, "%s%llx %llx %llx %d\n", guest_in_shim ? "s" : "",
               static_cast<unsigned long long>(instruction_address),
               static_cast<unsigned long long>(address), static_cast<unsigned long long>(value), width);
}

void record_guest_vector_store(std::uint64_t instruction_address, std::uint64_t address, int width) {
  if (guest_store_log == nullptr) return;
  // The value is a whole register, so the bytes are summarised rather than
  // printed; what the comparison needs is that a store of this width happened at
  // this address from this instruction.
  std::uint64_t digest = 14695981039346656037ull;
  for (int offset = 0; offset < width && address + offset < guest_memory_size; ++offset) {
    digest ^= guest_memory[address + offset];
    digest *= 1099511628211ull;
  }
  std::fprintf(guest_store_log, "%llx %llx v%llx %d\n", static_cast<unsigned long long>(instruction_address),
               static_cast<unsigned long long>(address), static_cast<unsigned long long>(digest), width);
}

std::FILE* guest_memory_windows = nullptr;

bool guest_mxcsr_logging = false;
static std::FILE* guest_mxcsr_log = nullptr;
static std::uint32_t guest_mxcsr_last = 0;

// The address of the instruction that last began, so a change observed at the start
// of instruction N can be attributed to N-1, which is the one that made it.
std::uint64_t guest_mxcsr_previous_address = 0;

void record_mxcsr_change(std::uint64_t address, std::uint32_t mxcsr) {
  (void)address;
  if (guest_mxcsr_log == nullptr || mxcsr == guest_mxcsr_last) return;
  guest_mxcsr_last = mxcsr;
  // The instruction that caused the change is the one before this call, not this
  // one: the value is read before the current instruction has run.
  std::fprintf(guest_mxcsr_log, "%llx %x\n",
               static_cast<unsigned long long>(guest_mxcsr_previous_address), mxcsr);
}

void open_guest_mxcsr_log(const char* path) {
  if (path == nullptr) return;
  guest_mxcsr_log = std::fopen(path, "w");
  guest_mxcsr_logging = guest_mxcsr_log != nullptr;
  // The starting value, so the first line is a change rather than a baseline.
  guest_mxcsr_last = 0xffffffffu;
}

void open_guest_memory_windows(const char* path) {
  if (path == nullptr) return;
  guest_memory_windows = std::fopen(path, "wb");
}

std::FILE* guest_dirty_page_log = nullptr;

void open_guest_dirty_page_log(const char* path) {
  if (path == nullptr || path[0] == '\0') return;
  guest_dirty_page_log = std::fopen(path, "w");
}

void open_guest_store_log(const char* path) {
  if (path == nullptr) return;
  guest_store_log = std::fopen(path, "w");
  guest_store_logging = guest_store_log != nullptr;
}

std::uint8_t* guest_page_dirty = nullptr;

std::uint64_t guest_memory_digest(const GuestContext* context) {
  // The window starts AT the stack pointer, not below it. Memory below the stack
  // pointer is dead: the program has moved past it and cannot read it again, and
  // the two sides legitimately differ there -- the first version of this digest
  // reported a divergence at checkpoint 1 that was four bytes of dead stack, a
  // return address the reference had popped and the candidate had overwritten.
  // Nothing a program can observe differed.
  constexpr std::uint64_t kStackWindow = 0x1000;   // the live stack, from the pointer up
  constexpr std::uint64_t kDataWindow = 0x10000;   // the image's writable area
  std::uint64_t hash = 14695981039346656037ull;
  const auto stack_pointer = context->registers[4];
  hash = digest_bytes(hash, stack_pointer, kStackWindow);
  if (recompiled_image_base != 0) hash = digest_bytes(hash, recompiled_image_base, kDataWindow);
  return hash;
}

void capture_guest_checkpoint(GuestContext* context, std::uint64_t address) {
  const auto index = guest_checkpoint_counter++;
  if (index % guest_checkpoint_interval != 0) return;
  GuestCheckpoint checkpoint;
  checkpoint.index = index;
  checkpoint.address = address;
  for (int register_index = 0; register_index < 16; ++register_index)
    checkpoint.registers[register_index] = context->registers[register_index];
  checkpoint.flags = eflags_value(context);
  checkpoint.mxcsr = context->mxcsr;
  checkpoint.x87_control_word = context->x87_control_word;
  checkpoint.x87_status_word = x87_status_value(context);
  checkpoint.memory_digest = guest_memory_digest(context);
  // The pages this run has written, exported so the harness can hash the SAME addresses in
  // both memories. The set decides what to compare; it never decides whether the two sides
  // agree -- which is what the first attempt got wrong.
  if (guest_dirty_page_log != nullptr && guest_page_dirty != nullptr) {
    for (std::uint64_t page = 0; page < (guest_memory_size >> kGuestPageShift); ++page) {
      if (guest_page_dirty[page] == 0) continue;
      // The PAGE's digest, not its address alone. The candidate has exited by the time the
      // harness compares, so its memory is gone; a per-page digest is what lets the
      // reference's memory be hashed over the SAME pages and the two compared.
      const auto page_digest = digest_bytes(14695981039346656037ull, page << kGuestPageShift, kGuestPageBytes);
      std::fprintf(guest_dirty_page_log, "%llu %llu %llx\n", static_cast<unsigned long long>(index),
                   static_cast<unsigned long long>(page), static_cast<unsigned long long>(page_digest));
    }
  }
  const auto checkpoint_number = index / guest_checkpoint_interval;
  if (guest_memory_windows != nullptr &&
      checkpoint_number < kMemoryWindowSampleLimit) {
    const std::uint64_t header[3] = {index, context->registers[4], recompiled_image_base};
    std::fwrite(header, sizeof(std::uint64_t), 3, guest_memory_windows);
    std::fwrite(guest_memory + context->registers[4], 1, 0x1000, guest_memory_windows);
    if (recompiled_image_base != 0)
      std::fwrite(guest_memory + recompiled_image_base, 1, 0x10000, guest_memory_windows);
    else {
      const std::uint8_t zeros[0x10000] = {};
      std::fwrite(zeros, 1, 0x10000, guest_memory_windows);
    }
  }
  guest_checkpoints.push_back(checkpoint);
}

void (*guest_exit_handler)(int code) = nullptr;

void guest_request_exit(int code) {
  write_guest_checkpoints_if_requested();
  // Registered handlers do not run. Saying so is the point: the runtime used to accept
  // the registration and report success, so a program that registered one produced
  // neither the handler's effect nor any diagnostic. Running them is the next step and
  // needs the differential reference to run them too, which means continuing emulation
  // at each handler rather than calling a compiled function.
  report_unrun_atexit_handlers();
  if (guest_exit_handler != nullptr) {
    guest_exit_handler(code);
    return;
  }
  std::fflush(stdout);
  std::exit(code);
}

std::ptrdiff_t write_guest_output(int descriptor, const char* data, std::size_t size) {
  if (size == 0) return 0;
  if (guest_output_capture != nullptr) {
    guest_output_capture->append(data, size);
    return static_cast<std::ptrdiff_t>(size);
  }
  // A failed or partial write is reported to the caller. Discarding it made a
  // closed descriptor indistinguishable from a successful write.
  const auto accepted = ::write(descriptor, data, size);
  if (accepted < 0) return 0;
  return accepted;
}

// Brings the guest address space to the state a program starts in. The image must
// already be loaded; everything else the runtime sets up before the entry point
// runs is done here, so that the candidate and the differential reference begin
// from the same state by construction rather than from two lists that happen to
// agree. A shim whose result depends on this state -- the heap allocator above
// all, whose addresses appear in program output -- would otherwise differ between
// the two sides for a reason that has nothing to do with the translation.
std::uint64_t initial_guest_stack_pointer(std::uint64_t stack_top, int pointer_width) {
  const auto pointer = static_cast<std::uint64_t>(pointer_width);
  return stack_top - pointer;
}

// Chooses the directory a recompiled app is allowed to touch. The explicit
// choice wins, then the directory the generator recorded for the input image,
// then the host working directory -- which is what an un-bundled app expects,
// because a Windows program reads its data files from next to itself.
//
// Something always has to be chosen. Leaving the sandbox unarmed would refuse
// every path, and the refusal would look like a missing file rather than like a
// policy that was never told where the app lives.
void arm_guest_file_sandbox() {
  auto& sandbox = guest_file_sandbox();
  if (const char* explicit_root = std::getenv("RECOMP_APP_DIR")) {
    if (explicit_root[0] != '\0') {
      sandbox.set_root(explicit_root);
      return;
    }
  }
  if (!sandbox.armed()) {
    std::array<char, 4096> buffer{};
    if (::getcwd(buffer.data(), buffer.size()) != nullptr) sandbox.set_root(buffer.data());
  }
}

void initialize_guest_state(std::uint64_t image_base, std::uint64_t heap_base, std::uint64_t stack_top) {
  // Both sides of a verification pass through here, so loading the supplied stdin once
  // is enough for the reference and the candidate to read the same bytes.
  load_guest_input_from_environment();
  if (const char* budget = std::getenv("RECOMP_INSTRUCTION_BUDGET"))
    guest_instruction_budget = std::strtoull(budget, nullptr, 10);
  recompiled_image_base = image_base;
  next_heap_address = heap_base;
  heap_initialize(heap_base, stack_top);
  arm_guest_file_sandbox();
  build_environment_blocks();
  const char* command_line = "recomp-guest";
  std::memcpy(guest_memory + guest_reserved_top() - 0x500000, command_line, std::strlen(command_line) + 1);
  const std::uint64_t wide_command_line = guest_reserved_top() - 0x600000;
  for (std::size_t index = 0; index < std::strlen(command_line); ++index)
    store_guest_memory(nullptr, wide_command_line + index * 2,
                       static_cast<std::uint8_t>(command_line[index]), 2);
  store_guest_memory(nullptr, wide_command_line + std::strlen(command_line) * 2, 0, 2);
  msvcrt_initialize();
  cxx_initialize();
}

bool invoke_shared_shim(GuestContext* context, const char* library_name, const char* symbol_name) {
  const auto* shim = find_win32_shim(library_name, symbol_name);
  if (shim == nullptr) return false;
  select_import_convention(library_name, symbol_name);
  guest_in_shim = true;
  shim->function(context);
  guest_in_shim = false;
  return true;
}

bool map_guest_memory(std::uint64_t bytes) {
  if (guest_memory != nullptr) return true;
  guest_memory_size = bytes;
  // One byte per 4 KiB page: 2 MiB for the 8 GiB space, against the mapping it describes.
  guest_page_dirty = static_cast<std::uint8_t*>(std::calloc(
      static_cast<std::size_t>(guest_memory_size >> kGuestPageShift), sizeof(std::uint8_t)));
#ifdef _WIN32
  // MEM_RESERVE alone commits nothing; pages are committed on first touch, which is what
  // MAP_NORESERVE asks for on the other side. The address is chosen by the system, exactly as
  // it is with a null hint to mmap.
  guest_memory = static_cast<std::uint8_t*>(
      VirtualAlloc(nullptr, static_cast<SIZE_T>(guest_memory_size), MEM_RESERVE, PAGE_READWRITE));
  if (guest_memory == nullptr) {
    guest_memory_size = 0;
    return false;
  }
#else
  guest_memory = static_cast<std::uint8_t*>(mmap(nullptr, static_cast<std::size_t>(guest_memory_size),
                                                 PROT_READ | PROT_WRITE,
                                                 MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0));
  if (guest_memory == MAP_FAILED) {
    guest_memory = nullptr;
    guest_memory_size = 0;
    return false;
  }
#endif
  return true;
}

int run_recompiled_image(const RecompiledImage* image) {
  if (const char* trace_path = std::getenv("RECOMP_TRACE")) {
    guest_trace_stream = std::fopen(trace_path, "wb");
    guest_tracing_enabled = guest_trace_stream != nullptr;
  }
  recompiled_image_base = image->image_base;
  guest_pointer_width = image->pointer_width;
  // Reuses an existing mapping when there is one. The differential reference maps
  // this same buffer into the emulator, so re-allocating here would leave the
  // emulator pointing at memory the candidate no longer uses -- and the two would
  // silently stop being comparable.
  if (!map_guest_memory(kGuestMemoryBytes)) terminate_with_message("mmap failed: %s", std::strerror(errno));
  std::memset(guest_memory, 0, 0x1000);  // the low page, which a 32-bit guest may use
  if (image->image_blob_size != 0)
    std::memcpy(guest_memory + image->image_base, image->image_blob, image->image_blob_size);

  function_table.assign(image->functions, image->functions + image->function_count);
  function_hash = static_cast<std::uint32_t*>(std::calloc(kFunctionHashSize, sizeof(std::uint32_t)));
  for (std::uint32_t index = 0; index < image->function_count; ++index) {
    const auto start = hash_function_address(image->functions[index].address);
    for (std::uint32_t probe = 0;; ++probe) {
      const auto slot = (start + probe) & (kFunctionHashSize - 1);
      if (function_hash[slot] == 0) { function_hash[slot] = index + 1; break; }
    }
  }

  std::uint32_t implemented = 0;
  std::string unsupported;
  for (std::uint32_t index = 0; index < image->import_count; ++index) {
    const auto& imported = image->imports[index];
    const bool is_fmode_data = std::strcmp(imported.library_name, "msvcrt.dll") == 0 &&
                               std::strcmp(imported.symbol_name, "_fmode") == 0;
    void (*function)(GuestContext*) = nullptr;
    const auto found = lookup_win32_import(imported.library_name, imported.symbol_name, &function);
    const auto import_address = is_fmode_data
                                    ? msvcrt_file_mode_pointer
                                    : import_thunk_base() + static_cast<std::uint64_t>(index) * 0x10;
    if (!is_fmode_data) {
      register_import_thunk(import_address, found ? function : unbound_import_thunk, imported.library_name,
                            imported.symbol_name);
    }
    store_guest_memory(nullptr, image->image_base + imported.import_address_table_rva, import_address,
                       imported.slot_size != 0 ? static_cast<int>(imported.slot_size) : 8);
    if (found || is_fmode_data) {
      ++implemented;
    } else {
      unsupported += std::string(" ") + imported.library_name + "!" + imported.symbol_name;
    }
  }
  if (!unsupported.empty()) {
    std::fprintf(stderr, "recomp: %u/%u imports implemented; UNSUPPORTED:%s\n", implemented,
                 image->import_count, unsupported.c_str());
  }

  const auto teb_address =
      guest_pointer_width >= 8 ? kThreadEnvironmentBlockAddress64 : kThreadEnvironmentBlockAddress32;
  const auto peb_address =
      guest_pointer_width >= 8 ? kProcessEnvironmentBlockAddress64 : kProcessEnvironmentBlockAddress32;
  if (guest_pointer_width >= 8) {
    store_guest_memory(nullptr, teb_address + 0x08, image->stack_top, 8);
    store_guest_memory(nullptr, teb_address + 0x10, image->stack_top - 0x100000, 8);
    store_guest_memory(nullptr, teb_address + 0x30, peb_address, 8);
    store_guest_memory(nullptr, teb_address + 0x60, peb_address, 8);
    store_guest_memory(nullptr, peb_address + 0x10, image->image_base, 8);
  } else {
    // 32-bit layout: TEB self pointer at +0x18, PEB at +0x30.
    store_guest_memory(nullptr, teb_address + 0x04, image->stack_top, 4);
    store_guest_memory(nullptr, teb_address + 0x08, image->stack_top - 0x100000, 4);
    store_guest_memory(nullptr, teb_address + 0x18, teb_address, 4);
    store_guest_memory(nullptr, teb_address + 0x30, peb_address, 4);
    store_guest_memory(nullptr, peb_address + 0x08, image->image_base, 4);
  }
  initialize_guest_state(image->image_base, image->heap_base, image->stack_top);
  // The differential comparison asks for guest-state checkpoints at a fixed
  // interval; the reference uses the same one, so the two streams line up.
  open_guest_store_log(std::getenv("RECOMP_STORE_LOG"));
  open_guest_dirty_page_log(std::getenv("RECOMP_DIRTY_PAGES"));
  open_guest_memory_windows(std::getenv("RECOMP_MEMORY_WINDOWS"));
  open_guest_mxcsr_log(std::getenv("RECOMP_MXCSR_LOG"));
  if (const char* interval = std::getenv("RECOMP_CHECKPOINT_INTERVAL"))
    guest_checkpoint_interval = std::strtoull(interval, nullptr, 0);
  if (const char* watch = std::getenv("RECOMP_WATCH"))
    watched_guest_address = std::strtoull(watch, nullptr, 0);

  GuestContext context{};
  context.registers[kRegisterStackPointer] = image->stack_top;
  context.fs_base = teb_address;
  context.gs_base = teb_address;
  // The x87 control word after FINIT: all exceptions masked, extended precision
  // (precision control 0b11), round to nearest. 0x027f was wrong -- it selected
  // double precision, so a guest that read the control word with FNSTCW saw a
  // different value from the one hardware would give it, and `x87.exe` does
  // exactly that.
  context.x87_control_word = 0x037f;
  context.mxcsr = kMxcsrDefaultValue;
  push_guest_stack(&context, 0);
  guest_context_for_atexit = &context;

  auto entry = lookup_guest_function(image->image_base + image->entry_point_rva);
  if (entry == nullptr)
    terminate_with_message("entry point 0x%" PRIx64 " was not recompiled",
                           image->image_base + image->entry_point_rva);
  entry(&context);
  guest_context_for_atexit = nullptr;
  std::fflush(stdout);
  if (guest_trace_stream != nullptr) { std::fflush(guest_trace_stream); std::fclose(guest_trace_stream); guest_trace_stream = nullptr; }
  return static_cast<int>(static_cast<std::uint32_t>(context.registers[kRegisterReturnValue]));
}

}  // namespace recomp
