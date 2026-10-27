#include "recomp_runtime.hpp"
#include "win32_abi.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cctype>
#include <cstdlib>
#include <system_error>
#include <map>
#include <filesystem>
#include <algorithm>

// The host environment, used to build the guest's environment blocks.
extern char** environ;
#include <ctime>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace recomp {

std::uint8_t* guest_memory = nullptr;
std::uint64_t guest_memory_size = 0;
std::uint64_t recompiled_image_base = 0;
bool guest_tracing_enabled = false;
int guest_pointer_width = 8;

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
  import_thunk_functions[static_cast<std::size_t>(index)](context);
  if (guest_pointer_width < 8) {
    context->registers[4] = mask_guest_address(
        context->registers[4] +
        win32_import_stack_cleanup(import_thunk_libraries[static_cast<std::size_t>(index)].c_str(),
                                   import_thunk_symbols[static_cast<std::size_t>(index)].c_str()));
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

// ---- Win32 handle table ---------------------------------------------------
// Handles are opaque to the guest, but GetFileType, CloseHandle and the file and
// mutex shims have to agree about what a handle refers to. The three standard
// handles keep the values the reference also returns for GetStdHandle (10, 11,
// 12), so introducing the table does not change anything a differential
// comparison can observe; the table simply knows what those values mean.
enum GuestHandleType {
  kGuestHandleFree = 0,
  kGuestHandleStandard = 1,
  kGuestHandleFile = 2,
  kGuestHandleFind = 3,
  kGuestHandleHeap = 4,
  kGuestHandleMutex = 5,
};

struct GuestHandle {
  int type{kGuestHandleFree};
  int host_descriptor{-1};
};

constexpr std::uint32_t kGuestHandleBase = 0x1000;
constexpr std::uint32_t kGuestHandleCount = 1024;
GuestHandle guest_handles[kGuestHandleCount];
GuestHandle standard_handles[3] = {{kGuestHandleStandard, STDIN_FILENO},
                                   {kGuestHandleStandard, STDOUT_FILENO},
                                   {kGuestHandleStandard, STDERR_FILENO}};

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
      guest_handles[index].type = type;
      guest_handles[index].host_descriptor = descriptor;
      return kGuestHandleBase + index * 4u;
    }
  }
  return 0;  // exhausted; the shim reports the failure
}

void guest_handle_close(std::uint64_t handle) {
  auto* entry = guest_handle_lookup(handle);
  if (entry == nullptr || entry->type == kGuestHandleStandard) return;
  if (entry->host_descriptor >= 0) ::close(entry->host_descriptor);
  entry->type = kGuestHandleFree;
  entry->host_descriptor = -1;
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
  if (buffer + length > guest_memory_size) { set_import_result(context, 0); return; }
  const auto descriptor = standard_handle_to_descriptor(handle);
  std::uint64_t written = 0;
  while (written < length) {
    const auto count = ::write(descriptor, guest_memory + buffer + written, static_cast<std::size_t>(length - written));
    if (count <= 0) break;
    written += static_cast<std::uint64_t>(count);
  }
  if (written_pointer != 0) store_guest_memory(context, written_pointer, written, 4);
  set_import_result(context, 1);
}
void win32_read_file(GuestContext* context) {
  const auto handle = import_argument(context, 0);
  const auto buffer = import_argument(context, 1);
  const auto length = import_argument(context, 2);
  const auto read_pointer = import_argument(context, 3);
  if (buffer + length > guest_memory_size) { set_import_result(context, 0); return; }
  const auto descriptor = standard_handle_to_descriptor(handle);
  auto count = ::read(descriptor, guest_memory + buffer, static_cast<std::size_t>(length));
  if (count < 0) count = 0;
  if (read_pointer != 0) store_guest_memory(context, read_pointer, static_cast<std::uint64_t>(count), 4);
  set_import_result(context, 1);
}
void win32_exit_process(GuestContext* context) {
  std::fflush(stdout);
  std::exit(static_cast<int>(static_cast<std::uint32_t>(import_argument(context, 0))));
}
void win32_terminate_process(GuestContext* context) {
  (void)context;
  std::fflush(stdout);
  std::exit(1);
}
void win32_zero(GuestContext* context) { set_import_result(context, 0); }
void win32_ignore(GuestContext* context) { (void)context; }
void win32_one(GuestContext* context) { set_import_result(context, 1); }
void win32_current_process_id(GuestContext* context) { set_import_result(context, 4321); }
void win32_current_thread_id(GuestContext* context) { set_import_result(context, 4321); }
void win32_current_process(GuestContext* context) { set_import_result(context, static_cast<std::uint64_t>(-1)); }
void win32_current_thread(GuestContext* context) { set_import_result(context, static_cast<std::uint64_t>(-2)); }
void win32_module_handle(GuestContext* context) { set_import_result(context, recompiled_image_base); }
void win32_is_processor_feature_present(GuestContext* context) { set_import_result(context, 0); }
void win32_get_version(GuestContext* context) { set_import_result(context, 0x0a000000); }
void win32_code_page(GuestContext* context) { set_import_result(context, 65001); }

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
  (void)import_argument(context, 0);
  set_import_result(context, 1);
}
void win32_flush_file_buffers(GuestContext* context) {
  // Deliberately reports success without flushing, as igi-recomp does; the
  // reference has to take the same branch or the traces diverge.
  (void)import_argument(context, 0);
  set_import_result(context, 1);
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
void win32_set_std_handle(GuestContext* context) {
  (void)import_argument(context, 0);
  (void)import_argument(context, 1);
  set_import_result(context, 1);
}
void win32_create_mutex_a(GuestContext* context) {
  (void)import_argument(context, 0);  // attributes
  (void)import_argument(context, 1);  // initial owner
  (void)import_argument(context, 2);  // name
  set_import_result(context, guest_handle_new(kGuestHandleMutex));
}

void win32_get_process_heap(GuestContext* context) { set_import_result(context, 0x1000); }
void win32_heap_create(GuestContext* context) { set_import_result(context, 0x1000); }
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
  set_import_result(context, heap_allocate(import_argument(context, 2)));
}

// Releases a block and coalesces its free neighbours.
void heap_release(GuestContext* context, std::uint64_t pointer) {
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

void win32_get_tick_count(GuestContext* context) {
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  const auto milliseconds = static_cast<std::uint64_t>(now.tv_sec) * 1000ull +
                            static_cast<std::uint64_t>(now.tv_nsec) / 1000000ull;
  set_import_result(context, static_cast<std::uint32_t>(milliseconds));
}
void win32_query_performance_counter(GuestContext* context) {
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
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
void win32_get_startup_info(GuestContext* context) {
  const auto out = import_argument(context, 0);
  if (out != 0 && out + 68 <= guest_memory_size) std::memset(guest_memory + out, 0, 68);
}
void win32_get_command_line(GuestContext* context) {
  static std::uint64_t offset = 0;
  if (offset == 0) {
    offset = guest_memory_size - 0x100000;
    const char* command_line = "recomp-guest";
    std::memcpy(guest_memory + offset, command_line, std::strlen(command_line) + 1);
  }
  set_import_result(context, offset);
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
  environment_block_a = guest_memory_size - 0x200000;
  environment_block_w = guest_memory_size - 0x100000;
  std::memset(guest_memory + environment_block_a, 0, 0x100000);
  std::memset(guest_memory + environment_block_w, 0, 0x100000);
  std::uint64_t ansi = 0;
  std::uint64_t wide = 0;
  for (char** entry = environ; entry != nullptr && *entry != nullptr; ++entry) {
    const std::string variable{*entry};
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

// ---- msvcrt: the C runtime ------------------------------------------------
// Every MSVC- or mingw-built Windows binary imports its C runtime, so this is not
// application-specific: these are the standard C library functions implemented
// against the guest's own heap and address space. They are cdecl, so their ABI
// rows carry callee_cleans_stack = false and the caller pops, as on Windows.
std::uint64_t msvcrt_data_block = 0;   // CRT globals: errno, _iob, ctype tables
std::uint64_t msvcrt_environment_pointer = 0;
std::uint64_t msvcrt_file_mode_pointer = 0;
std::uint64_t msvcrt_iob = 0;

constexpr std::uint64_t kMsvcrtFileObjectBytes = 48;
constexpr std::uint64_t kMsvcrtFileCount = 3;  // stdin, stdout, stderr

void msvcrt_initialize() {
  msvcrt_data_block = 0;
  if (guest_memory == nullptr || guest_memory_size < 0x400000) return;
  msvcrt_data_block = guest_memory_size - 0x300000;
  std::memset(guest_memory + msvcrt_data_block, 0, 0x1000);
  msvcrt_environment_pointer = msvcrt_data_block + 0x100;
  msvcrt_file_mode_pointer = msvcrt_data_block + 0x110;
  msvcrt_iob = msvcrt_data_block + 0x200;
  // __p__environ and __p__fmode return the address of a variable, not the value.
  const std::uint32_t environment = static_cast<std::uint32_t>(environment_block_a);
  std::memcpy(guest_memory + msvcrt_environment_pointer, &environment, 4);
  const std::uint32_t mode = 0;  // _O_TEXT
  std::memcpy(guest_memory + msvcrt_file_mode_pointer, &mode, 4);
  const std::uint32_t mb_cur_max = 1;
  std::memcpy(guest_memory + msvcrt_data_block + 0x320, &mb_cur_max, 4);
}

std::uint64_t msvcrt_stream_index(std::uint64_t stream) {
  if (msvcrt_iob == 0 || stream < msvcrt_iob) return 0;
  const auto index = (stream - msvcrt_iob) / kMsvcrtFileObjectBytes;
  return index < kMsvcrtFileCount ? index : 0;
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

void msvcrt_fwrite(GuestContext* context) {
  const auto buffer = import_argument(context, 0);
  const auto size = import_argument(context, 1);
  const auto count = import_argument(context, 2);
  const auto stream = import_argument(context, 3);
  const auto total = size * count;
  const auto index = msvcrt_stream_index(stream);
  const int descriptor = index == 0 ? STDIN_FILENO : index == 1 ? STDOUT_FILENO : STDERR_FILENO;
  if (total != 0 && buffer + total <= guest_memory_size)
    (void)::write(descriptor, guest_memory + buffer, static_cast<std::size_t>(total));
  set_import_result(context, count);
}

// CRT globals. Each accessor returns the address of a variable in the reserved
// CRT block, which is what the real functions do.
void msvcrt_errno(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x000); }
void msvcrt_p_environ(GuestContext* context) { set_import_result(context, msvcrt_environment_pointer); }
void msvcrt_p_fmode(GuestContext* context) { set_import_result(context, msvcrt_file_mode_pointer); }
void msvcrt_iob_pointer(GuestContext* context) { set_import_result(context, msvcrt_iob); }
void msvcrt_pctype(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x300); }
void msvcrt_mb_cur_max(GuestContext* context) { set_import_result(context, msvcrt_data_block + 0x320); }

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
void msvcrt_strchr(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto character = static_cast<char>(import_argument(context, 1) & 0xffu);
  const auto found = text.find(character);
  set_import_result(context, found == std::string::npos ? 0 : import_argument(context, 0) + found);
}
void msvcrt_strrchr(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto character = static_cast<char>(import_argument(context, 1) & 0xffu);
  const auto found = text.rfind(character);
  set_import_result(context, found == std::string::npos ? 0 : import_argument(context, 0) + found);
}
void msvcrt_strstr(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto needle = read_guest_string(import_argument(context, 1));
  const auto found = text.find(needle);
  set_import_result(context, found == std::string::npos ? 0 : import_argument(context, 0) + found);
}
void msvcrt_strtol(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  const auto base = static_cast<int>(import_argument(context, 2));
  std::size_t consumed = 0;
  long value = 0;
  try {
    value = std::stol(text, &consumed, base == 0 ? 10 : base);
  } catch (...) {
    value = 0;
    consumed = 0;
  }
  const auto end = import_argument(context, 1);
  if (end != 0) store_guest_memory(context, end, import_argument(context, 0) + consumed, 4);
  set_import_result(context, static_cast<std::uint64_t>(value));
}
void msvcrt_atoi(GuestContext* context) {
  const auto text = read_guest_string(import_argument(context, 0));
  try {
    set_import_result(context, static_cast<std::uint64_t>(static_cast<std::int64_t>(std::stol(text))));
  } catch (...) {
    set_import_result(context, 0);
  }
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

// _onexit returns the function pointer it was given (NULL on failure); atexit
// returns 0. A CRT that stores the return value of _onexit into its exit table
// therefore stores the pointer, and returning 0 there puts a null into the table
// that the exit loop then calls.
void msvcrt_onexit(GuestContext* context) { set_import_result(context, import_argument(context, 0)); }
void msvcrt_abort(GuestContext* context) {
  terminate_with_message("abort() called by the guest (ip=0x%" PRIx64 ")", context->instruction_pointer);
}
void msvcrt_exit(GuestContext* context) {
  std::exit(static_cast<int>(import_argument(context, 0)));
}
void msvcrt_isctype(GuestContext* context) {
  const auto character = import_argument(context, 1);
  set_import_result(context, classify_character(static_cast<std::uint32_t>(character & 0xffu)) != 0 ? 1 : 0);
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

std::string guest_path_to_host(std::string path) {
  for (auto& character : path)
    if (character == '\\') character = '/';
  // A drive-qualified path has no meaning on the host; the rest of it is still
  // the best interpretation available, and a relative path is used as given.
  if (path.size() >= 2 && path[1] == ':') path.erase(0, 2);
  return path.empty() ? std::string(".") : path;
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
  const auto host = guest_path_to_host(pattern);
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
  set_import_result(context, guest_memory_size - 0x200000);
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
void win32_get_proc_address(GuestContext* context) {
  const auto name = read_guest_string(import_argument(context, 1));
  void (*function)(GuestContext*) = nullptr;
  if (!lookup_win32_import("kernel32.dll", name.c_str(), &function)) {
    // The real API returns NULL for a name it cannot resolve, and programs probe
    // for optional symbols precisely because that is allowed. Terminating here
    // turned a routine negative probe into a hard failure -- and a program that
    // genuinely needs the symbol still fails, at the call through the null it
    // was given, which is what Windows does too.
    std::fprintf(stderr, "recomp: GetProcAddress(\"%s\") not provided; returning NULL\n", name.c_str());
    set_import_result(context, 0);
    return;
  }
  static std::uint64_t next_thunk = 0;
  if (next_thunk == 0) next_thunk = import_thunk_base() + 0x00010000;
  const auto address = next_thunk;
  next_thunk += 0x10;
  register_import_thunk(address, function, "kernel32.dll", name.c_str());
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
    {"kernel32.dll", "GetLastError", win32_zero},
    {"kernel32.dll", "SetLastError", win32_ignore},
    {"kernel32.dll", "GetCurrentProcessId", win32_current_process_id},
    {"kernel32.dll", "GetCurrentThreadId", win32_current_thread_id},
    {"kernel32.dll", "GetCurrentProcess", win32_current_process},
    {"kernel32.dll", "GetCurrentThread", win32_current_thread},
    {"kernel32.dll", "IsDebuggerPresent", win32_zero},
    {"kernel32.dll", "GetModuleHandleA", win32_module_handle},
    {"kernel32.dll", "GetModuleHandleW", win32_module_handle},
    {"kernel32.dll", "GetModuleFileNameA", win32_zero},
    {"kernel32.dll", "SetUnhandledExceptionFilter", win32_zero},
    {"kernel32.dll", "UnhandledExceptionFilter", win32_one},
    {"kernel32.dll", "IsProcessorFeaturePresent", win32_is_processor_feature_present},
    {"kernel32.dll", "VirtualAlloc", win32_virtual_alloc},
    {"kernel32.dll", "VirtualFree", win32_virtual_free},
    {"kernel32.dll", "VirtualQuery", win32_virtual_query},
    {"kernel32.dll", "VirtualProtect", win32_virtual_protect},
    {"kernel32.dll", "Beep", win32_console_success},
    {"kernel32.dll", "SetConsoleCursorPosition", win32_console_success},
    {"kernel32.dll", "SetConsoleTextAttribute", win32_console_success},
    {"kernel32.dll", "SetConsoleCursorInfo", win32_console_success},
    {"kernel32.dll", "FindFirstFileA", win32_find_first_file_a},
    {"kernel32.dll", "FindNextFileA", win32_find_next_file_a},
    {"kernel32.dll", "FindClose", win32_find_close},
    {"kernel32.dll", "GetProcessHeap", win32_get_process_heap},
    {"kernel32.dll", "GetVersionExA", win32_get_version_ex_a},
    {"kernel32.dll", "GetFileType", win32_get_file_type},
    {"kernel32.dll", "GetEnvironmentStringsW", win32_get_environment_strings_w},
    {"kernel32.dll", "HeapReAlloc", win32_heap_realloc},
    {"kernel32.dll", "DebugBreak", win32_debug_break},
    {"kernel32.dll", "GetStringTypeA", win32_get_string_type_a},
    {"kernel32.dll", "GetStringTypeW", win32_get_string_type_w},
    {"kernel32.dll", "LCMapStringA", win32_lc_map_string_a},
    {"kernel32.dll", "LCMapStringW", win32_lc_map_string_w},
    {"kernel32.dll", "GetLocaleInfoA", win32_get_locale_info_a},
    // msvcrt: cdecl, so the caller pops and callee_cleans_stack is false below.
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
    {"msvcrt.dll", "atexit", msvcrt_noop},
    {"msvcrt.dll", "_onexit", msvcrt_onexit},
    {"msvcrt.dll", "_cexit", msvcrt_noop},
    {"msvcrt.dll", "_getch", msvcrt_noop},
    {"msvcrt.dll", "_kbhit", msvcrt_noop},
    {"msvcrt.dll", "abort", msvcrt_abort},
    {"msvcrt.dll", "exit", msvcrt_exit},
    {"msvcrt.dll", "_isctype", msvcrt_isctype},
    {"msvcrt.dll", "mbstowcs", msvcrt_mbstowcs},
    {"msvcrt.dll", "setlocale", msvcrt_setlocale},
    {"ole32.dll", "CoInitialize", win32_co_initialize},
    {"ole32.dll", "CoUninitialize", win32_co_uninitialize},
    {"kernel32.dll", "OutputDebugStringA", win32_output_debug_string_a},
    {"kernel32.dll", "GetDriveTypeA", win32_get_drive_type_a},
    {"kernel32.dll", "CompareFileTime", win32_compare_file_time},
    {"kernel32.dll", "CloseHandle", win32_close_handle},
    {"kernel32.dll", "SetStdHandle", win32_set_std_handle},
    {"kernel32.dll", "CreateMutexA", win32_create_mutex_a},
    {"kernel32.dll", "SetHandleCount", win32_set_handle_count},
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
    {"kernel32.dll", "GetSystemTimeAsFileTime", win32_get_system_time_as_file_time},
    {"kernel32.dll", "GetStartupInfoA", win32_get_startup_info},
    {"kernel32.dll", "GetCommandLineA", win32_get_command_line},
    {"kernel32.dll", "GetEnvironmentStrings", win32_get_environment_strings},
    {"kernel32.dll", "FreeEnvironmentStringsA", win32_one},
    {"kernel32.dll", "lstrlenA", win32_lstrlen_a},
    {"kernel32.dll", "lstrlenW", win32_lstrlen_w},
    {"kernel32.dll", "lstrcpyA", win32_lstrcpy_a},
    {"kernel32.dll", "GetACP", win32_code_page},
    {"kernel32.dll", "GetOEMCP", win32_code_page},
    {"kernel32.dll", "GetConsoleOutputCP", win32_code_page},
    {"kernel32.dll", "SetConsoleOutputCP", win32_one},
    {"kernel32.dll", "GetVersion", win32_get_version},
    {"kernel32.dll", "GetSystemInfo", win32_get_system_info},
    {"kernel32.dll", "FlsAlloc", win32_zero},
    {"kernel32.dll", "FlsFree", win32_one},
    {"kernel32.dll", "FlsSetValue", win32_one},
    {"kernel32.dll", "FlsGetValue", win32_zero},
    {"kernel32.dll", "TlsAlloc", win32_zero},
    {"kernel32.dll", "TlsFree", win32_one},
    {"kernel32.dll", "TlsSetValue", win32_one},
    {"kernel32.dll", "TlsGetValue", win32_zero},
    {"kernel32.dll", "WideCharToMultiByte", win32_zero},
    {"kernel32.dll", "MultiByteToWideChar", win32_zero},
    {"kernel32.dll", "GetProcAddress", win32_get_proc_address},
    {"kernel32.dll", "LoadLibraryA", win32_module_handle},
    {"kernel32.dll", "LoadLibraryW", win32_module_handle},
    {"kernel32.dll", "FreeLibrary", win32_one},
};

}  // namespace

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
  terminate_with_message("guest %s fault at 0x%" PRIx64 " (width %d) ip=0x%" PRIx64,
                         is_write ? "write" : "read", address, width, context->instruction_pointer);
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
    const __int128 product = static_cast<__int128>(static_cast<std::int64_t>(context->registers[0])) *
                             static_cast<__int128>(static_cast<std::int64_t>(operand));
    context->registers[0] = static_cast<std::uint64_t>(product);
    context->registers[2] = static_cast<std::uint64_t>(product >> 64);
    context->carry_flag = context->overflow_flag =
        product != static_cast<__int128>(static_cast<std::int64_t>(context->registers[0]));
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
    const __int128 product = static_cast<__int128>(left_value) * static_cast<__int128>(right_value);
    const auto result = static_cast<std::uint64_t>(product);
    context->carry_flag = context->overflow_flag = product != static_cast<__int128>(static_cast<std::int64_t>(result));
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
  const auto product = static_cast<unsigned __int128>(left) * static_cast<unsigned __int128>(right);
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
    const auto dividend = (static_cast<unsigned __int128>(context->registers[2]) << 64) | context->registers[0];
    context->registers[0] = static_cast<std::uint64_t>(dividend / divisor);
    context->registers[2] = static_cast<std::uint64_t>(dividend % divisor);
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
    const __int128 dividend = (static_cast<__int128>(static_cast<std::int64_t>(context->registers[2])) << 64) |
                              static_cast<unsigned __int128>(context->registers[0]);
    context->registers[0] = static_cast<std::uint64_t>(dividend / divisor_value);
    context->registers[2] = static_cast<std::uint64_t>(dividend % divisor_value);
    return;
  }
  const auto high = sign_extend(context->registers[2], width);
  const auto low = context->registers[0] & mask;
  const __int128 dividend = (static_cast<__int128>(high) << (width * 8)) | static_cast<unsigned __int128>(low);
  context->registers[0] = static_cast<std::uint64_t>(dividend / divisor_value) & mask;
  context->registers[2] = static_cast<std::uint64_t>(dividend % divisor_value) & mask;
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
    // Only 32-bit x86 needs the return address pushed: its cleanup pass then
    // removes the return address and the stdcall arguments. On x86-64 the shim
    // returns directly and the guest stack must be left untouched.
    invoke_import_thunk(context, thunk, return_address, guest_pointer_width < 8);
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
void invoke_win32_import_tail(GuestContext* context, const char* library_name, const char* symbol_name) {
  const auto* shim = find_win32_shim(library_name, symbol_name);
  if (shim == nullptr) {
    terminate_with_message("unimplemented Win32 import %s!%s (ip=0x%" PRIx64 ")", library_name, symbol_name,
                           context->instruction_pointer);
  }
  shim->function(context);
  if (guest_pointer_width >= 8) return;
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
  if (guest_pointer_width >= 8) {
    shim->function(context);
    return;
  }
  // 32-bit x86: emulate the `call` and the matching `ret`/`ret n` so the guest
  // stack matches what real hardware would leave behind. cdecl leaves the
  // arguments for the caller to pop; stdcall pops them in the callee.
  context->registers[4] = mask_guest_address(context->registers[4] - 4);
  store_guest_memory(context, context->registers[4], return_address, 4);
  shim->function(context);
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

int run_recompiled_image(const RecompiledImage* image) {
  if (const char* trace_path = std::getenv("RECOMP_TRACE")) {
    guest_trace_stream = std::fopen(trace_path, "wb");
    guest_tracing_enabled = guest_trace_stream != nullptr;
  }
  recompiled_image_base = image->image_base;
  guest_pointer_width = image->pointer_width;
  guest_memory_size = kGuestMemoryBytes;
  guest_memory = static_cast<std::uint8_t*>(mmap(nullptr, static_cast<std::size_t>(guest_memory_size),
                                                 PROT_READ | PROT_WRITE,
                                                 MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0));
  if (guest_memory == MAP_FAILED) terminate_with_message("mmap failed: %s", std::strerror(errno));
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
    void (*function)(GuestContext*) = nullptr;
    const auto found = lookup_win32_import(imported.library_name, imported.symbol_name, &function);
    const auto thunk_address = import_thunk_base() + static_cast<std::uint64_t>(index) * 0x10;
    register_import_thunk(thunk_address, found ? function : unbound_import_thunk, imported.library_name,
                          imported.symbol_name);
    store_guest_memory(nullptr, image->image_base + imported.import_address_table_rva, thunk_address,
                       imported.slot_size != 0 ? static_cast<int>(imported.slot_size) : 8);
    if (found) {
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
  next_heap_address = image->heap_base;
  heap_initialize(image->heap_base, image->stack_top);
  build_environment_blocks();
  msvcrt_initialize();
  if (const char* watch = std::getenv("RECOMP_WATCH"))
    watched_guest_address = std::strtoull(watch, nullptr, 0);

  GuestContext context{};
  context.registers[kRegisterStackPointer] = image->stack_top;
  context.fs_base = teb_address;
  context.gs_base = teb_address;
  context.x87_control_word = 0x027f;
  context.mxcsr = kMxcsrDefaultValue;
  push_guest_stack(&context, 0);

  auto entry = lookup_guest_function(image->image_base + image->entry_point_rva);
  if (entry == nullptr)
    terminate_with_message("entry point 0x%" PRIx64 " was not recompiled",
                           image->image_base + image->entry_point_rva);
  entry(&context);
  std::fflush(stdout);
  if (guest_trace_stream != nullptr) { std::fflush(guest_trace_stream); std::fclose(guest_trace_stream); guest_trace_stream = nullptr; }
  return static_cast<int>(static_cast<std::uint32_t>(context.registers[kRegisterReturnValue]));
}

}  // namespace recomp
