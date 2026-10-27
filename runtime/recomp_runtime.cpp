#include "recomp_runtime.hpp"
#include "win32_abi.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

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
    terminate_with_message("GetProcAddress(\"%s\") is not implemented", name.c_str());
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
    {"kernel32.dll", "GetProcessHeap", win32_get_process_heap},
    {"kernel32.dll", "GetVersionExA", win32_get_version_ex_a},
    {"kernel32.dll", "GetFileType", win32_get_file_type},
    {"kernel32.dll", "GetEnvironmentStringsW", win32_get_environment_strings_w},
    {"kernel32.dll", "HeapReAlloc", win32_heap_realloc},
    {"kernel32.dll", "DebugBreak", win32_debug_break},
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
  terminate_with_message("indirect call to unmapped guest address 0x%" PRIx64 " (ip=0x%" PRIx64 ")", target,
                         context->instruction_pointer);
}

void jump_guest_indirect(GuestContext* context, std::uint64_t target) {
  if (auto function = lookup_guest_function(target)) { function(context); return; }
  const auto thunk = lookup_import_thunk(target);
  if (thunk >= 0) {
    invoke_import_thunk(context, thunk, 0, false);
    return;
  }
  terminate_with_message("indirect jump to unmapped guest address 0x%" PRIx64 " (ip=0x%" PRIx64 ")", target,
                         context->instruction_pointer);
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
