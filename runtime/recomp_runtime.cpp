#include "recomp_runtime.hpp"
#include "win32_abi.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <fcntl.h>
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

// Compile the unmodified MIT scanner in callback mode. Its standard-input
// wrappers are disabled; the guest adapter supplies the host stream explicitly.
#define SCANF_SSCANF_ONLY 1
#include "upstream_scanf.c"

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
// Runtime-owned blocks must be addressable by the guest, including PE32 images
// whose pointers cannot represent the upper half of the mapped address space.
std::uint64_t guest_reserved_top() {
  return guest_pointer_width >= 8 ? guest_memory_size : std::min(guest_memory_size, 0x100000000ull);
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
  // The count reported back is what the host accepted, not what was requested.
  // Reporting the requested length made a short write -- a full disk, a closed
  // descriptor -- look like success, and a program that trusts the count would
  // believe data had been written that had not.
  std::uint64_t written = 0;
  while (written < length) {
    const auto accepted = write_guest_output(
        descriptor, reinterpret_cast<const char*>(guest_memory + buffer + written),
        static_cast<std::size_t>(length - written));
    if (accepted <= 0) break;
    written += static_cast<std::uint64_t>(accepted);
  }
  if (written_pointer != 0) store_guest_memory(context, written_pointer, written, 4);
  // WriteFile succeeds when it wrote something; a partial write is still a
  // success with a short count, which is what the API specifies.
  set_import_result(context, written != 0 ? 1 : 0);
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
void win32_current_process_id(GuestContext* context) { set_import_result(context, 4321); }
void win32_current_thread_id(GuestContext* context) { set_import_result(context, 4321); }
void win32_current_process(GuestContext* context) { set_import_result(context, static_cast<std::uint64_t>(-1)); }
void win32_current_thread(GuestContext* context) { set_import_result(context, static_cast<std::uint64_t>(-2)); }
void win32_module_handle(GuestContext* context) { set_import_result(context, recompiled_image_base); }
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
// Adapted from igi-recomp shim/src/kernel32.c GetLocalTime (MIT, HenryKun55).
void win32_get_local_time(GuestContext* context) {
  const std::time_t now = std::time(nullptr);
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
  if (out != 0 && out + 68 <= guest_memory_size) std::memset(guest_memory + out, 0, 68);
}
void win32_get_command_line(GuestContext* context) {
  set_import_result(context, guest_reserved_top() - 0x500000);
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
  const auto path = guest_path_to_host(read_guest_string(import_argument(context, 1)));
  const auto mode = import_argument(context, 2);
  const auto bytes = for_output ? kCxxOfstreamBytes : kCxxIfstreamBytes;
  if (object + bytes <= guest_memory_size) std::memset(guest_memory + object, 0, bytes);
  auto flags = for_output ? (O_WRONLY | O_CREAT) : O_RDONLY;
  if ((mode & 1u) != 0 || (mode & 2u) != 0) flags |= O_APPEND; else if (for_output) flags |= O_TRUNC;
  const auto descriptor = ::open(path.c_str(), flags, 0644);
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

constexpr std::uint64_t kMsvcrtFileObjectBytes = 48;
constexpr std::uint64_t kMsvcrtFileCount = 3;  // stdin, stdout, stderr

void msvcrt_initialize() {
  msvcrt_data_block = 0;
  if (guest_memory == nullptr || guest_memory_size < 0x400000) return;
  msvcrt_data_block = guest_reserved_top() - 0x300000;
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
  store_guest_memory(nullptr, msvcrt_data_block + 0x430, guest_reserved_top() - 0x500000, guest_pointer_width);
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
    write_guest_output(descriptor, reinterpret_cast<const char*>(guest_memory + buffer), static_cast<std::size_t>(total));
  set_import_result(context, count);
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
  write_guest_output(1, text.data(), text.size());
  set_import_result(context, text.size());
}

void msvcrt_putchar(GuestContext* context) {
  const auto character = static_cast<unsigned char>(import_argument(context, 0));
  const char byte = static_cast<char>(character);
  write_guest_output(1, &byte, 1);
  set_import_result(context, character);
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

// ---- msvcrt: the remaining CRT entry points -------------------------------
void msvcrt_system(GuestContext* context) {
  const auto command = read_guest_string(import_argument(context, 0));
  if (command.empty()) { set_import_result(context, 1); return; }
  set_import_result(context, static_cast<std::uint64_t>(std::system(command.c_str())));
}
void msvcrt_time(GuestContext* context) {
  const auto target = import_argument(context, 0);
  const auto now = static_cast<std::int64_t>(std::time(nullptr));
  if (target != 0) store_guest_memory(context, target, static_cast<std::uint64_t>(now), 4);
  set_import_result(context, static_cast<std::uint64_t>(now));
}
void msvcrt_time64(GuestContext* context) {
  const auto target = import_argument(context, 0);
  const auto now = static_cast<std::uint64_t>(static_cast<std::int64_t>(std::time(nullptr)));
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
std::uint64_t msvcrt_format_into_stream(GuestContext* context, std::uint64_t stream,
                                        const std::string& format, std::uint64_t arguments);

void msvcrt_vfprintf(GuestContext* context) {
  const auto stream = import_argument(context, 0);
  const auto format = read_guest_string(import_argument(context, 1));
  const auto arguments = import_argument(context, 2);
  set_import_result(context, msvcrt_format_into_stream(context, stream, format, arguments));
}
std::uint64_t msvcrt_format_into_stream(GuestContext* context, std::uint64_t stream,
                                        const std::string& format, std::uint64_t arguments) {
  std::string output;
  const auto descriptor = static_cast<int>(cxx_stream_descriptor(context, stream, true));
  for (std::size_t index = 0; index < format.size(); ++index) {
    if (format[index] != '%') { output.push_back(format[index]); continue; }
    if (index + 1 >= format.size()) break;
    auto specifier = format[++index];
    while (specifier == '-' || specifier == '+' || specifier == ' ' || specifier == '#' || specifier == '0')
      specifier = format[++index];
    while (specifier >= '0' && specifier <= '9') specifier = format[++index];
    if (specifier == 'l' || specifier == 'h') specifier = format[++index];
    const auto next = [&arguments, context] {
      const auto value = load_guest_memory(context, arguments, 4);
      arguments += 4;
      return value;
    };
    switch (specifier) {
      case '%': output.push_back('%'); break;
      case 'c': output.push_back(static_cast<char>(next() & 0xffu)); break;
      case 'd':
      case 'i': output += std::to_string(static_cast<std::int32_t>(next() & 0xffffffffu)); break;
      case 'u': output += std::to_string(static_cast<std::uint32_t>(next() & 0xffffffffu)); break;
      case 'x': {
        std::ostringstream text;
        text << std::hex << static_cast<std::uint32_t>(next() & 0xffffffffu);
        output += text.str();
        break;
      }
      case 's': {
        const auto address = next();
        output += address == 0 ? std::string("(null)") : read_guest_string(address);
        break;
      }
      case 'p': {
        std::ostringstream text;
        text << "0x" << std::hex << next();
        output += text.str();
        break;
      }
      default:
        terminate_with_message("vfprintf: unsupported conversion '%%%c' (ip=0x%" PRIx64 ")", specifier,
                               context->instruction_pointer);
    }
  }
  write_guest_output(descriptor, output.data(), output.size());
  return output.size();
}

// _initterm runs the table of static initialisers the CRT is given: the C++
// static constructors and anything else placed in .CRT$XCU. Without it a C++
// program's globals are never constructed. Each entry is a guest function, so it
// is called through the same dispatch table the guest itself uses.
void msvcrt_initterm(GuestContext* context) {
  const auto begin = import_argument(context, 0);
  const auto end = import_argument(context, 1);
  for (std::uint64_t slot = begin; slot + 4 <= end; slot += 4) {
    const auto entry = load_guest_memory(context, slot, 4);
    if (entry == 0) continue;
    if (auto function = lookup_guest_function(entry)) {
      function(context);
    } else {
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

// UCRT uses a guest va_list and Windows-sized pointers, not a host va_list.
// Bridge the single-character forms for now and reject other formats explicitly.
void msvcrt_stdio_common_vfscanf(GuestContext* context) {
  const bool wide_guest = guest_pointer_width >= 8;
  const auto sp = context->registers[4];
  const auto options = wide_guest ? import_argument(context, 0) : load_guest_memory(context, sp + 4, 8);
  const auto stream = wide_guest ? import_argument(context, 1) : load_guest_memory(context, sp + 12, 4);
  const auto format_address = wide_guest ? import_argument(context, 2) : load_guest_memory(context, sp + 16, 4);
  const auto locale = wide_guest ? import_argument(context, 3) : load_guest_memory(context, sp + 20, 4);
  const auto arguments = wide_guest ? import_argument(context, 4) : load_guest_memory(context, sp + 24, 4);
  const auto format = read_guest_string(format_address);
  // Legacy wide-specifier mode does not change a narrow %c; secure scanf
  // requires additional buffer-size arguments and remains unsupported.
  if ((options & ~std::uint64_t{2}) != 0 || locale != 0 || stream != msvcrt_iob ||
      (format != "%c" && format != " %c"))
    terminate_with_message("__stdio_common_vfscanf: unsupported options=0x%" PRIx64 " stream=0x%" PRIx64
                           " stdin=0x%" PRIx64 " locale=0x%" PRIx64 " format='%s'",
                           options, stream, msvcrt_iob, locale, format.c_str());
  const auto destination = load_guest_memory(context, arguments, guest_pointer_width);
  (void)load_guest_memory(context, destination, 1);  // check the destination before passing it to host code
  const auto getch = [](void* input) { return std::fgetc(static_cast<std::FILE*>(input)); };
  const auto ungetch = [](int ch, void* input) { (void)std::ungetc(ch, static_cast<std::FILE*>(input)); };
  const auto result = fctscanf_(getch, ungetch, stdin, format.c_str(), guest_memory + destination);
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
    {"msvcrt.dll", "_initterm", msvcrt_initterm},
    {"msvcrt.dll", "_initterm_e", msvcrt_initterm_e},
    {"msvcrt.dll", "__acrt_iob_func", msvcrt_acrt_iob_func},
    {"msvcrt.dll", "__stdio_common_vfprintf", msvcrt_stdio_common_vfprintf},
    {"msvcrt.dll", "__stdio_common_vfscanf", msvcrt_stdio_common_vfscanf},
    {"msvcrt.dll", "memcmp", msvcrt_memcmp},
    {"msvcrt.dll", "fflush", msvcrt_return_zero},
    {"msvcrt.dll", "setvbuf", msvcrt_return_zero},
    {"msvcrt.dll", "_set_new_mode", msvcrt_return_zero},
    {"msvcrt.dll", "_configthreadlocale", msvcrt_return_zero},
    {"msvcrt.dll", "__setusermatherr", msvcrt_return_zero},
    {"msvcrt.dll", "_set_invalid_parameter_handler", msvcrt_return_zero},
    {"msvcrt.dll", "_configure_narrow_argv", msvcrt_return_zero},
    {"msvcrt.dll", "_initialize_narrow_environment", msvcrt_return_zero},
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
    {"msvcrt.dll", "putchar", msvcrt_putchar},
    {"msvcrt.dll", "signal", msvcrt_signal},
    {"msvcrt.dll", "strcoll", msvcrt_strcoll},
    {"msvcrt.dll", "_stricoll", msvcrt_strcoll},
    {"msvcrt.dll", "_fullpath", msvcrt_fullpath},
    {"msvcrt.dll", "wcstombs", msvcrt_wcstombs},
    {"msvcrt.dll", "vfprintf", msvcrt_vfprintf},
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
    {"msvcrt.dll", "puts", msvcrt_puts},
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

void open_guest_store_log(const char* path) {
  if (path == nullptr) return;
  guest_store_log = std::fopen(path, "w");
  guest_store_logging = guest_store_log != nullptr;
}

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
  if (guest_memory_windows != nullptr) {
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

void initialize_guest_state(std::uint64_t image_base, std::uint64_t heap_base, std::uint64_t stack_top) {
  recompiled_image_base = image_base;
  next_heap_address = heap_base;
  heap_initialize(heap_base, stack_top);
  build_environment_blocks();
  const char* command_line = "recomp-guest";
  std::memcpy(guest_memory + guest_reserved_top() - 0x500000, command_line, std::strlen(command_line) + 1);
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
  guest_memory = static_cast<std::uint8_t*>(mmap(nullptr, static_cast<std::size_t>(guest_memory_size),
                                                 PROT_READ | PROT_WRITE,
                                                 MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0));
  if (guest_memory == MAP_FAILED) {
    guest_memory = nullptr;
    guest_memory_size = 0;
    return false;
  }
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
  initialize_guest_state(image->image_base, image->heap_base, image->stack_top);
  // The differential comparison asks for guest-state checkpoints at a fixed
  // interval; the reference uses the same one, so the two streams line up.
  open_guest_store_log(std::getenv("RECOMP_STORE_LOG"));
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
