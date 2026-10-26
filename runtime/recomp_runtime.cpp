#include "recomp_runtime.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
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
constexpr std::uint64_t kThreadEnvironmentBlockAddress = 0x0000000164000000ull;
constexpr std::uint64_t kProcessEnvironmentBlockAddress = 0x0000000164001000ull;
constexpr std::uint64_t kImportThunkBase = 0x0000000100000000ull;

constexpr int kFunctionHashBits = 18;
constexpr std::uint32_t kFunctionHashSize = 1u << kFunctionHashBits;

std::vector<GuestFunctionDescriptor> function_table;
std::uint32_t* function_hash = nullptr;
std::vector<std::uint64_t> import_thunk_addresses;
std::vector<void (*)(GuestContext*)> import_thunk_functions;

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

void (*lookup_import_thunk(std::uint64_t address))(GuestContext*) {
  for (std::size_t index = 0; index < import_thunk_addresses.size(); ++index)
    if (import_thunk_addresses[index] == address) return import_thunk_functions[index];
  return nullptr;
}

std::string read_guest_string(std::uint64_t address) {
  std::string value;
  while (value.size() < 4096 && address < guest_memory_size && guest_memory[address] != 0) {
    value.push_back(static_cast<char>(guest_memory[address]));
    ++address;
  }
  return value;
}

int standard_handle_to_descriptor(std::uint64_t handle) {
  if (handle == 11) return STDOUT_FILENO;
  if (handle == 12) return STDERR_FILENO;
  if (handle == 10) return STDIN_FILENO;
  return STDOUT_FILENO;
}

std::uint64_t next_heap_address = 0;

// ---- Win32 shims -------------------------------------------------------
void win32_get_std_handle(GuestContext* context) {
  const auto which = static_cast<std::int32_t>(context->registers[kRegisterArgument0]);
  context->registers[kRegisterReturnValue] = which == -10 ? 10 : which == -12 ? 12 : 11;
}
void win32_write_file(GuestContext* context) {
  const auto handle = context->registers[kRegisterArgument0];
  const auto buffer = context->registers[kRegisterArgument1];
  const auto length = context->registers[kRegisterArgument2];
  const auto written_pointer = context->registers[kRegisterArgument3];
  if (buffer + length > guest_memory_size) { context->registers[kRegisterReturnValue] = 0; return; }
  const auto descriptor = standard_handle_to_descriptor(handle);
  std::uint64_t written = 0;
  while (written < length) {
    const auto count = ::write(descriptor, guest_memory + buffer + written, static_cast<std::size_t>(length - written));
    if (count <= 0) break;
    written += static_cast<std::uint64_t>(count);
  }
  if (written_pointer != 0) store_guest_memory(context, written_pointer, written, 4);
  context->registers[kRegisterReturnValue] = 1;
}
void win32_read_file(GuestContext* context) {
  const auto handle = context->registers[kRegisterArgument0];
  const auto buffer = context->registers[kRegisterArgument1];
  const auto length = context->registers[kRegisterArgument2];
  const auto read_pointer = context->registers[kRegisterArgument3];
  if (buffer + length > guest_memory_size) { context->registers[kRegisterReturnValue] = 0; return; }
  const auto descriptor = standard_handle_to_descriptor(handle);
  auto count = ::read(descriptor, guest_memory + buffer, static_cast<std::size_t>(length));
  if (count < 0) count = 0;
  if (read_pointer != 0) store_guest_memory(context, read_pointer, static_cast<std::uint64_t>(count), 4);
  context->registers[kRegisterReturnValue] = 1;
}
void win32_exit_process(GuestContext* context) {
  std::fflush(stdout);
  std::exit(static_cast<int>(static_cast<std::uint32_t>(context->registers[kRegisterArgument0])));
}
void win32_terminate_process(GuestContext* context) {
  (void)context;
  std::fflush(stdout);
  std::exit(1);
}
void win32_zero(GuestContext* context) { context->registers[kRegisterReturnValue] = 0; }
void win32_ignore(GuestContext* context) { (void)context; }
void win32_one(GuestContext* context) { context->registers[kRegisterReturnValue] = 1; }
void win32_current_process_id(GuestContext* context) { context->registers[kRegisterReturnValue] = 4321; }
void win32_current_thread_id(GuestContext* context) { context->registers[kRegisterReturnValue] = 4321; }
void win32_current_process(GuestContext* context) { context->registers[kRegisterReturnValue] = static_cast<std::uint64_t>(-1); }
void win32_current_thread(GuestContext* context) { context->registers[kRegisterReturnValue] = static_cast<std::uint64_t>(-2); }
void win32_module_handle(GuestContext* context) { context->registers[kRegisterReturnValue] = recompiled_image_base; }
void win32_is_processor_feature_present(GuestContext* context) { context->registers[kRegisterReturnValue] = 0; }
void win32_get_version(GuestContext* context) { context->registers[kRegisterReturnValue] = 0x0a000000; }
void win32_code_page(GuestContext* context) { context->registers[kRegisterReturnValue] = 65001; }

void win32_virtual_alloc(GuestContext* context) {
  const auto requested = context->registers[kRegisterArgument0];
  const auto size = context->registers[kRegisterArgument1];
  if (requested != 0) { context->registers[kRegisterReturnValue] = requested; return; }
  const auto aligned = (size + 0xfff) & ~0xfffull;
  if (next_heap_address + aligned > guest_memory_size) { context->registers[kRegisterReturnValue] = 0; return; }
  context->registers[kRegisterReturnValue] = next_heap_address;
  next_heap_address += aligned;
}
void win32_virtual_free(GuestContext* context) { context->registers[kRegisterReturnValue] = 1; }
void win32_get_process_heap(GuestContext* context) { context->registers[kRegisterReturnValue] = 0x1000; }
void win32_heap_create(GuestContext* context) { context->registers[kRegisterReturnValue] = 0x1000; }
void win32_heap_alloc(GuestContext* context) {
  const auto size = context->registers[kRegisterArgument2];
  const auto aligned = (size + 0xf) & ~0xfull;
  if (next_heap_address + aligned > guest_memory_size) { context->registers[kRegisterReturnValue] = 0; return; }
  context->registers[kRegisterReturnValue] = next_heap_address;
  next_heap_address += aligned;
}
void win32_heap_free(GuestContext* context) { context->registers[kRegisterReturnValue] = 1; }

void win32_get_tick_count(GuestContext* context) {
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  const auto milliseconds = static_cast<std::uint64_t>(now.tv_sec) * 1000ull +
                            static_cast<std::uint64_t>(now.tv_nsec) / 1000000ull;
  context->registers[kRegisterReturnValue] = static_cast<std::uint32_t>(milliseconds);
}
void win32_query_performance_counter(GuestContext* context) {
  timespec now{};
  ::clock_gettime(CLOCK_MONOTONIC, &now);
  const auto nanoseconds = static_cast<std::uint64_t>(now.tv_sec) * 1000000000ull +
                           static_cast<std::uint64_t>(now.tv_nsec);
  const auto out = context->registers[kRegisterArgument0];
  if (out != 0) store_guest_memory(context, out, nanoseconds, 8);
  context->registers[kRegisterReturnValue] = 1;
}
void win32_query_performance_frequency(GuestContext* context) {
  const auto out = context->registers[kRegisterArgument0];
  if (out != 0) store_guest_memory(context, out, 1000000000ull, 8);
  context->registers[kRegisterReturnValue] = 1;
}
void win32_get_system_time_as_file_time(GuestContext* context) {
  const auto out = context->registers[kRegisterArgument0];
  if (out != 0) { store_guest_memory(context, out, 0, 4); store_guest_memory(context, out + 4, 0, 4); }
}
void win32_get_startup_info(GuestContext* context) {
  const auto out = context->registers[kRegisterArgument0];
  if (out != 0 && out + 68 <= guest_memory_size) std::memset(guest_memory + out, 0, 68);
}
void win32_get_command_line(GuestContext* context) {
  static std::uint64_t offset = 0;
  if (offset == 0) {
    offset = guest_memory_size - 0x100000;
    const char* command_line = "recomp-guest";
    std::memcpy(guest_memory + offset, command_line, std::strlen(command_line) + 1);
  }
  context->registers[kRegisterReturnValue] = offset;
}
void win32_get_environment_strings(GuestContext* context) {
  context->registers[kRegisterReturnValue] = guest_memory_size - 0x200000;
}
void win32_get_system_info(GuestContext* context) {
  const auto out = context->registers[kRegisterArgument0];
  if (out != 0 && out + 48 <= guest_memory_size) std::memset(guest_memory + out, 0, 48);
}
void win32_lstrlen_a(GuestContext* context) {
  context->registers[kRegisterReturnValue] = read_guest_string(context->registers[kRegisterArgument0]).size();
}
void win32_lstrlen_w(GuestContext* context) {
  std::uint64_t address = context->registers[kRegisterArgument0];
  std::uint64_t length = 0;
  while (address + length * 2 + 1 < guest_memory_size && load_guest_memory(context, address + length * 2, 2) != 0) ++length;
  context->registers[kRegisterReturnValue] = length;
}
void win32_lstrcpy_a(GuestContext* context) {
  const auto destination = context->registers[kRegisterArgument0];
  const auto source = context->registers[kRegisterArgument1];
  std::uint64_t index = 0;
  for (;;) {
    const auto byte = static_cast<std::uint8_t>(load_guest_memory(context, source + index, 1));
    store_guest_memory(context, destination + index, byte, 1);
    if (byte == 0) break;
    ++index;
  }
  context->registers[kRegisterReturnValue] = destination;
}
void win32_get_proc_address(GuestContext* context) {
  const auto name = read_guest_string(context->registers[kRegisterArgument1]);
  void (*function)(GuestContext*) = nullptr;
  if (!lookup_win32_import("kernel32.dll", name.c_str(), &function)) {
    terminate_with_message("GetProcAddress(\"%s\") is not implemented", name.c_str());
  }
  static std::uint64_t next_thunk = 0x000000017f000000ull;
  const auto address = next_thunk;
  next_thunk += 0x10;
  register_import_thunk(address, function);
  context->registers[kRegisterReturnValue] = address;
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

bool lookup_win32_import(const char* library_name, const char* symbol_name, void (**function)(GuestContext*)) {
  for (const auto& shim : kShims) {
    if (std::strcmp(shim.library_name, library_name) == 0 && std::strcmp(shim.symbol_name, symbol_name) == 0) {
      *function = shim.function;
      return true;
    }
  }
  return false;
}

bool register_import_thunk(std::uint64_t address, void (*function)(GuestContext*)) {
  import_thunk_addresses.push_back(address);
  import_thunk_functions.push_back(function);
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
  if (auto function = lookup_import_thunk(target)) {
    function(context);
    return;
  }
  terminate_with_message("indirect call to unmapped guest address 0x%" PRIx64 " (ip=0x%" PRIx64 ")", target,
                         context->instruction_pointer);
}

void jump_guest_indirect(GuestContext* context, std::uint64_t target) {
  if (auto function = lookup_guest_function(target)) { function(context); return; }
  if (auto function = lookup_import_thunk(target)) { function(context); return; }
  terminate_with_message("indirect jump to unmapped guest address 0x%" PRIx64 " (ip=0x%" PRIx64 ")", target,
                         context->instruction_pointer);
}

void invoke_win32_import(GuestContext* context, const char* library_name, const char* symbol_name) {
  void (*function)(GuestContext*) = nullptr;
  if (!lookup_win32_import(library_name, symbol_name, &function)) {
    terminate_with_message("unimplemented Win32 import %s!%s (ip=0x%" PRIx64 ")", library_name, symbol_name,
                           context->instruction_pointer);
  }
  function(context);
}

namespace {

void unbound_import_thunk(GuestContext* context) {
  terminate_with_message("call to an unbound import thunk (ip=0x%" PRIx64 ")", context->instruction_pointer);
}

}  // namespace

int run_recompiled_image(const RecompiledImage* image) {
  if (const char* trace_path = std::getenv("RECOMP_TRACE")) {
    guest_trace_stream = std::fopen(trace_path, "wb");
    guest_tracing_enabled = guest_trace_stream != nullptr;
  }
  recompiled_image_base = image->image_base;
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
    const auto thunk_address = kImportThunkBase + static_cast<std::uint64_t>(index) * 0x10;
    register_import_thunk(thunk_address, found ? function : unbound_import_thunk);
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

  store_guest_memory(nullptr, kThreadEnvironmentBlockAddress + 0x08, image->stack_top, 8);
  store_guest_memory(nullptr, kThreadEnvironmentBlockAddress + 0x10, image->stack_top - 0x100000, 8);
  store_guest_memory(nullptr, kThreadEnvironmentBlockAddress + 0x30, kProcessEnvironmentBlockAddress, 8);
  store_guest_memory(nullptr, kThreadEnvironmentBlockAddress + 0x60, kProcessEnvironmentBlockAddress, 8);
  store_guest_memory(nullptr, kProcessEnvironmentBlockAddress + 0x10, image->image_base, 8);
  next_heap_address = image->heap_base;

  GuestContext context{};
  context.registers[kRegisterStackPointer] = image->stack_top;
  context.fs_base = kThreadEnvironmentBlockAddress;
  context.gs_base = kThreadEnvironmentBlockAddress;
  context.x87_control_word = 0x027f;
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
