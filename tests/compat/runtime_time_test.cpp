#include "recomp_runtime.hpp"

#include <cstdint>
#include <ctime>

int main() {
  using namespace recomp;
  if (!map_guest_memory(kGuestAddressSpaceBytes)) return 1;
  for (const int width : {4, 8}) {
    guest_pointer_width = width;
    initialize_guest_state(0x100000, 0x70000000);
    for (const std::uint64_t pointer : {0ull, 0x200000ull}) {
      GuestContext context{};
      context.registers[1] = pointer;
      context.registers[2] = 0xdeadbeef;
      context.registers[4] = 0x700000;
      store_guest_memory(&context, context.registers[4] + 4, pointer, 4);
      store_guest_memory(&context, 0x200000, 0xdeadbeefcafebabeull, 8);
      const auto before = std::time(nullptr);
      if (!invoke_shared_shim(&context, "api-ms-win-crt-time-l1-1-0.dll", "_time64")) return 2;
      const auto after = std::time(nullptr);
      const auto returned = width == 4 ? (context.registers[0] | (context.registers[2] << 32))
                                       : context.registers[0];
      if (returned < static_cast<std::uint64_t>(before) || returned > static_cast<std::uint64_t>(after)) return 3;
      if (pointer && load_guest_memory(&context, pointer, 8) != returned) return 4;
    }
    GuestContext tail{};
    tail.registers[4] = 0x700000;
    push_guest_stack(&tail, 0x12345678);
    invoke_win32_import_tail(&tail, "msvcrt.dll", "rand");
    if (tail.registers[4] != 0x700000) return 5;
    void (*shim)(GuestContext*) = nullptr;
    if (!lookup_win32_import("msvcrt.dll", "rand", &shim)) return 6;
    const auto thunk = 0x500000ull + width * 16;
    if (!register_import_thunk(thunk, shim, "msvcrt.dll", "rand")) return 7;
    push_guest_stack(&tail, 0x12345678);
    jump_guest_indirect(&tail, thunk);
    if (tail.registers[4] != 0x700000) return 8;
    std::string captured;
    guest_output_capture = &captured;
    std::memcpy(guest_memory + 0x210000, "hello", 6);
    GuestContext output{};
    output.registers[4] = 0x700000;
    output.registers[1] = 0x210000;
    store_guest_memory(&output, output.registers[4] + 4, 0x210000, 4);
    if (!invoke_shared_shim(&output, "api-ms-win-crt-stdio-l1-1-0.dll", "puts")) return 9;
    if (static_cast<std::int32_t>(output.registers[0]) < 0 || captured != "hello\n") return 10;
    output.registers[1] = '!';
    store_guest_memory(&output, output.registers[4] + 4, '!', 4);
    if (!invoke_shared_shim(&output, "api-ms-win-crt-stdio-l1-1-0.dll", "putchar")) return 11;
    if (output.registers[0] != '!' || captured != "hello\n!") return 12;
    guest_output_capture = nullptr;
    GuestContext local{};
    local.registers[1] = 0x220000;
    local.registers[4] = 0x700000;
    store_guest_memory(&local, local.registers[4] + 4, 0x220000, 4);
    const auto before_local = std::time(nullptr);
    if (!invoke_shared_shim(&local, "kernel32.dll", "GetLocalTime")) return 13;
    const auto after_local = std::time(nullptr);
    const auto matches = [&](std::time_t time) {
      std::tm fields{};
      if (!localtime_r(&time, &fields)) return false;
      return load_guest_memory(&local, 0x220000, 2) == static_cast<unsigned>(fields.tm_year + 1900) &&
             load_guest_memory(&local, 0x220002, 2) == static_cast<unsigned>(fields.tm_mon + 1) &&
             load_guest_memory(&local, 0x220004, 2) == static_cast<unsigned>(fields.tm_wday) &&
             load_guest_memory(&local, 0x220006, 2) == static_cast<unsigned>(fields.tm_mday) &&
             load_guest_memory(&local, 0x220008, 2) == static_cast<unsigned>(fields.tm_hour) &&
             load_guest_memory(&local, 0x22000a, 2) == static_cast<unsigned>(fields.tm_min) &&
             load_guest_memory(&local, 0x22000c, 2) == static_cast<unsigned>(fields.tm_sec);
    };
    if (!matches(before_local) && !matches(after_local)) return 14;
    if (load_guest_memory(&local, 0x22000e, 2) != 0) return 15;
  }
  return 0;
}
