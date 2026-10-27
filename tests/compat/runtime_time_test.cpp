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
  }
  return 0;
}
