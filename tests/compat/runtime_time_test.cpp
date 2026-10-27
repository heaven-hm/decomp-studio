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
  }
  return 0;
}
