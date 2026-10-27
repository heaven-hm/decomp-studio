#include "recomp_runtime.hpp"

#include <cstdio>
#include <cstring>

extern char** environ;

int main() {
  using namespace recomp;
  if (!map_guest_memory(kGuestAddressSpaceBytes)) return 1;
  for (const int width : {4, 8}) {
    guest_pointer_width = width;
    initialize_guest_state(0x100000, 0x70000000);
    GuestContext context{};
    if (!invoke_shared_shim(&context, "kernel32.dll", "GetCommandLineA")) return 2;
    const auto command = context.registers[0];
    if (command == 0 || std::strcmp(reinterpret_cast<const char*>(guest_memory + command), "recomp-guest") != 0)
      return 3;
    if (!invoke_shared_shim(&context, "api-ms-win-crt-runtime-l1-1-0.dll", "__p__acmdln")) return 4;
    const auto address = context.registers[0];
    if (address == 0 || load_guest_memory(&context, address, width) != command) return 5;
    if (!invoke_shared_shim(&context, "kernel32.dll", "GetEnvironmentStringsW")) return 6;
    if (context.registers[0] == command) return 7;
    if (std::strcmp(reinterpret_cast<const char*>(guest_memory + command), "recomp-guest") != 0) return 8;
    if (environ && environ[0] && load_guest_memory(&context, context.registers[0], 2) !=
                                     static_cast<unsigned char>(environ[0][0])) return 9;
    std::printf("width=%d command-line and CRT pointer passed\n", width);
  }
  return 0;
}
