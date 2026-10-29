#include "recomp_runtime.hpp"

#include <cstdio>
#include <cstring>

extern char** environ;

int main() {
  using namespace recomp;
  if (!map_guest_memory(kGuestAddressSpaceBytes)) return 1;
  for (const int width : {4, 8}) {
    guest_pointer_width = width;
    initialize_guest_state(0x100000, 0x70000000, 0x7fff0000);
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
    // The guest's environment is a FIXED set, not the host's. Asserting that it matched
    // `environ[0]` was the same wrong premise the clock test had: the candidate is a
    // subprocess and the reference is not, so their host environments differ by construction
    // and a guest reading either one sees a different answer. What matters is that the
    // block is well-formed, non-empty, and the SAME on both sides -- which is what a fixed
    // set gives and what the host's environment cannot.
    // The shim called above is `GetEnvironmentStringsW`, so this is the WIDE block and its
    // first variable reads as UTF-16. Reading it as ANSI is exactly the mistake the
    // environment work was about, and it is worth the two lines to be explicit.
    if (load_guest_memory(&context, context.registers[0], 2) == 0) return 9;
    const auto* wide = reinterpret_cast<const std::uint16_t*>(guest_memory + context.registers[0]);
    if (wide[0] != 'P' || wide[1] != 'A' || wide[2] != 'T' || wide[3] != 'H' || wide[4] != '=')
      return 10;
    // The runtime reports UTF-8 as its ANSI code page; UTF-8 has no DBCS lead bytes.
    for (const auto byte : {0x41, 0x81, 0xc2, 0xff}) {
      context.registers[1] = byte;
      context.registers[4] = 0x700000;
      store_guest_memory(&context, context.registers[4] + 4, byte, 4);
      if (!invoke_shared_shim(&context, "kernel32.dll", "IsDBCSLeadByte")) return 10;
      if (context.registers[0] != 0) return 11;
    }
    std::printf("width=%d command-line and CRT pointer passed\n", width);
  }
  return 0;
}
