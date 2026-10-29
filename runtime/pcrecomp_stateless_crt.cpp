// Narrow PE32 bridge: reuse existing stateless CRT implementations while the
// PCRecomp machine lock is held. Pointer, allocation and callback APIs require
// a shared memory/ownership contract and are deliberately not registered here.
#include "recomp_runtime.hpp"
extern "C" {
#include "win32hle.h"
}

namespace {
void invoke_stateless_crt() {
  if (recomp::guest_memory != nullptr || g_mem_base == 0 || g_cur_import == nullptr)
    hle_fatal("stateless CRT bridge requires exclusive PCRecomp guest memory");
  recomp::GuestContext context{};
  context.registers[4] = g_esp;
  recomp::guest_memory = reinterpret_cast<std::uint8_t*>(g_mem_base);
  recomp::guest_memory_size = 0x100000000ull;
  const auto previous_width = recomp::guest_pointer_width;
  recomp::guest_pointer_width = 4;
  const bool handled = recomp::invoke_shared_shim(&context, "msvcrt.dll", g_cur_import);
  recomp::guest_pointer_width = previous_width;
  recomp::guest_memory = nullptr;
  recomp::guest_memory_size = 0;
  if (!handled) hle_fatal("stateless CRT bridge cannot dispatch %s", g_cur_import);
  g_eax = static_cast<std::uint32_t>(context.registers[0]);
  g_esp += 4;  // cdecl: the caller retains its argument slot.
}

const win32hle_shim shims[] = {{"isalnum", invoke_stateless_crt}, {"isalpha", invoke_stateless_crt},
  {"isdigit", invoke_stateless_crt}, {"toupper", invoke_stateless_crt},
  {"tolower", invoke_stateless_crt}, {nullptr, nullptr}};
}

extern "C" void recomp_register_pcrecomp_stateless_crt() { win32hle_register(shims); }
