#include <cstdint>
#include <cstdio>
extern "C" {
#include "win32hle.h"
void recomp_register_pcrecomp_stateless_crt();
extern const recomp_dispatch_entry_t recomp_dispatch_table[] = {{0, nullptr}};
extern const std::uint32_t recomp_dispatch_count = 0;
}

int main() {
  recomp_register_pcrecomp_stateless_crt();
  mach_enter();
  const auto initial_stack = g_esp;
  for (int i = 0; i < 64; ++i) {
    const auto function = recomp_lookup_import(hle_resolve("isalnum"));
    if (!function) return 1;
    PUSH32(g_esp, 'A');
    PUSH32(g_esp, 0x12345678);
    function();
    if (g_eax == 0 || g_esp != initial_stack - 4 || MEM32(g_esp) != 'A') return 2;
    g_esp += 4;
  }
  const auto function = recomp_lookup_import(hle_resolve("toupper"));
  PUSH32(g_esp, 'q');
  PUSH32(g_esp, 0x12345678);
  function();
  if (g_eax != 'Q' || g_esp != initial_stack - 4) return 3;
  g_esp += 4;
  const struct { const char* name; char input; int expected; } cases[] = {
    {"tolower", 'Q', 'q'}, {"isalpha", '7', 0}, {"isdigit", 'A', 0}};
  for (const auto& item : cases) {
    const auto call = recomp_lookup_import(hle_resolve(item.name));
    if (!call) return 5;
    PUSH32(g_esp, item.input);
    PUSH32(g_esp, 0x12345678);
    call();
    if (g_eax != static_cast<std::uint32_t>(item.expected) || g_esp != initial_stack - 4) return 6;
    g_esp += 4;
  }
  if (hle_resolve("malloc") != 0) return 4;
  mach_leave();
  std::puts("PCRecomp stateless CRT bridge passed");
}
