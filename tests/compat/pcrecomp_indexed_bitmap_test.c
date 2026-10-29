/* Exercise packed DIB pixels through PCRecomp's real GDI import path. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "win32hle.h"
#include "host.h"

const recomp_dispatch_entry_t recomp_dispatch_table[1];
const uint32_t recomp_dispatch_count = 0;
static uint32_t call(const char *name, int n, const uint32_t *args) {
  return hle_call_guest(hle_resolve(name), n, args);
}

static int check_bitmap(int bpp) {
  uint32_t screen[4] = {0};
  hle_gdi_window_surface((uint8_t *)screen, 4, 1, 16, 32);
  uint8_t *bmi = hle_alloc(40 + 16 * 4);
  memset(bmi, 0, 40 + 16 * 4);
  bmi[0] = 40; bmi[4] = 4; bmi[8] = 1; bmi[12] = 1; bmi[14] = (uint8_t)bpp;
  uint32_t colors[] = {0x00000000, 0x00ff0000, 0x0000ff00, 0x000000ff, 0x00ffffff};
  memcpy(bmi + 40, colors, sizeof colors);
  uint32_t *bits = hle_alloc(4);
  uint32_t create[] = {0, hle_va(bmi), 0, hle_va(bits), 0, 0};
  uint32_t bitmap = call("CreateDIBSection", 6, create);
  if (!bitmap || !*bits) return 0;
  uint8_t *pixels = hle_ptr(*bits);
  pixels[0] = bpp == 4 ? 0x12 : 0xa0;
  pixels[1] = bpp == 4 ? 0x34 : 0;
  uint32_t zero = 0, memory = call("CreateCompatibleDC", 1, &zero);
  uint32_t select[] = {memory, bitmap};
  call("SelectObject", 2, select);
  uint32_t window = call("GetDC", 1, &zero);
  uint32_t blit[] = {window, 0, 0, 4, 1, memory, 0, 0, 0x00cc0020};
  call("BitBlt", 9, blit);
  const uint32_t *expected = bpp == 4 ? colors + 1 : (const uint32_t[]){colors[1], colors[0], colors[1], colors[0]};
  for (int i = 0; i < 4; ++i) if (screen[i] != expected[i]) return 0;
  return 1;
}

int main(void) {
  recomp_host_init();
  int ok4 = check_bitmap(4), ok1 = check_bitmap(1);
  if (!ok4 || !ok1) fprintf(stderr, "indexed bitmap mismatch: 4-bit=%d 1-bit=%d\n", ok4, ok1);
  return !(ok4 && ok1);
}
