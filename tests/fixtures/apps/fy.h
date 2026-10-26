/* Minimal freestanding Win64 runtime for recomp-studio fixtures.
 *
 * Compiled with mingw-w64 -nostdlib so the resulting PE has real compiler
 * machine code and a tiny import surface (GetStdHandle, WriteFile,
 * ExitProcess). This keeps the recompiler's Win32 shim layer honest and small
 * while still exercising genuine GCC code generation.
 */
#ifndef RECOMP_FIXTURE_H
#define RECOMP_FIXTURE_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
typedef int i32;
typedef void* HANDLE;

#define STD_OUTPUT_HANDLE ((u32)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(u32 which);
__declspec(dllimport) int __stdcall WriteFile(HANDLE h, const void* buf, u32 len, u32* written, void* ov);
__declspec(dllimport) void __stdcall ExitProcess(u32 code);

static u32 slen(const char* s) { u32 n = 0; while (s[n]) n++; return n; }

static void out(const char* s) {
  u32 written = 0;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, slen(s), &written, 0);
}

static void outc(char c) {
  u32 written = 0;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &c, 1, &written, 0);
}

/* Print a signed 64-bit integer in base 10. */
static void outi(i64 v) {
  char buf[24];
  int i = 0;
  unsigned long long u;
  if (v < 0) { outc('-'); u = (unsigned long long)(-v); } else { u = (unsigned long long)v; }
  if (u == 0) { outc('0'); return; }
  while (u > 0) { buf[i++] = (char)('0' + (int)(u % 10)); u /= 10; }
  while (i > 0) outc(buf[--i]);
}

static void crlf(void) { outc('\r'); outc('\n'); }

int app_main(void);

void recomp_entry(void) {
  int rc = app_main();
  ExitProcess((u32)rc);
}

#endif
