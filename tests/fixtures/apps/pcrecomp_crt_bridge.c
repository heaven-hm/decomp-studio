/* A real PE32 import call that exercises the PCRecomp/CRT cdecl bridge. */
#include "fy.h"
__declspec(dllimport) int __cdecl isalnum(int);

int app_main(void) {
  for (int i = 0; i < 64; ++i) {
    if (!isalnum('A') || isalnum('!')) return 1;
  }
  out("character imports passed"); crlf();
  return 0;
}
