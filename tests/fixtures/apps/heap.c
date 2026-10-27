/* Guest heap fixture.
 *
 * HeapFree used to be a no-op and HeapAlloc only bumped a pointer, so a guest
 * that allocates and frees in a loop consumed the heap until allocations
 * started returning null — which is what loading a level does. This fixture
 * allocates a 1 MB block and frees it, two hundred times: 200 MB through a
 * 128 MB region. With the old bump-only allocator it exhausts around round 128
 * and prints the round it died on; with a reclaiming allocator it completes.
 *
 * The checksum covers the bytes written into every block, so a block handed out
 * twice, or reused without being freed, changes the result. */
#include "fy.h"

__declspec(dllimport) HANDLE __stdcall GetProcessHeap(void);
__declspec(dllimport) void* __stdcall HeapAlloc(HANDLE heap, u32 flags, u32 size);
__declspec(dllimport) int __stdcall HeapFree(HANDLE heap, u32 flags, void* block);

#define ROUNDS 200
#define BLOCK_BYTES (1024u * 1024u)

int app_main(void) {
  out("heap:start"); crlf();

  HANDLE heap = GetProcessHeap();
  out("heap_handle_nonzero="); outi(heap != 0 ? 1 : 0); crlf();

  u64 checksum = 0;
  int completed = 0;
  for (int round = 0; round < ROUNDS; round++) {
    u8* block = (u8*)HeapAlloc(heap, 0, BLOCK_BYTES);
    if (block == 0) {
      out("exhausted_at="); outi(round); crlf();
      break;
    }
    /* Touch the first and last byte so a mis-sized block is caught. */
    block[0] = (u8)(round * 7 + 1);
    block[BLOCK_BYTES - 1] = (u8)(round * 13 + 5);
    checksum = checksum * 131 + block[0];
    checksum = checksum * 131 + block[BLOCK_BYTES - 1];
    HeapFree(heap, 0, block);
    completed = round + 1;
  }

  out("rounds_completed="); outi(completed); crlf();
  out("heap_checksum="); outi((i64)checksum); crlf();

  /* Small allocations interleaved with frees exercise splitting and coalescing
     rather than one block being handed straight back. */
  u64 small_checksum = 0;
  for (int round = 0; round < 64; round++) {
    u8* first = (u8*)HeapAlloc(heap, 0, 24);
    u8* second = (u8*)HeapAlloc(heap, 0, 200);
    if (first == 0 || second == 0) {
      out("small_exhausted_at="); outi(round); crlf();
      break;
    }
    first[0] = (u8)round;
    second[0] = (u8)(255 - round);
    small_checksum = small_checksum * 131 + first[0];
    small_checksum = small_checksum * 131 + second[0];
    HeapFree(heap, 0, first);
    HeapFree(heap, 0, second);
  }
  out("small_checksum="); outi((i64)small_checksum); crlf();

  out("heap:done"); crlf();
  return 0;
}
