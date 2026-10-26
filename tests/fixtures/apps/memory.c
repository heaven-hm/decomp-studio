/* Memory-addressing fixture.
 *
 * Exercises base+index*scale+displacement, byte/word/dword/qword loads and
 * stores, RIP-relative access to read-only data, pointer arithmetic and
 * struct field offsets, so a wrong effective-address calculation or access
 * width changes the printed checksum. */
#include "fy.h"

typedef struct {
  u8 tag;
  u16 flags;
  u32 count;
  u64 total;
  i32 delta;
} Record;

static const u32 kTable[8] = {3u, 1u, 4u, 1u, 5u, 9u, 2u, 6u};

static Record records[6];

int app_main(void) {
  out("memory:start"); crlf();

  /* Statically initialised read-only data (RIP-relative in the code). */
  u64 checksum = 0;
  for (int index = 0; index < 8; index++) checksum += kTable[index] * (u64)(index + 1);
  out("table_checksum="); outi(checksum); crlf();

  /* Byte / word / dword / qword stores into a struct, then read back. */
  for (int index = 0; index < 6; index++) {
    records[index].tag = (u8)(index * 11 + 1);
    records[index].flags = (u16)(index * 4099 + 7);
    records[index].count = (u32)(index * 2654435761u);
    records[index].total = (u64)index * 0x0102030405060708ull;
    records[index].delta = (i32)(index * -7717);
  }

  u64 aggregate = 0;
  for (int index = 0; index < 6; index++) {
    aggregate += records[index].tag;
    aggregate += records[index].flags;
    aggregate += records[index].count;
    aggregate += records[index].total;
    aggregate += (u32)records[index].delta;
  }
  out("struct_aggregate="); outi(aggregate); crlf();

  /* Base + index * scale addressing over a byte buffer. */
  u8 buffer[64];
  for (int index = 0; index < 64; index++) buffer[index] = (u8)(index * 3 + 1);
  u32 strided = 0;
  for (int index = 0; index < 16; index++) strided += buffer[index * 4];
  out("strided="); outi(strided); crlf();

  /* Negative displacement from a base pointer. */
  u8* pointer = buffer + 32;
  u32 backwards = 0;
  for (int index = 1; index <= 8; index++) backwards += pointer[-index * 2];
  out("backwards="); outi(backwards); crlf();

  /* Unaligned access must read the exact little-endian value. */
  u8 unaligned[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  u32 unaligned_value;
  u8* source = unaligned + 1;
  for (int index = 0; index < 4; index++) ((u8*)&unaligned_value)[index] = source[index];
  out("unaligned="); outi(unaligned_value); crlf();

  out("memory:done"); crlf();
  return 0;
}
