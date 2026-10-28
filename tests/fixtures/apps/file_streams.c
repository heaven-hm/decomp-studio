/* File-backed fixture: real open/read/write/close through the runtime.
 *
 * Everything else in this suite reaches the host through the three standard
 * handles. A program that reads a data file exercises a different set of things
 * at once -- a path that has to resolve, a handle that has to mean the file it
 * came from, a position that has to advance, an end-of-file that has to be
 * distinguishable from an error, and a failure that has to be reported as a
 * failure instead of as zero bytes of nothing.
 *
 * The checksums are the point: they cover the bytes that actually came back, so
 * a stream that silently reads nothing still produces a wrong number rather than
 * a plausible-looking success line.
 *
 * Built for both widths (file_streams.exe on PE32+, pe32_file_streams.exe on
 * PE32). The 32-bit form additionally exercises cdecl versus stdcall stack
 * cleanup on the same source: fopen pops, CreateFileA does not.
 */
#include "fy.h"

#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define GENERIC_READ  0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ  1u
#define FILE_SHARE_WRITE 2u
#define CREATE_NEW          1u
#define CREATE_ALWAYS       2u
#define OPEN_EXISTING       3u
#define FILE_ATTRIBUTE_DIRECTORY 0x10u
#define FILE_ATTRIBUTE_ARCHIVE   0x80u
#define INVALID_FILE_ATTRIBUTES  0xffffffffu
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED  5u

__declspec(dllimport) HANDLE __stdcall CreateFileA(const char* name, u32 access, u32 share,
                                                    void* security, u32 disposition, u32 flags,
                                                    HANDLE template_file);
__declspec(dllimport) int __stdcall ReadFile(HANDLE h, void* buffer, u32 length, u32* read, void* overlapped);
__declspec(dllimport) int __stdcall CloseHandle(HANDLE h);
__declspec(dllimport) u32 __stdcall SetFilePointer(HANDLE h, i32 distance, u32* high_distance, u32 origin);
__declspec(dllimport) u32 __stdcall GetFileSize(HANDLE h, u32* high_size);
__declspec(dllimport) int __stdcall DeleteFileA(const char* name);
__declspec(dllimport) u32 __stdcall GetFileAttributesA(const char* name);
__declspec(dllimport) u32 __stdcall GetLastError(void);
__declspec(dllimport) u32 __stdcall GetModuleFileNameA(HANDLE module, char* buffer, u32 length);

typedef struct _GUEST_FILE FILE;
__declspec(dllimport) FILE* fopen(const char* path, const char* mode);
__declspec(dllimport) int fclose(FILE* stream);
__declspec(dllimport) u32 fread(void* buffer, u32 size, u32 count, FILE* stream);
__declspec(dllimport) u32 fwrite(const void* buffer, u32 size, u32 count, FILE* stream);
__declspec(dllimport) int fseek(FILE* stream, i32 offset, int origin);
__declspec(dllimport) i32 ftell(FILE* stream);
__declspec(dllimport) int feof(FILE* stream);
__declspec(dllimport) int ferror(FILE* stream);
__declspec(dllimport) int fgetc(FILE* stream);
__declspec(dllimport) int ungetc(int character, FILE* stream);
__declspec(dllimport) char* fgets(char* buffer, int count, FILE* stream);
__declspec(dllimport) int _open(const char* path, int flags, int mode);
__declspec(dllimport) int _close(int descriptor);
__declspec(dllimport) int _read(int descriptor, void* buffer, unsigned count);
__declspec(dllimport) int _write(int descriptor, const void* buffer, unsigned count);
__declspec(dllimport) int _lseek(int descriptor, i32 offset, int origin);

/* _O_RDONLY 0, _O_WRONLY 1, _O_RDWR 2, _O_CREAT 0x100, _O_TRUNC 0x200. */
#define O_RDONLY_ 0x0000
#define O_WRONLY_ 0x0001
#define O_RDWR_   0x0002
#define O_CREAT_  0x0100
#define O_TRUNC_  0x0200

#define SEEK_SET_ 0
#define SEEK_CUR_ 1
#define SEEK_END_ 2

static u64 checksum(const u8* data, u32 length) {
  u64 value = 1469598103934665603ull;
  for (u32 i = 0; i < length; i++) { value ^= data[i]; value *= 1099511628211ull; }
  return value;
}

/* A 777-byte block with a repeatable pattern, so a stream that reads the right
   number of bytes but from the wrong offset still produces a different hash. */
static void fill_pattern(u8* buffer, u32 length) {
  for (u32 i = 0; i < length; i++) buffer[i] = (u8)((i * 31u + (i / 7u) * 17u) & 0xffu);
}

static const char* PATH = "fs_probe.dat";
static const char* RAW_PATH = "fs_probe_raw.dat";
static const char* HANDLE_PATH = "fs_probe_handle.dat";
static const char* BLOCK = "0123456789abcdefghijklmnopqrstuvwxyz\n";

int app_main(void) {
  out("file_streams:start"); crlf();
  const u32 block_bytes = 777;
  static u8 tail_holder[8];
  u32 error_code = 0;

  /* --- 1. fopen / fwrite / fclose --------------------------------------- */
  FILE* writing = fopen(PATH, "wb");
  out("fopen_write="); outi(writing != 0 ? 1 : 0); crlf();
  if (writing == 0) { out("abort:fopen_write"); crlf(); return 1; }

  u8 source[1024];
  fill_pattern(source, block_bytes);
  const u32 items = fwrite(source, 1, block_bytes, writing);
  out("fwrite_items="); outi(items); crlf();
  out("fclose="); outi(fclose(writing)); crlf();

  /* --- 2. fopen / fread / ftell / fseek / feof --------------------------- */
  FILE* reading = fopen(PATH, "rb");
  out("fopen_read="); outi(reading != 0 ? 1 : 0); crlf();
  if (reading == 0) return 2;

  u8 mirror[1024];
  const u32 read_items = fread(mirror, 1, block_bytes, reading);
  out("fread_items="); outi(read_items); crlf();
  out("read_checksum="); outi((i64)checksum(mirror, read_items)); crlf();
  out("matches_source="); outi(checksum(mirror, read_items) == checksum(source, block_bytes) ? 1 : 0); crlf();

  out("ftell_after_read="); outi(ftell(reading)); crlf();
  out("feof_after_read="); outi(feof(reading)); crlf();
  out("ferror_after_read="); outi(ferror(reading)); crlf();

  /* Rewind by seeking, then read one byte and put it back. A stream whose
     position does not move returns the same byte twice, which is the failure
     this checks for; ungetc then has to hand back the byte it was given before
     the next read advances again. */
  out("fseek_set="); outi(fseek(reading, 0, SEEK_SET_)); crlf();
  out("ftell_after_seek="); outi(ftell(reading)); crlf();
  const int first = fgetc(reading);
  out("fgetc_first="); outi(first); crlf();
  out("ungetc="); outi(ungetc(first, reading)); crlf();
  out("fgetc_after_ungetc="); outi(fgetc(reading)); crlf();
  out("fgetc_next_differs="); outi(fgetc(reading) != first ? 1 : 0); crlf();

  /* Seek to the end and read: the count has to be zero and feof has to say so,
     because "no bytes" and "no more bytes" are different answers to the caller. */
  fseek(reading, 0, SEEK_END_);
  u8 spare[8];
  out("fread_at_end="); outi(fread(spare, 1, 8, reading)); crlf();
  out("feof_at_end="); outi(feof(reading)); crlf();
  fclose(reading);

  /* --- 3. _open / _write / _read / _lseek / _close ----------------------- */
  const int descriptor = _open(RAW_PATH, O_WRONLY_ | O_CREAT_ | O_TRUNC_, 0644);
  out("low_write_descriptor="); outi(descriptor >= 0 ? 1 : 0); crlf();
  const int raw_length = 36;
  out("low_write="); outi(_write(descriptor, BLOCK, (unsigned)raw_length)); crlf();
  out("low_close="); outi(_close(descriptor)); crlf();

  const int reading_descriptor = _open(RAW_PATH, O_RDONLY_, 0);
  u8 raw[64];
  out("low_read="); outi(_read(reading_descriptor, raw, (unsigned)raw_length)); crlf();
  out("low_read_checksum="); outi((i64)checksum(raw, (u32)raw_length)); crlf();
  out("low_lseek="); outi(_lseek(reading_descriptor, 0, SEEK_SET_)); crlf();
  out("low_lseek_to_end="); outi(_lseek(reading_descriptor, -4, SEEK_END_)); crlf();
  /* The count is printed on its own line before the bytes are hashed: argument
     evaluation order is the compiler's to choose, and folding the call into the
     hash argument hides a short read inside a hash of nothing. */
  const int tail_count = _read(reading_descriptor, tail_holder, 4);
  out("low_tail_count="); outi(tail_count); crlf();
  out("low_tail_checksum="); outi((i64)checksum(tail_holder, (u32)(tail_count > 0 ? tail_count : 0))); crlf();
  _close(reading_descriptor);

  /* --- 4. CreateFileA / WriteFile / SetFilePointer / ReadFile ------------ */
  HANDLE handle = CreateFileA(HANDLE_PATH, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
                              CREATE_ALWAYS, 0, 0);
  out("create_write_handle="); outi(handle != INVALID_HANDLE_VALUE ? 1 : 0); crlf();
  u32 transferred = 0;
  out("handle_write="); outi(WriteFile(handle, source, block_bytes, &transferred, 0)); crlf();
  out("handle_written="); outi(transferred); crlf();
  out("handle_close="); outi(CloseHandle(handle)); crlf();

  handle = CreateFileA(HANDLE_PATH, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
  out("create_read_handle="); outi(handle != INVALID_HANDLE_VALUE ? 1 : 0); crlf();
  u32 high_size = 0;
  out("handle_size="); outi(GetFileSize(handle, &high_size)); crlf();
  u8 handle_mirror[1024];
  out("handle_read="); outi(ReadFile(handle, handle_mirror, block_bytes, &transferred, 0)); crlf();
  out("handle_checksum="); outi((i64)checksum(handle_mirror, transferred)); crlf();
  out("handle_matches="); outi(checksum(handle_mirror, transferred) == checksum(source, block_bytes) ? 1 : 0); crlf();
  /* Read again without moving: the file is at its end, so the count is zero. */
  out("handle_read_at_end="); outi(ReadFile(handle, handle_mirror, 8, &transferred, 0)); crlf();
  out("handle_transferred_at_end="); outi(transferred); crlf();
  out("handle_set_pointer="); outi(SetFilePointer(handle, 16, 0, SEEK_SET_)); crlf();
  out("handle_read_at_16="); outi(ReadFile(handle, handle_mirror, 4, &transferred, 0)); crlf();
  out("handle_at_16_checksum="); outi((i64)checksum(handle_mirror, transferred)); crlf();
  CloseHandle(handle);

  /* A closed handle must not keep working. Nothing here can make the runtime
     write to a file the guest no longer owns except by asking it. */
  out("closed_handle_read="); outi(ReadFile(handle, handle_mirror, 4, &transferred, 0)); crlf();
  /* GetLastError is read into a variable before anything else runs. A successful
     WriteFile is allowed to clear it -- on Windows it does -- and a program that
     prints the code after more calls is asking about the last of those instead. */
  error_code = GetLastError();
  out("closed_handle_error="); outi(error_code); crlf();

  /* --- 5. The failure paths --------------------------------------------- */
  /* A file that is not there: NULL, and the error code says which kind of no. */
  FILE* absent = fopen("fs_does_not_exist.dat", "rb");
  error_code = GetLastError();
  out("fopen_absent_null="); outi(absent == 0 ? 1 : 0); crlf();
  out("fopen_absent_error="); outi(error_code); crlf();

  /* A path above the app directory is refused rather than opened. This is the
     check that a recompiled program cannot reach the user's files by spelling
     ".." in a string; the answer has to be a failure the guest can see. */
  FILE* escaped = fopen("../fs_escaped.dat", "wb");
  error_code = GetLastError();
  out("fopen_escape_null="); outi(escaped == 0 ? 1 : 0); crlf();
  out("fopen_escape_error="); outi(error_code); crlf();
  if (escaped != 0) { out("ESCAPED-SANDBOX"); crlf(); fclose(escaped); }

  /* CreateFileA with the same path: a different API, the same policy. */
  HANDLE escaped_handle = CreateFileA("../fs_escaped_handle.dat", GENERIC_WRITE, 0, 0,
                                      CREATE_ALWAYS, 0, 0);
  error_code = GetLastError();
  out("create_escape_invalid="); outi(escaped_handle == INVALID_HANDLE_VALUE ? 1 : 0); crlf();
  out("create_escape_error="); outi(error_code); crlf();

  /* --- 6. Delete and attributes ----------------------------------------- */
  out("attributes_before="); outi(GetFileAttributesA(PATH) != INVALID_FILE_ATTRIBUTES ? 1 : 0); crlf();
  out("delete="); outi(DeleteFileA(PATH)); crlf();
  out("attributes_after="); outi(GetFileAttributesA(PATH) == INVALID_FILE_ATTRIBUTES ? 1 : 0); crlf();
  out("delete_absent="); outi(DeleteFileA("fs_does_not_exist.dat")); crlf();
  error_code = GetLastError();
  out("delete_absent_error="); outi(error_code); crlf();
  DeleteFileA(RAW_PATH);
  DeleteFileA(HANDLE_PATH);

  /* GetModuleFileNameA has to name something: a program that finds its own data
     files by stripping the last component of this path depends on it, and on the
     result resolving back through the same policy that opened the file. */
  char module[512];
  const u32 module_length = GetModuleFileNameA(0, module, sizeof(module));
  out("module_name_nonempty="); outi(module_length != 0 ? 1 : 0); crlf();
  out("module_name_length="); outi(module_length); crlf();
  out("module_name="); out(module); crlf();
  /* The name it returns has to be openable: that is the whole reason it exists. */
  out("module_name_last_is_exe=");
  outi(module_length > 4 && module[module_length - 1] == 'e' && module[module_length - 2] == 'x' &&
       module[module_length - 3] == 'e' && module[module_length - 4] == '.' ? 1 : 0);
  crlf();

  out("file_streams:done"); crlf();
  return 0;
}
