// Glue for the vendored musl stdio engine.
//
// musl's `vfprintf` is a complete, well-tested formatting engine, and this project was
// hand-writing one. The vendored sources are unmodified; what they need from their
// environment is a `FILE` with the fields `vfprintf` touches, a `write` callback, and
// `__fwritex`/`__towrite`, which are vendored alongside.
//
// The one place this file departs from musl is the write itself. musl's own
// `__stdio_write` calls the host `write(2)`; here output must go through
// `write_guest_output`, because that is what captures the guest's stdout for
// verification and what reports a short write to the caller. Routing around it would
// make the captured output and the real output disagree.
//
// The buffers are per-stream and flushed by `__fwritex`, so the observable behaviour is
// musl's: the same padding, precision, flags and conversions, in the same order.

#include "musl/stdio_impl.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

// The guest stream this engine is writing to. Set by the caller before each formatted
// call, so one FILE can serve whichever descriptor the guest asked for.
extern "C" {

// Forward declarations for the vendored translation units.
size_t __fwritex(const unsigned char* restrict s, size_t l, FILE* restrict f);
int __towrite(FILE* f);
int vfprintf(FILE* restrict f, const char* restrict fmt, va_list ap);

// One FILE per guest descriptor, with its own buffer. Static storage keeps the engine
// allocation-free, which matters because it is reached from guest code that may itself
// be inside the guest's allocator.
struct MuslGuestStream {
  FILE file;
  unsigned char buffer[BUFSIZ];
  int descriptor;
  bool ready;
};

MuslGuestStream musl_guest_streams[3] = {};

int musl_guest_write(FILE* f, const unsigned char* data, size_t size) {
  auto* stream = reinterpret_cast<MuslGuestStream*>(f);
  const auto written = write_guest_output(stream->descriptor, reinterpret_cast<const char*>(data), size);
  if (written < 0) return -1;
  return static_cast<int>(written);
}

// The FILE the vendored engine should format into. `descriptor` is the host descriptor
// the guest's stream maps to (0/1/2), which is also the index into the stream table.
FILE* musl_guest_stream_for(int descriptor) {
  if (descriptor < 0 || descriptor > 2) return nullptr;
  auto& stream = musl_guest_streams[descriptor];
  if (!stream.ready) {
    std::memset(&stream.file, 0, sizeof(stream.file));
    stream.descriptor = descriptor;
    stream.file.fd = descriptor;
    stream.file.buf = stream.buffer;
    stream.file.buf_size = sizeof(stream.buffer);
    stream.file.write = musl_guest_write;
    // A line-buffered stdout matches what a console program expects, and a terminal's
    // stderr is unbuffered. Both are what the C standard requires of the standard
    // streams, so a guest that relies on either behaves as it would on Windows.
    stream.file.lbf = descriptor == 2 ? 0 : '\n';
    stream.file.flags = 0;
    stream.ready = true;
  }
  return &stream.file;
}

// Format into a guest stream with musl's engine. Returns the number of characters that
// would have been written, as `vfprintf` does.
int musl_guest_vfprintf(int descriptor, const char* format, va_list arguments) {
  FILE* stream = musl_guest_stream_for(descriptor);
  if (stream == nullptr) return -1;
  const int result = vfprintf(stream, format, arguments);
  // The guest's own `fflush` semantics: a formatted call to a line-buffered stream ends
  // at a newline, and the engine flushes it; anything left is flushed here so the
  // captured output is complete before the caller sees the return value.
  if (stream->wpos > stream->wbase) {
    const auto pending = static_cast<size_t>(stream->wpos - stream->wbase);
    if (musl_guest_write(stream, stream->wbase, pending) >= 0) {
      stream->wpos = stream->wbase;
      stream->wend = stream->wbase;
    }
  }
  return result;
}

}  // extern "C"
