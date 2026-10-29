#include "recomp_runtime.hpp"

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <unistd.h>

int main() {
  using namespace recomp;
  if (!map_guest_memory(kGuestAddressSpaceBytes)) return 1;
  for (const int width : {4, 8}) {
    guest_pointer_width = width;
    initialize_guest_state(0x100000, 0x70000000, 0x7fff0000);
    for (const std::uint64_t pointer : {0ull, 0x200000ull}) {
      GuestContext context{};
      context.registers[1] = pointer;
      context.registers[2] = 0xdeadbeef;
      context.registers[4] = 0x700000;
      store_guest_memory(&context, context.registers[4] + 4, pointer, 4);
      store_guest_memory(&context, 0x200000, 0xdeadbeefcafebabeull, 8);
      // DETERMINISM, not agreement with the host clock. The old assertion here was that the
      // guest's time lay between two HOST readings -- and that assertion is what the
      // divergence proved wrong: the candidate and the reference are different processes, so
      // bracketing the host clock let them receive different seconds and, for a program that
      // seeds its RNG from the time, take different branches. Measured: `hangman` diverged in
      // about 8% of runs before this and 0 of 42 after.
      if (!invoke_shared_shim(&context, "api-ms-win-crt-time-l1-1-0.dll", "_time64")) return 2;
      const auto returned = width == 4 ? (context.registers[0] | (context.registers[2] << 32))
                                       : context.registers[0];
      // A plausible instant, not zero: zero is 1970, which is a different answer rather than
      // a missing one, and a program that computes an age from it would behave oddly.
      if (returned < 1000000000ull) return 3;
      // And the SAME instant on a second call, which is what both sides now rely on.
      GuestContext repeat{};
      repeat.registers[4] = 0x700000;
      store_guest_memory(&repeat, 0x700004, 0, 4);
      if (!invoke_shared_shim(&repeat, "api-ms-win-crt-time-l1-1-0.dll", "_time64")) return 5;
      const auto second = width == 4 ? (repeat.registers[0] | (repeat.registers[2] << 32))
                                     : repeat.registers[0];
      if (second != returned) return 6;
      if (pointer && load_guest_memory(&context, pointer, 8) != returned) return 4;
    }
    GuestContext tail{};
    tail.registers[4] = 0x700000;
    push_guest_stack(&tail, 0x12345678);
    invoke_win32_import_tail(&tail, "msvcrt.dll", "rand");
    if (tail.registers[4] != 0x700000) return 5;
    void (*shim)(GuestContext*) = nullptr;
    if (!lookup_win32_import("msvcrt.dll", "rand", &shim)) return 6;
    const auto thunk = 0x500000ull + width * 16;
    if (!register_import_thunk(thunk, shim, "msvcrt.dll", "rand")) return 7;
    push_guest_stack(&tail, 0x12345678);
    jump_guest_indirect(&tail, thunk);
    if (tail.registers[4] != 0x700000) return 8;
    std::string captured;
    guest_output_capture = &captured;
    std::memcpy(guest_memory + 0x210000, "hello", 6);
    GuestContext output{};
    output.registers[4] = 0x700000;
    output.registers[1] = 0x210000;
    store_guest_memory(&output, output.registers[4] + 4, 0x210000, 4);
    if (!invoke_shared_shim(&output, "api-ms-win-crt-stdio-l1-1-0.dll", "puts")) return 9;
    if (static_cast<std::int32_t>(output.registers[0]) < 0 || captured != "hello\n") return 10;
    output.registers[1] = '!';
    store_guest_memory(&output, output.registers[4] + 4, '!', 4);
    if (!invoke_shared_shim(&output, "api-ms-win-crt-stdio-l1-1-0.dll", "putchar")) return 11;
    if (output.registers[0] != '!' || captured != "hello\n!") return 12;
    guest_output_capture = nullptr;
    GuestContext local{};
    local.registers[1] = 0x220000;
    local.registers[4] = 0x700000;
    store_guest_memory(&local, local.registers[4] + 4, 0x220000, 4);
    // ASK THE RUNTIME, not the host. The host clock is no longer what the guest sees, so a
    // test that brackets `std::time(nullptr)` is testing the wrong contract -- and it was
    // testing the wrong contract before too, because that is exactly the coupling that let
    // the candidate and the reference disagree. The runtime's own `_time64` is the single
    // source of truth here, and `GetLocalTime` must agree with IT.
    if (!invoke_shared_shim(&local, "api-ms-win-crt-time-l1-1-0.dll", "_time64")) return 12;
    const auto before_local = static_cast<std::time_t>(local.registers[0]);
    if (!invoke_shared_shim(&local, "kernel32.dll", "GetLocalTime")) return 13;
    const auto after_local = before_local;
    const auto matches = [&](std::time_t time) {
      std::tm fields{};
      if (!localtime_r(&time, &fields)) return false;
      return load_guest_memory(&local, 0x220000, 2) == static_cast<unsigned>(fields.tm_year + 1900) &&
             load_guest_memory(&local, 0x220002, 2) == static_cast<unsigned>(fields.tm_mon + 1) &&
             load_guest_memory(&local, 0x220004, 2) == static_cast<unsigned>(fields.tm_wday) &&
             load_guest_memory(&local, 0x220006, 2) == static_cast<unsigned>(fields.tm_mday) &&
             load_guest_memory(&local, 0x220008, 2) == static_cast<unsigned>(fields.tm_hour) &&
             load_guest_memory(&local, 0x22000a, 2) == static_cast<unsigned>(fields.tm_min) &&
             load_guest_memory(&local, 0x22000c, 2) == static_cast<unsigned>(fields.tm_sec);
    };
    if (!matches(before_local) && !matches(after_local)) return 14;
    if (load_guest_memory(&local, 0x22000e, 2) != 0) return 15;
    GuestContext io{};
    io.registers[4] = 0x700000;
    io.registers[1] = 0;
    store_guest_memory(&io, io.registers[4] + 4, 0, 4);
    if (!invoke_shared_shim(&io, "msvcrt.dll", "__acrt_iob_func")) return 16;
    const auto stream = io.registers[0];
    std::memcpy(guest_memory + 0x230000, " %c", 4);
    store_guest_memory(&io, 0x230100, 0x230200, width);
    if (width == 8) {
      io.registers[1] = 2; io.registers[2] = stream; io.registers[8] = 0x230000; io.registers[9] = 0;
      store_guest_memory(&io, io.registers[4] + 0x28, 0x230100, 8);
    } else {
      store_guest_memory(&io, io.registers[4] + 4, 0, 8);
      store_guest_memory(&io, io.registers[4] + 12, stream, 4);
      store_guest_memory(&io, io.registers[4] + 16, 0x230000, 4);
      store_guest_memory(&io, io.registers[4] + 20, 0, 4);
      store_guest_memory(&io, io.registers[4] + 24, 0x230100, 4);
    }
    const auto saved_stdin = dup(STDIN_FILENO);
    int pipe_fds[2];
    if (saved_stdin < 0 || pipe(pipe_fds) != 0) return 17;
    if (write(pipe_fds[1], " \tQx", 4) != 4) return 18;
    close(pipe_fds[1]);
    if (dup2(pipe_fds[0], STDIN_FILENO) < 0) return 19;
    close(pipe_fds[0]);
    clearerr(stdin);
    if (!invoke_shared_shim(&io, "api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vfscanf")) return 20;
    if (io.registers[0] != 1 || load_guest_memory(&io, 0x230200, 1) != 'Q' || std::fgetc(stdin) != 'x') return 21;
    if (!invoke_shared_shim(&io, "api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vfscanf")) return 22;
    if (static_cast<std::int32_t>(io.registers[0]) != -1) return 23;
    if (dup2(saved_stdin, STDIN_FILENO) < 0) return 24;
    close(saved_stdin);
     clearerr(stdin);
  }
  return 0;
}
