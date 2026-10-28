# Applications

Applications this studio has actually ported: translated from a Windows PE
binary, built as a native host executable, run, and **differentially verified**
against a Unicorn reference executing the original instructions.

A row appears here only when all of that happened. An application that
translates but does not run, or runs but does not verify, is not a port and is
not listed -- see the refused list at the end of this file for those, with the
reason each one gave.

The screenshot is the ported program's own output, rendered as an image. For a
console application that is the whole observable result, so the image is the
evidence rather than a decoration.

Host: `macos (macos-arm64)`

| application | source arch | source OS | target host | output | screenshot |
|---|---|---|---|---|---|
| `aliasing.exe` | x86_64 | windows | macos (macos-arm64) | 170 bytes | [view](screenshots/aliasing.png) |
| `arith.exe` | x86_64 | windows | macos (macos-arm64) | 161 bytes | [view](screenshots/arith.png) |
| `backward_entry.exe` | x86_64 | windows | macos (macos-arm64) | 30 bytes | [view](screenshots/backward_entry.png) |
| `bitops.exe` | x86_64 | windows | macos (macos-arm64) | 127 bytes | [view](screenshots/bitops.png) |
| `byteops.exe` | x86_64 | windows | macos (macos-arm64) | 130 bytes | [view](screenshots/byteops.png) |
| `calls.exe` | x86_64 | windows | macos (macos-arm64) | 144 bytes | [view](screenshots/calls.png) |
| `eflags.exe` | x86_64 | windows | macos (macos-arm64) | 90 bytes | [view](screenshots/eflags.png) |
| `flagprobe.exe` | x86_64 | windows | macos (macos-arm64) | 15017 bytes | [view](screenshots/flagprobe.png) |
| `heap.exe` | x86_64 | windows | macos (macos-arm64) | 133 bytes | [view](screenshots/heap.png) |
| `memory.exe` | x86_64 | windows | macos (macos-arm64) | 127 bytes | [view](screenshots/memory.png) |
| `packed.exe` | x86_64 | windows | macos (macos-arm64) | 1780 bytes | [view](screenshots/packed.png) |
| `pe32_abi.exe` | x86 | windows | macos (macos-arm64) | 119 bytes | [view](screenshots/pe32_abi.png) |
| `pe32_arith.exe` | x86 | windows | macos (macos-arm64) | 161 bytes | [view](screenshots/pe32_arith.png) |
| `pe32_remill_aas.exe` | x86 | windows | macos (macos-arm64) | 13 bytes | [view](screenshots/pe32_remill_aas.png) |
| `pe32_remill_movhalf.exe` | x86 | windows | macos (macos-arm64) | 50 bytes | [view](screenshots/pe32_remill_movhalf.png) |
| `pe32_simd_convert.exe` | x86 | windows | macos (macos-arm64) | 1261 bytes | [view](screenshots/pe32_simd_convert.png) |
| `remill_movhalf.exe` | x86_64 | windows | macos (macos-arm64) | 50 bytes | [view](screenshots/remill_movhalf.png) |
| `simd_convert.exe` | x86_64 | windows | macos (macos-arm64) | 1261 bytes | [view](screenshots/simd_convert.png) |
| `snake.exe` | x86_64 | windows | macos (macos-arm64) | 297 bytes | [view](screenshots/snake.png) |
| `tail_import.exe` | x86_64 | windows | macos (macos-arm64) | 37 bytes | [view](screenshots/tail_import.png) |
| `teb32.exe` | x86 | windows | macos (macos-arm64) | 133 bytes | [view](screenshots/teb32.png) |
| `tictactoe.exe` | x86_64 | windows | macos (macos-arm64) | 101 bytes | [view](screenshots/tictactoe.png) |
| `unpack.exe` | x86_64 | windows | macos (macos-arm64) | 185 bytes | [view](screenshots/unpack.png) |
| `vecmove.exe` | x86_64 | windows | macos (macos-arm64) | 97 bytes | [view](screenshots/vecmove.png) |
| `wide.exe` | x86_64 | windows | macos (macos-arm64) | 592 bytes | [view](screenshots/wide.png) |
| `x87.exe` | x86_64 | windows | macos (macos-arm64) | 437 bytes | [view](screenshots/x87.png) |

## Refused, with the reason each one gave

Recorded so the list above cannot be mistaken for the whole story. Every entry
here is an application that did **not** reach a verified native port.

| application | reason |
|---|---|
| `unsupported_import.exe` | exited with code 3 |
| `unsupported_instruction.exe` | error: unsupported instruction 'rdmsr' at 0x1400010beull |
| `vex.exe` | did not verify |
