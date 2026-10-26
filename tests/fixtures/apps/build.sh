#!/usr/bin/env bash
# Build the recomp-studio fixture apps as real Win64 PE executables with mingw-w64.
# Freestanding (-nostdlib) so the import surface stays tiny and honest.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/bin}"
CC="${CC:-x86_64-w64-mingw32-gcc}"
mkdir -p "$out"

for name in arith tictactoe snake; do
  "$CC" -O2 -nostdlib -ffreestanding \
        -fno-asynchronous-unwind-tables -fno-stack-protector -fno-tree-vectorize -fno-tree-slp-vectorize \
        -Wl,-e,recomp_entry -Wl,--subsystem,console \
        -o "$out/$name.exe" "$here/$name.c" -lkernel32 -lgcc
  echo "built $out/$name.exe"
done
