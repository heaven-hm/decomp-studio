#!/usr/bin/env bash
# Build the recomp-studio fixture apps as real Windows PE executables.
#
# Reproducible: --no-insert-timestamp removes the PE timestamp so repeated
# builds of identical sources produce byte-identical binaries. The list of
# fixtures and their SHA-256 digests is written to fixtures.sha256.
#
# Usage: build.sh [output-directory]
#   CC   override the 64-bit compiler (default x86_64-w64-mingw32-gcc)
#   CC32 override the 32-bit compiler (default i686-w64-mingw32-gcc)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/bin}"
CC="${CC:-x86_64-w64-mingw32-gcc}"
CC32="${CC32:-i686-w64-mingw32-gcc}"

mkdir -p "$out"

# Fixtures that must build and pass for the 64-bit target.
FIXTURES_X64="arith tictactoe snake aliasing eflags calls memory flagprobe wide byteops bitops x87 simd_convert vecmove heap packed backward_entry unpack remill_movhalf movhps shufpd pinsrw pextrw"

# VEX/AVX fixture: needs -mavx so the compiler emits genuine VEX encodings.
FIXTURES_AVX="vex"

# AVX2 fixture: VPBROADCASTB has genuine 256-bit VEX forms.
FIXTURES_AVX2="vpbroadcast"

# Fixtures that must build and pass for the 32-bit target, as source:output pairs
# so they never collide with the 64-bit fixture built from the same source.
FIXTURES_X86="pe32_abi:pe32_abi simd_convert:pe32_simd_convert teb32:teb32 remill_movhalf:pe32_remill_movhalf remill_aas:pe32_remill_aas legacy32:pe32_legacy32 shufpd:pe32_shufpd popal:pe32_popal"

# Negative fixtures: these must fail explicitly, so they are not in FIXTURES_X64.
FIXTURES_NEGATIVE="unsupported_instruction unsupported_import"
COMMON_FLAGS="-O2 -nostdlib -ffreestanding -fno-asynchronous-unwind-tables -fno-stack-protector -fno-tree-vectorize -fno-tree-slp-vectorize -Wl,--no-insert-timestamp"

build_one() {
  local compiler="$1" source="$2" output="$3" extra_flags="${4:-}"
  "$compiler" $COMMON_FLAGS $extra_flags -Wl,-e,recomp_entry -Wl,--subsystem,console \
      -o "$out/$output.exe" "$here/$source.c" -lkernel32 -lgcc
  echo "built $out/$output.exe"
}

for name in $FIXTURES_X64; do
  if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: $CC not found; cannot build required fixture $name" >&2
    exit 1
  fi
  build_one "$CC" "$name" "$name"
done

"$CC" $COMMON_FLAGS -Wl,-e,recomp_entry -Wl,--subsystem,console \
    -o "$out/tail_import.exe" "$here/tail_import.c" -lkernel32 -lmsvcrt -lgcc

# The file-backed fixture reaches the host through the CRT as well as kernel32, so
# it links msvcrt explicitly. Built for both widths: on PE32 the same source also
# exercises cdecl stack cleanup (fopen) beside stdcall (CreateFileA).
"$CC" $COMMON_FLAGS -Wl,-e,recomp_entry -Wl,--subsystem,console \
    -o "$out/file_streams.exe" "$here/file_streams.c" -lkernel32 -lmsvcrt -lgcc
echo "built $out/file_streams.exe"

for name in $FIXTURES_AVX; do
  if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: $CC not found; cannot build required fixture $name" >&2
    exit 1
  fi
  build_one "$CC" "$name" "$name" "-mavx"
done

for name in $FIXTURES_AVX2; do
  if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: $CC not found; cannot build required fixture $name" >&2
    exit 1
  fi
  build_one "$CC" "$name" "$name" "-mavx2"
done

# 32-bit fixtures are built when the i686 toolchain is present. They are used by
# the PE32 regression tests.
if command -v "$CC32" >/dev/null 2>&1; then
  build_one "$CC32" "arith" "pe32_arith"
  for entry in $FIXTURES_X86; do
    build_one "$CC32" "${entry%%:*}" "${entry##*:}" "-msse2"
  done
  "$CC32" $COMMON_FLAGS -Wl,-e,recomp_entry -Wl,--subsystem,console \
      -o "$out/pe32_file_streams.exe" "$here/file_streams.c" -lkernel32 -lmsvcrt -lgcc
  echo "built $out/pe32_file_streams.exe"
fi

# Negative fixtures are built separately because they need extra libraries.
if command -v "$CC" >/dev/null 2>&1; then
  for name in $FIXTURES_NEGATIVE; do
    extra=""
    [ "$name" = "unsupported_import" ] && extra="-luser32"
    "$CC" $COMMON_FLAGS -Wl,-e,recomp_entry -Wl,--subsystem,console \
        -o "$out/$name.exe" "$here/$name.c" -lkernel32 $extra -lgcc
    echo "built $out/$name.exe (negative)"
  done
fi

( cd "$out" && shasum -a 256 ./*.exe > fixtures.sha256 && echo "wrote $out/fixtures.sha256" )
