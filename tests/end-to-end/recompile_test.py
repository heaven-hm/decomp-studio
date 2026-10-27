#!/usr/bin/env python3
"""End-to-end regression: every positive fixture must recompile to a native
binary, run, and pass differential verification against the original x86-64 code.

This test cannot silently pass. If a mandatory toolchain is missing it fails
(unless RECOMP_OPTIONAL=1); if verification is unavailable, incomplete, or
reports anything other than an exact match, it fails.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CLI = sys.argv[1]
APPS_DIRECTORY = Path(sys.argv[2])
OPTIONAL_MODE = os.environ.get("RECOMP_OPTIONAL") == "1"

# 64-bit (PE32+) fixtures that must recompile, execute and verify.
FIXTURES = [
    ("arith", "arithmetic, recursion, flags"),
    ("tictactoe", "minimax game"),
    ("snake", "deterministic simulation"),
    ("aliasing", "register aliasing"),
    ("eflags", "EFLAGS"),
    ("calls", "calling conventions and indirect calls"),
    ("memory", "memory addressing"),
    ("flagprobe", "per-operation flag semantics"),
    ("wide", "64-bit arithmetic and shifts"),
    ("byteops", "byte swap and the direction flag"),
    ("bitops", "BT/BTS/BTR/BTC register forms"),
    ("x87", "x87 stack, flags direction, counted loops"),
    ("vecmove", "SSE register-move merge semantics"),
    ("packed", "SSE2 packed integer, register and immediate forms"),
    ("simd_convert", "packed integer-to-float conversion and MXCSR rounding modes"),
]

# 32-bit (PE32) fixtures. These exercise the independent x86 decode mode, the
# 32-bit guest context, stack handling and the Win32 stdcall ABI.
FIXTURES_PE32 = [
    ("pe32_arith", "32-bit arithmetic, flags and recursion"),
    ("pe32_abi", "32-bit calling conventions, indirect dispatch and address wrapping"),
    ("pe32_simd_convert", "32-bit packed integer-to-float conversion and MXCSR"),
    ("teb32", "32-bit TEB access through fs:"),
]

EXPECTED_OUTPUT = {
    "arith": ["arith:start", "primes<200=46", "fib(20)=6765", "gcd(1071,462)=21", "arith:done"],
    "tictactoe": ["tictactoe:start", "result=draw moves=9", "tictactoe:done"],
    "snake": ["snake:start", "snake:done"],
    "aliasing": ["aliasing:start", "zero_extend=1", "aliasing:done"],
    "eflags": ["eflags:start", "flags_checksum=", "eflags:done"],
    "calls": ["calls:start", "sum8=36", "factorial(12)=479001600", "table_dispatch=", "calls:done"],
    "memory": ["memory:start", "table_checksum=", "memory:done"],
    "flagprobe": ["add ", "imul ", "shln "],
    "wide": ["wide:start", "roll=", "wide:done"],
    # Exact values, not just markers: a wrong byte order or an ignored direction
    # flag changes the printed digits, so the fragments have to pin them.
    "byteops": ["byteops:start", "bswap32=2018915346", "bswap64=", "bswap64_hi=",
                "backward=abcdefg", "forward=abcdefg", "byteops:done"],
    # BTR's write-back is the point: anding with the mask instead of its
    # complement prints 32 instead of -33 and 32768 instead of 32767.
    "bitops": ["bitops:start", "btr=-33", "btr_cf=1", "bts=8", "bts_cf=0", "btc=0",
               "btc_cf=1", "bt_cf=1", "btr32=32767", "btr32_cf=1", "bitops:done"],
    # The merge is the point: a 16-byte register copy prints movsd_hi=22 and
    # movss_lane3=0 instead of preserving 11 and 33.
    # Exact values: a wrong element width, a missing saturation clamp or a wrong
    # shift direction all change these digits. pmuludq in particular must keep
    # the full 64-bit product.
    "packed": ["packed:start", "paddb=", "psubb=", "paddw=", "psubw=", "paddd=", "paddq=",
               "paddusb=", "paddsb=", "psubusb=", "psubsb=", "paddusw=", "psubsw=",
               "pcmpeqb=0", "pcmpeqw=0", "pcmpgtb=", "pcmpgtw=",
               "pmullw=", "pmulhw=", "pmulhuw=", "pmuludq=", "pmaddwd=", "psadbw=", "pandn=",
               "psllw3=", "pslld5=", "psllq9=", "psrlw3=", "psrld5=", "psrlq9=",
               "psraw3=", "psrad5=", "psrldq4=", "pslldq4=",
               "punpcklbw=", "punpckhbw=", "punpcklwd=", "punpckhwd=",
               "packsswb=", "packuswb=", "packssdw=",
               "pshufb=", "pshuflw=", "pshufhw=", "pmovmskb=",
               # Memory-source forms for the five helpers that once had no
               # _memory twin and so produced code that would not compile.
               "mem_paddd=", "mem_psubd=", "mem_pcmpeqd=", "mem_pmaddwd=", "mem_psadbw=",
               "mem_paddw=", "packed:done"],
    "vecmove": ["vecmove:start", "movsd_lo=7", "movsd_hi=11", "movss_lo=5",
                "movss_lane3=33", "load_lo=42", "load_hi=0", "vecmove:done"],
    "x87": ["x87:start", "add ", "fistp ", "sqrt ", "cmp_eq ", "sin ", "cw_trunc ",
            "store_trunc ", "rep_std ", "loop ", "jecxz_zero ", "jecxz_nonzero ", "x87:done"],
    "simd_convert": ["simdconvert:start", "default_mxcsr=", "mode=0", "mode=3", "boundary",
                     "extremes", "memory ", "roundtrip=", "restored=", "simdconvert:done"],
    "pe32_simd_convert": ["simdconvert:start", "default_mxcsr=", "mode=0", "mode=3", "boundary",
                          "extremes", "memory ", "roundtrip=", "restored=", "simdconvert:done"],
    # A 32-bit guest reaches its TEB through fs: with an absolute displacement.
    # Dropping the segment base turned every one of those reads into a read of
    # the low page, so these fields all came back zero.
    "teb32": ["teb32:start", "teb_readable=1", "stack_base_nonzero=1",
              "stack_limit_below_base=1", "peb_nonzero=1", "self_nonzero=1",
              "pointer_roundtrip=1", "teb32:done"],
    "pe32_arith": ["arith:start", "primes<200=46", "fib(20)=6765", "gcd(1071,462)=21", "arith:done"],
    "pe32_abi": ["pe32:start", "cdecl=", "stdcall=", "fastcall=", "thiscall=", "dispatch=",
                 "wrapped=16", "checksum=", "pe32:done"],
}


def fail(message: str) -> None:
    print("FAIL: " + message, file=sys.stderr)
    raise SystemExit(1)


def build_fixtures(destination: Path) -> None:
    if shutil.which("x86_64-w64-mingw32-gcc") is None:
        if OPTIONAL_MODE:
            print("SKIP (RECOMP_OPTIONAL=1): mingw-w64 x86_64 compiler not available")
            raise SystemExit(0)
        fail("mingw-w64 x86_64 compiler is required; install it or set RECOMP_OPTIONAL=1")
    subprocess.run(["sh", str(APPS_DIRECTORY / "build.sh"), str(destination)], check=True,
                   stdout=subprocess.DEVNULL)


def run_cli(arguments) -> subprocess.CompletedProcess:
    return subprocess.run([CLI, *arguments], text=True, capture_output=True)


def verify_fixture(name: str, executable: Path, project: Path) -> str:
    translated = run_cli(["translate", str(executable), "--target", "macos-arm64",
                          "--output", str(project), "--json"])
    if translated.returncode != 0:
        fail(f"{name}: translate failed: {translated.stderr.strip()}")
    if json.loads(translated.stdout).get("status") != "ok":
        fail(f"{name}: translate did not report ok: {translated.stdout}")

    built = run_cli(["build", str(project), "--json"])
    if built.returncode != 0:
        fail(f"{name}: build failed: {built.stderr.strip()}")

    guest = project / "recomp-guest"
    if not guest.exists():
        fail(f"{name}: generated executable is missing")

    if platform.machine().lower() in ("arm64", "aarch64"):
        description = subprocess.run(["file", str(guest)], text=True, capture_output=True, check=True)
        if "arm64" not in description.stdout.lower():
            fail(f"{name}: generated executable is not arm64: {description.stdout.strip()}")

    execution = run_cli(["run", str(project)])
    if execution.returncode != 0:
        fail(f"{name}: the translated binary failed to run: {execution.stderr.strip()}")
    if not execution.stdout.strip():
        fail(f"{name}: the translated binary produced no output")
    for fragment in EXPECTED_OUTPUT[name]:
        if fragment not in execution.stdout:
            fail(f"{name}: expected output fragment {fragment!r} was not produced")

    verification = run_cli(["verify", str(project), "--json"])
    if verification.returncode != 0:
        detail = verification.stdout.strip() or verification.stderr.strip()
        if "not built" in detail:
            fail(f"{name}: verification backend is unavailable; verification is mandatory ({detail})")
        fail(f"{name}: verification failed: {detail}")

    report = json.loads(verification.stdout)
    if report.get("status") != "pass":
        fail(f"{name}: verification status is {report.get('status')!r}, not 'pass'")
    if not report.get("reference_completed"):
        fail(f"{name}: the reference execution did not complete")
    if not report.get("candidate_completed"):
        fail(f"{name}: the candidate execution did not complete")
    if not report.get("outputs_match"):
        fail(f"{name}: candidate output differs from the reference")
    if report.get("unsupported_mnemonics"):
        fail(f"{name}: translation reported unsupported mnemonics: {report['unsupported_mnemonics']}")
    if report.get("executed_instructions", 0) <= 0:
        fail(f"{name}: the reference executed no instructions")

    return f"{name}: {len(execution.stdout)} bytes, {report['executed_instructions']} reference instructions, VERIFIED"


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixture_binaries = root / "bin"
        build_fixtures(fixture_binaries)

        required = FIXTURES + FIXTURES_PE32
        for name, description in required:
            executable = fixture_binaries / f"{name}.exe"
            if not executable.exists():
                if name.startswith("pe32_") and OPTIONAL_MODE:
                    print(f"SKIP (RECOMP_OPTIONAL=1): {name} needs the i686 toolchain")
                    continue
                fail(f"{name}: fixture was not built ({description})")
            print("PASS " + verify_fixture(name, executable, root / f"project-{name}"))

        executed = sum(1 for name, _ in required if (fixture_binaries / f"{name}.exe").exists())
        print(f"PASS: {executed} fixtures recompiled, executed and verified "
              f"({len(FIXTURES)} PE32+, {len(FIXTURES_PE32)} PE32)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
