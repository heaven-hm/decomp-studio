#!/usr/bin/env python3
"""Compile a PE32 fixture, lift it with PCRecomp, and run its generated C."""

import pathlib
import shlex
import subprocess
import sys
import tempfile


def run(args, *, cwd=None, binary=False):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=not binary, timeout=90)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result


def main():
    upstream, fixture, mingw, cc, pkg_config, *sdk = sys.argv[1:]
    reference_cli = None
    if "--reference-cli" in sdk:
        position = sdk.index("--reference-cli")
        reference_cli = sdk[position + 1]
        del sdk[position:position + 2]
    upstream = pathlib.Path(upstream).resolve()
    fixture = pathlib.Path(fixture).resolve()
    hle = upstream / "runtime/win32hle"
    recomp = upstream / "runtime/recomp32"
    with tempfile.TemporaryDirectory(prefix="pcrecomp-pe32-") as temp:
        root = pathlib.Path(temp)
        image = root / "arith.exe"
        generated = root / "generated"
        run([mingw, "-O2", "-nostdlib", "-ffreestanding", "-fno-asynchronous-unwind-tables",
             "-fno-stack-protector", "-fno-tree-vectorize", "-fno-tree-slp-vectorize",
             "-Wl,--no-insert-timestamp", "-Wl,-e,recomp_entry", "-Wl,--subsystem,console",
             "-o", str(image), str(fixture), "-lkernel32", "-lgcc"])
        run([sys.executable, "-m", "tools", str(image), "--all", "--split", "3",
             "--output", str(generated)], cwd=upstream)
        sources = sorted(generated.glob("recomp_*.c"))
        failure_markers = ("RECOMP_TODO", "/* ERROR lifting ", "/* FAILED */")
        if not sources or any(marker in source.read_text() for source in sources for marker in failure_markers):
            raise RuntimeError("PCRecomp did not produce complete fixture source")
        driver = root / "main.c"
        driver.write_text('#include "host.h"\nint main(int argc, char **argv) { return recomp_host_main(argc, argv); }\n')
        core = sorted(str(path) for path in hle.glob("*.c") if not path.name.endswith("_selftest.c"))
        flags = shlex.split(run([pkg_config, "--cflags", "--libs", "sdl2", "SDL2_ttf"]).stdout)
        executable = root / "arith-native"
        sysroot = ["-isysroot", sdk[0]] if sdk else []
        run([cc, *sysroot, "-O1", f"-I{hle}", f"-I{recomp}", f"-I{generated}",
             "-include", str(generated / "recomp_funcs.h"), *core,
             str(driver), *(str(path) for path in sources), *flags, "-lpthread", "-lm", "-o", str(executable)])
        output = run([str(executable), str(image)], binary=True).stdout
        expected = ("arith:start\nprimes<200=46\nfib(20)=6765\ngcd(1071,462)=21\n"
                    "popcount(0xF0F0F0F0)=16\nrotl(0x12345678,8)=878082066\n"
                    "poly=12512\nmul=-8369910\ndiv=-18\nmod=-141\narith:done\n")
        if output != expected.replace("\n", "\r\n").encode("ascii"):
            raise AssertionError(f"fixture output differs:\n{output}")
        if reference_cli:
            reference_project = root / "reference"
            run([reference_cli, "autorecomp", str(image), "--output", str(reference_project),
                 "--buildrun", "--timeout", "10"])
            reference = (reference_project / "reports/reference.txt").read_bytes()
            if output != reference:
                raise AssertionError("PCRecomp output differs from Unicorn's original-PE execution")
    print("PCRecomp PE32 fixture compiled and ran with expected output")


if __name__ == "__main__":
    main()
