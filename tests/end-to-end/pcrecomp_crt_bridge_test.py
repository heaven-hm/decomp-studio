"""Run an actual PE32 CRT import through PCRecomp and the experimental bridge."""
import pathlib
import shlex
import subprocess
import sys
import tempfile


def run(args, *, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr.decode(errors='replace')}")
    return result.stdout


upstream, source, mingw, cc, cxx, pkg, provider, cli, *sdk = sys.argv[1:]
upstream, source = pathlib.Path(upstream).resolve(), pathlib.Path(source).resolve()
with tempfile.TemporaryDirectory(prefix="pcrecomp-crt-") as tmp:
    root = pathlib.Path(tmp)
    image, generated = root / "fixture.exe", root / "generated"
    run([mingw, "-O2", "-nostdlib", "-ffreestanding", "-fno-asynchronous-unwind-tables",
         "-fno-stack-protector", "-Wl,--no-insert-timestamp", "-Wl,-e,recomp_entry",
         "-Wl,--subsystem,console", "-o", str(image), str(source), "-lkernel32", "-lmsvcrt", "-lgcc"])
    run([sys.executable, "-m", "tools", str(image), "--all", "--split", "3", "--output", str(generated)], cwd=upstream)
    sources = sorted(generated.glob("recomp_*.c"))
    markers = ("RECOMP_TODO", "/* ERROR lifting ", "/* FAILED */")
    if not sources or any(marker in src.read_text() for src in sources for marker in markers):
        raise RuntimeError("incomplete PCRecomp output")
    driver = root / "main.c"
    driver.write_text('#include "host.h"\nvoid recomp_register_pcrecomp_stateless_crt(void);\n'
                      'int main(int n,char **v){if(n<2)return 64;recomp_host_init();'
                      'recomp_register_pcrecomp_stateless_crt();if(recomp_host_boot(v[1]))return 2;'
                      'return (int)recomp_host_run();}\n')
    sysroot = ["-isysroot", sdk[0]] if sdk else []
    includes = [f"-I{upstream / 'runtime/recomp32'}", f"-I{upstream / 'runtime/win32hle'}", f"-I{generated}"]
    run([cc, *sysroot, "-O0", *includes, "-include", str(generated / "recomp_funcs.h"),
         "-c", str(driver), *(str(src) for src in sources)], cwd=root)
    flags = shlex.split(run([pkg, "--libs", "sdl2", "SDL2_ttf"]).decode())
    native = root / "native"
    run([cxx, *sysroot, "-o", str(native), *(str(obj) for obj in root.glob("*.o")), provider,
         *flags, "-lpthread", "-lm"])
    candidate = run([str(native), str(image)])
    if candidate != b"character imports passed\r\n":
        raise AssertionError(f"unexpected candidate output: {candidate!r}")
    project = root / "reference"
    run([cli, "autorecomp", str(image), "--output", str(project), "--buildrun", "--timeout", "10"])
    if candidate != (project / "reports/reference.txt").read_bytes():
        raise AssertionError("output differs from original PE under Unicorn")
