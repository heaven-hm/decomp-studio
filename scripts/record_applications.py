#!/usr/bin/env python3
"""Record the applications this studio has actually ported, in APPLICATIONS.md.

A row is written only for an application that got all the way through: translated,
built, ran, and passed differential verification. Anything short of that is not a port
and does not belong in the table -- the point of the file is to be a list of things that
work, and a list that includes things that nearly work is not worth reading.

Each row carries the evidence: the source architecture and operating system read from
the binary itself, the target host, and a screenshot of what the ported program
printed. For a console application the screenshot IS the output rendered as an image,
which is what a reader would otherwise have to run the program to see.

Usage:
    record_applications.py <cli> <output-dir> <executable> [<executable> ...]

Writes <output-dir>/APPLICATIONS.md and <output-dir>/screenshots/<name>.png.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

# The bundled runtime has Pillow; the system python3 may not.
PILLOW_PYTHON = "/Users/haseeb-mir/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/bin/python3"

RUN_TIMEOUT_SECONDS = 120


def host_description(cli: str) -> str:
    """The host the studio is running on, as the studio itself reports it."""
    doctor = subprocess.run([cli, "doctor"], text=True, capture_output=True)
    host = target = "unknown"
    for line in doctor.stdout.splitlines():
        if line.startswith("host:"):
            host = line.split(":", 1)[1].strip()
        elif line.startswith("target:"):
            target = line.split(":", 1)[1].strip().split()[0]
    return f"{host} ({target})"


def describe(cli: str, executable: pathlib.Path):
    """Source architecture and OS, taken from the binary rather than assumed."""
    report = subprocess.run([cli, "inspect", str(executable), "--json"],
                            text=True, capture_output=True)
    if report.returncode != 0:
        return None
    try:
        payload = json.loads(report.stdout)
    except json.JSONDecodeError:
        return None
    architecture = payload.get("architecture", "?")
    fmt = payload.get("format", "")
    # A PE is a Windows executable by construction; say so from the format rather than
    # from a guess about the filename.
    operating_system = "windows" if "PE" in fmt else "?"
    return architecture, operating_system


def port(cli: str, executable: pathlib.Path, workspace: pathlib.Path):
    """Translate, build, run and verify. Returns (ok, output, detail)."""
    project = workspace / "project"
    translated = subprocess.run(
        [cli, "translate", str(executable), "--target", "macos-arm64", "--output", str(project)],
        text=True, capture_output=True)
    if translated.returncode != 0:
        return False, "", (translated.stderr or translated.stdout).strip().splitlines()[0][:120]

    built = subprocess.run([cli, "build", str(project), "--json"], text=True, capture_output=True)
    if built.returncode != 0:
        return False, "", "build failed"

    try:
        ran = subprocess.run([str(project / "recomp-guest")], text=True, capture_output=True,
                             timeout=RUN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return False, "", f"did not finish within {RUN_TIMEOUT_SECONDS}s"
    if ran.returncode != 0:
        return False, ran.stdout, f"exited with code {ran.returncode}"

    verified = subprocess.run([cli, "verify", str(project), "--json"],
                              text=True, capture_output=True)
    try:
        verdict = json.loads(verified.stdout)
    except json.JSONDecodeError:
        return False, ran.stdout, "verification produced no verdict"
    if verdict.get("status") != "pass":
        return False, ran.stdout, "did not verify"
    return True, ran.stdout, "verified"


def render(output: str, name: str, destination: pathlib.Path) -> bool:
    """Render the program's output as an image, which is the screenshot for a console app."""
    script = r'''
import sys
from PIL import Image, ImageDraw, ImageFont
text, path, title = sys.argv[1], sys.argv[2], sys.argv[3]
lines = text.splitlines() or ["(the program printed nothing)"]
font = None
for candidate in ("/System/Library/Fonts/Menlo.ttc",
                  "/System/Library/Fonts/SFNSMono.ttf",
                  "/System/Library/Fonts/Monaco.ttf"):
    try:
        font = ImageFont.truetype(candidate, 14)
        break
    except Exception:
        continue
if font is None:
    font = ImageFont.load_default()
line_height = 20
padding = 16
header = 34
width = 900
height = header + padding * 2 + line_height * max(len(lines), 1)
image = Image.new("RGB", (width, height), (24, 24, 28))
draw = ImageDraw.Draw(image)
draw.rectangle([0, 0, width, header], fill=(44, 44, 52))
draw.text((padding, 9), title, font=font, fill=(230, 230, 235))
for index, line in enumerate(lines):
    draw.text((padding, header + padding + index * line_height), line[:110], font=font,
              fill=(200, 220, 200))
image.save(path)
'''
    try:
        result = subprocess.run([PILLOW_PYTHON, "-c", script, output, str(destination), name],
                                text=True, capture_output=True, timeout=60)
        return result.returncode == 0
    except Exception:
        return False


def main() -> int:
    cli, output_directory = sys.argv[1], pathlib.Path(sys.argv[2])
    executables = [pathlib.Path(argument) for argument in sys.argv[3:]]
    output_directory.mkdir(parents=True, exist_ok=True)
    screenshots = output_directory / "screenshots"
    screenshots.mkdir(exist_ok=True)
    host = host_description(cli)

    ported, rejected = [], []
    for executable in executables:
        described = describe(cli, executable)
        if described is None:
            rejected.append((executable.name, "not a readable PE image"))
            continue
        architecture, operating_system = described
        with tempfile.TemporaryDirectory() as workspace:
            ok, output, detail = port(cli, executable, pathlib.Path(workspace))
        if not ok:
            rejected.append((executable.name, detail))
            continue
        screenshot = screenshots / (executable.stem + ".png")
        rendered = render(output, executable.name, screenshot)
        ported.append({
            "application": executable.name,
            "source_arch": architecture,
            "source_os": operating_system,
            "target_host": host,
            "output_bytes": len(output),
            "screenshot": screenshot.name if rendered else "",
        })
        print(f"PORTED   {executable.name} ({architecture}, {operating_system})")
    for name, why in rejected:
        print(f"refused  {name}: {why}")

    lines = [
        "# Applications",
        "",
        "Applications this studio has actually ported: translated from a Windows PE",
        "binary, built as a native host executable, run, and **differentially verified**",
        "against a Unicorn reference executing the original instructions.",
        "",
        "A row appears here only when all of that happened. An application that",
        "translates but does not run, or runs but does not verify, is not a port and is",
        "not listed -- see the refused list at the end of this file for those, with the",
        "reason each one gave.",
        "",
        "The screenshot is the ported program's own output, rendered as an image. For a",
        "console application that is the whole observable result, so the image is the",
        "evidence rather than a decoration.",
        "",
        f"Host: `{host}`",
        "",
    ]
    if ported:
        lines += [
            "| application | source arch | source OS | target host | output | screenshot |",
            "|---|---|---|---|---|---|",
        ]
        for row in ported:
            shot = (f"[view](screenshots/{row['screenshot']})" if row["screenshot"] else "not captured")
            lines.append(f"| `{row['application']}` | {row['source_arch']} | {row['source_os']} | "
                         f"{row['target_host']} | {row['output_bytes']} bytes | {shot} |")
    else:
        lines.append("No application has been ported end to end yet.")
    lines += [
        "",
        "## Refused, with the reason each one gave",
        "",
        "Recorded so the list above cannot be mistaken for the whole story. Every entry",
        "here is an application that did **not** reach a verified native port.",
        "",
    ]
    if rejected:
        lines += ["| application | reason |", "|---|---|"]
        for name, why in rejected:
            lines.append(f"| `{name}` | {why.replace('|', '/')} |")
    else:
        lines.append("None.")
    lines.append("")
    (output_directory / "APPLICATIONS.md").write_text("\n".join(lines))

    print(f"\n{len(ported)} ported, {len(rejected)} refused -> {output_directory / 'APPLICATIONS.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
