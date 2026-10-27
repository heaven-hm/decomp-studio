#!/usr/bin/env python3
"""Render real recomp-studio terminal sessions into PNG screenshots for the README."""

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "build" / "recomp-studio"
OUTPUT_DIRECTORY = ROOT / "assets" / "screenshots"

BACKGROUND = (13, 17, 23)
TITLEBAR = (22, 27, 34)
BORDER = (48, 54, 61)
PROMPT = (88, 166, 255)
OUTPUT = (201, 209, 217)
SUCCESS = (63, 185, 80)
MUTED = (139, 148, 158)

FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
FONT_SIZE = 15
LINE_HEIGHT = 21
PADDING = 18
TITLEBAR_HEIGHT = 30
WIDTH_CHARS = 104


def load_font(size=FONT_SIZE):
    return ImageFont.truetype(FONT_PATH, size)


def run(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True)
    return (result.stdout + result.stderr).rstrip("\n")


def wrap(text, width):
    lines = []
    for line in text.split("\n"):
        while len(line) > width:
            lines.append(line[:width])
            line = line[width:]
        lines.append(line)
    return lines


def render(title, transcript, destination):
    font = load_font()
    character_width = font.getbbox("M")[2]
    width = PADDING * 2 + character_width * WIDTH_CHARS
    lines = wrap(transcript, WIDTH_CHARS)
    height = TITLEBAR_HEIGHT + PADDING * 2 + LINE_HEIGHT * len(lines)

    image = Image.new("RGB", (width, height), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, width, TITLEBAR_HEIGHT], fill=TITLEBAR)
    draw.line([0, TITLEBAR_HEIGHT, width, TITLEBAR_HEIGHT], fill=BORDER)
    for index, colour in enumerate([(237, 106, 94), (245, 191, 79), (98, 197, 84)]):
        draw.ellipse([PADDING + index * 18, 10, PADDING + 11 + index * 18, 21], fill=colour)
    title_font = load_font(12)
    draw.text((width // 2 - len(title) * 3, 9), title, font=title_font, fill=MUTED)

    y = TITLEBAR_HEIGHT + PADDING
    for line in lines:
        if line.startswith("$ "):
            draw.text((PADDING, y), "$", font=font, fill=PROMPT)
            draw.text((PADDING + character_width * 2, y), line[2:], font=font, fill=OUTPUT)
        elif line.startswith("[ok]") or "VERIFIED" in line or "PASS" in line or "built " in line:
            draw.text((PADDING, y), line, font=font, fill=SUCCESS)
        elif line.startswith("#"):
            draw.text((PADDING, y), line, font=font, fill=MUTED)
        else:
            draw.text((PADDING, y), line, font=font, fill=OUTPUT)
        y += LINE_HEIGHT

    image.save(destination)
    print(f"wrote {destination}")


def main():
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    applications = {
        "arith": ["arith:start", "primes<200=46", "fib(20)=6765"],
        "tictactoe": ["tictactoe:start", "result=draw"],
        "snake": ["snake:start", "snake:done"],
    }
    for name in applications:
        project = ROOT / "build" / "screenshots-projects" / name
        transcript = []
        transcript.append(f"$ recomp-studio translate tests/fixtures/apps/bin/{name}.exe \\")
        transcript.append(f"      --target macos-arm64 --output {project.relative_to(ROOT)}")
        transcript.append(run([str(CLI), "translate", str(ROOT / "tests" / "fixtures" / "apps" / "bin" / f"{name}.exe"),
                               "--target", "macos-arm64", "--output", str(project)]))
        transcript.append(f"$ recomp-studio build {project.relative_to(ROOT)}")
        transcript.append(run([str(CLI), "build", str(project)]))
        transcript.append("$ file " + str((project / "recomp-guest").relative_to(ROOT)))
        transcript.append(run(["file", str(project / "recomp-guest")]))
        transcript.append(f"$ {project.relative_to(ROOT)}/recomp-guest")
        transcript.append(run([str(project / "recomp-guest")]))
        transcript.append(f"$ recomp-studio verify {project.relative_to(ROOT)}")
        transcript.append(run([str(CLI), "verify", str(project)]))
        render(f"recomp-studio - {name} (x86-64 PE32+ -> native arm64)", "\n".join(transcript),
               OUTPUT_DIRECTORY / f"{name}.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
