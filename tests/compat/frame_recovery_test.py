#!/usr/bin/env python3
"""Frame recovery must find the size the PROLOGUE states, and must not invent one.

The check is against a fixture whose frame is a known constant, so the expected value comes
from the source rather than from the tool's own output. A test that asserts "the tool agrees
with itself" proves nothing.
"""
import json
import subprocess
import sys

CLI, FIXTURE, EXPECTED_FUNCTIONS = sys.argv[1], sys.argv[2], int(sys.argv[3])
PASSES, FAILURES = [], []


def check(name, ok, detail=""):
    (PASSES if ok else FAILURES).append(name if ok else f"{name}: {detail}")


result = subprocess.run([CLI, "coverage", FIXTURE, "--json"], capture_output=True, text=True)
report = json.loads(result.stdout)
count = report["function_count"]
recovered = report["functions_with_recovered_frame"]

check("frame/report-has-field", "functions_with_recovered_frame" in report,
      "the report does not carry the count at all")
check("frame/functions-recovered", count == EXPECTED_FUNCTIONS,
      f"{count} functions recovered, expected {EXPECTED_FUNCTIONS}")
# A frame is a LOWER BOUND and a leaf function reserves none, so the count is a fraction --
# but it must be a fraction OF SOMETHING. Zero would mean the scan reads nothing, and a count
# equal to every function would mean it is not reading the prologue either.
check("frame/some-frames-recovered", recovered > 0,
      "no function reported a frame, so the prologue scan is not reading anything")
check("frame/not-every-function-has-a-frame", recovered < count,
      "every function reported a frame, which a leaf function cannot have")
check("frame/count-is-a-subset", recovered <= count, f"{recovered} > {count}")

for line in PASSES:
    print("PASS " + line)
for line in FAILURES:
    print("FAIL " + line, file=sys.stderr)
print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
sys.exit(1 if FAILURES else 0)
