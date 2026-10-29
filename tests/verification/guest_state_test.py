#!/usr/bin/env python3
"""Guest-state checkpoints must be compared, and must be able to fail.

Comparing program output alone cannot see a wrong register, a wrong flag or a wrong
store that never reaches the output. This test pins the stronger claim:

  1. checkpoints ARE compared (a non-zero count, so the gate is not vacuous);
  2. a run whose state agrees verifies;
  3. a run whose state disagrees does NOT verify, even when its output matches.

The third check is the one that matters. It is established by mutating the
reported checkpoint state -- not the program's execution -- so the program's output
is provably unchanged and only the state differs. If verification still passed, the
state comparison would be decoration.
"""

import json
import pathlib
import re
import signal
import subprocess
import sys
import tempfile

CLI = sys.argv[1]
FIXTURES = pathlib.Path(sys.argv[2])
# tests/fixtures/apps -> tests/fixtures -> tests -> the repository root.
ROOT = FIXTURES.resolve().parent.parent.parent
RUNTIME = ROOT / "runtime" / "recomp_runtime.cpp"

PASSES = []
FAILURES = []


def check(name, condition, detail=""):
    if condition:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: {detail}")


def run_cli(arguments):
    return subprocess.run([CLI, *arguments], text=True, capture_output=True)


def verify_json(project):
    result = run_cli(["verify", str(project), "--json"])
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def main():
    fixture = FIXTURES / "bin" / "arith.exe"
    if not fixture.exists():
        print(f"FAIL: {fixture} is missing; build the fixtures first", file=sys.stderr)
        return 1

    # This test mutates a tracked source file, because the mutation has to be
    # compiled into the candidate and the only way to do that is through the
    # runtime the translator copies. That makes it dangerous if it is interrupted:
    # a killed run would leave the runtime mutated. So the original is restored
    # from a signal handler as well as from the finally block, and the test refuses
    # to start if a previous run left the file dirty.
    original = RUNTIME.read_text()
    mutation_marker = "// test mutation"
    if mutation_marker in original:
        print("FAIL: runtime/recomp_runtime.cpp is already mutated; a previous run was "
              "interrupted. Restore it with `git checkout -- runtime/recomp_runtime.cpp`.",
              file=sys.stderr)
        return 1

    def restore_and_exit(signum, _frame):
        RUNTIME.write_text(original)
        print(f"restored runtime/recomp_runtime.cpp after signal {signum}", file=sys.stderr)
        sys.exit(1)

    for handled in (signal.SIGINT, signal.SIGTERM):
        signal.signal(handled, restore_and_exit)

    try:
        with tempfile.TemporaryDirectory() as workspace:
            workspace = pathlib.Path(workspace)
            project = workspace / "project"
            if run_cli(["translate", str(fixture), "--target", "macos-arm64",
                        "--output", str(project)]).returncode != 0:
                print("FAIL: translate failed", file=sys.stderr)
                return 1
            if run_cli(["build", str(project)]).returncode != 0:
                print("FAIL: build failed", file=sys.stderr)
                return 1

            clean = verify_json(project)
            check("verify/json", clean is not None, "verify --json did not return JSON")
            if clean is None:
                return 1

            # 1. The gate must not be vacuous.
            check("state/checkpoints-compared", clean["checkpoints_compared"] > 0,
                  "no guest-state checkpoints were compared, so the state gate cannot fail")
            check("state/checkpoints-match-percent", clean["checkpoint_match_percent"] == 100,
                  f"a correct build matched only {clean['checkpoint_match_percent']}% of checkpoints")
            check("state/matches-when-correct", clean["state_match"] is True,
                  f"state disagreed on a correct build: {clean['state_diagnosis']}")
            check("state/verifies", clean["status"] == "pass", clean["state_diagnosis"])

            # 3. Mutate only what the checkpoint reports. Execution is untouched, so
            #    the output cannot change; the state comparison is the only thing
            #    that can notice.
            marker = "checkpoint.flags = eflags_value(context);"
            if marker not in original:
                check("state/mutation-point-exists", False,
                      f"cannot find {marker!r} in runtime/recomp_runtime.cpp")
                return 1
            # The mutation goes into the GENERATED PROJECT's copy, never the source
            # tree. Writing to runtime/recomp_runtime.cpp -- which this used to do --
            # makes `ctest -j` unsafe: a dozen other tests copy that exact file at
            # translate time, so they would pick up the mutation and fail for a reason
            # that is not theirs, and a SIGKILL inside the window leaves the tree
            # poisoned for every later run. A test may not edit tracked source to prove
            # something, and the restore below is kept only so the file's contents are
            # unchanged if anything ever writes to it again.
            mutated_project = workspace / "mutated"
            if run_cli(["translate", str(fixture), "--target", "macos-arm64",
                        "--output", str(mutated_project)]).returncode != 0:
                print("FAIL: translate failed", file=sys.stderr)
                return 1
            project_runtime = mutated_project / "recomp_runtime.cpp"
            project_source = project_runtime.read_text()
            if marker not in project_source:
                check("state/mutation-point-exists", False,
                      f"cannot find {marker!r} in the generated project's runtime copy")
                return 1
            project_runtime.write_text(project_source.replace(
                marker, "checkpoint.flags = eflags_value(context) ^ 0x1u;  // test mutation"))
            # The mutation above edits a generated source, so the manifest check would refuse the
            # rebuild. Saying so explicitly is the point of the flag: the weakening is visible
            # in the command rather than hidden in a bypass.
            if run_cli(["build", str(mutated_project), "--allow-modified-sources"]).returncode != 0:
                print("FAIL: build failed after the mutation", file=sys.stderr)
                return 1

            mutated = verify_json(mutated_project)
            check("state/mutation-json", mutated is not None, "verify --json did not return JSON")
            if mutated is not None:
                check("state/mutation-leaves-output-identical", mutated["outputs_match"] is True,
                      "the mutation changed the program's output, so it does not isolate the state gate")
                check("state/mutation-detected", mutated["state_match"] is False,
                      "a changed register/flag value was not detected")
                check("state/mutation-lowers-match-percent", mutated["checkpoint_match_percent"] < 100,
                      "a changed checkpoint still reports a 100% match")
                check("state/mutation-fails-verification", mutated["status"] == "fail",
                      "verification passed while the guest state disagreed")
                check("state/mutation-names-the-place",
                      bool(re.search(r"checkpoint \d+", mutated["state_diagnosis"])),
                      f"the diagnosis does not locate the divergence: {mutated['state_diagnosis']!r}")
    finally:
        RUNTIME.write_text(original)

    for line in PASSES:
        print("PASS " + line)
    for line in FAILURES:
        print("FAIL " + line, file=sys.stderr)
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
