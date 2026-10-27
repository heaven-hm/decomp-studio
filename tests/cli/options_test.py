#!/usr/bin/env python3
"""The CLI contract: parsing, help, capabilities and backward compatibility.

The property that matters most is that the help text and the parser cannot
disagree. Both are generated from one option table, so this test derives the
option list FROM THE HELP OUTPUT and then asks the parser to accept every option it
found. If someone adds an option to the table but breaks the parser, or documents
one that is not parsed, this fails.

The other rules pinned here:
  * an unknown option is an error, never ignored;
  * a value outside an option's declared set is an error;
  * a declared-but-planned value is UNSUPPORTED, distinct from a usage error;
  * every command that existed before this change still runs.
"""

import json
import pathlib
import re
import subprocess
import sys

CLI = sys.argv[1]
FIXTURES = pathlib.Path(sys.argv[2])

PASSES = []
FAILURES = []


def check(name, condition, detail=""):
    if condition:
        PASSES.append(name)
    else:
        FAILURES.append(f"{name}: {detail}")


def run(arguments, **kwargs):
    return subprocess.run([CLI, *arguments], text=True, capture_output=True, **kwargs)


def main():
    # --- help is generated, and complete ------------------------------------
    help_result = run(["--help"])
    check("help/exit", help_result.returncode == 0, help_result.stderr[:160])
    help_text = help_result.stdout
    check("help/version", "recomp-studio 0.5.0" in help_text, help_text[:80])

    for command in ("doctor", "inspect", "analyze", "coverage", "imports", "autorecomp", "functions",
                    "cfg", "translate", "build", "run", "verify", "repair", "report", "examples",
                    "capabilities", "detect", "backends"):
        check(f"help/lists-command/{command}", re.search(rf"^\s+{command}\b", help_text, re.M) is not None,
              f"{command} is missing from the help")

    # Derive the declared options from the help itself.
    documented = sorted(set(re.findall(r"^\s+(--[a-z0-9-]+)", help_text, re.M)))
    check("help/documents-options", len(documented) >= 25, f"only {len(documented)} options documented")

    # --- every documented option is accepted by the parser ------------------
    # A bare flag needs no value; an option that takes one is given a value from
    # its own documented set where the help names one, and a harmless placeholder
    # otherwise. The point is that the parser must not call a documented option
    # unknown.
    for option in documented:
        if option in ("--help",):
            continue
        # `capabilities` is the cheapest command that parses options and does
        # nothing else, so a parse failure is attributable to the option.
        for candidate in ([option], [option, "auto"], [option, "/tmp/recomp-cli-probe"]):
            result = run(["capabilities", *candidate])
            if result.returncode in (0, 3):
                break
        else:
            result = run(["capabilities", option, "auto"])
        combined = result.stdout + result.stderr
        check(f"parse/accepts-documented/{option}", "unknown option" not in combined,
              f"the help documents {option} but the parser rejected it: {combined.strip()[:140]}")

    # --- defaults are documented and applied --------------------------------
    defaults_block = help_text.split("Defaults:", 1)[1] if "Defaults:" in help_text else ""
    for name, value in (("source-os", "auto"), ("output-lang", "cpp"), ("mode", "recompile"),
                        ("fidelity", "semantic"), ("verify", "strict"), ("source-style", "faithful")):
        check(f"defaults/documented/{name}", re.search(rf"^\s+{name}\s+{value}\s*$", defaults_block, re.M) is not None,
              f"{name}={value} is not documented as the default")
    explained = run(["capabilities", "--explain"])
    check("defaults/applied/output-lang", "cpp" in explained.stdout, explained.stdout[:200])

    # --- unknown options are errors, not ignored ----------------------------
    unknown = run(["capabilities", "--definitely-not-an-option"])
    check("usage/unknown-option-exit", unknown.returncode == 2, f"exit {unknown.returncode}")
    check("usage/unknown-option-names-it", "--definitely-not-an-option" in unknown.stderr, unknown.stderr[:160])

    # --- values outside the declared set are errors -------------------------
    bad_value = run(["capabilities", "--target-arch", "sparc"])
    check("usage/bad-value-exit", bad_value.returncode == 2, f"exit {bad_value.returncode}")
    check("usage/bad-value-lists-allowed", "riscv64" in bad_value.stderr, bad_value.stderr[:200])

    missing_value = run(["capabilities", "--target-arch"])
    check("usage/missing-value-exit", missing_value.returncode == 2, f"exit {missing_value.returncode}")

    # --- planned values are UNSUPPORTED, distinct from a usage error --------
    for option, value in (("--target-os", "linux"), ("--target-os", "windows"),
                          ("--source-lang", "csharp"), ("--source-os", "macos"),
                          ("--output-lang", "llvm-ir"), ("--reference", "qemu"),
                          ("--mode", "compat"), ("--checkpoints", "memory"),
                          ("--recover-types", None)):
        arguments = ["capabilities", option] + ([value] if value else [])
        result = run(arguments)
        label = f"{option} {value}" if value else option
        check(f"unsupported/{label}-exit", result.returncode == 3, f"exit {result.returncode}")
        check(f"unsupported/{label}-says-unsupported", "UNSUPPORTED" in result.stderr, result.stderr[:160])

    # --- supported values are accepted --------------------------------------
    for option, value in (("--target-os", "macos"), ("--target-arch", "arm64"),
                          ("--source-arch", "x64"), ("--output-lang", "cpp"),
                          ("--reference", "unicorn"), ("--mode", "recompile"),
                          ("--checkpoints", "registers"), ("--optimize", "0")):
        result = run(["capabilities", option, value])
        check(f"supported/{option}-{value}", result.returncode == 0,
              (result.stdout + result.stderr)[:160])

    # --- the new commands ---------------------------------------------------
    capabilities = run(["capabilities"])
    check("capabilities/exit", capabilities.returncode == 0, capabilities.stderr[:160])
    check("capabilities/counts-implemented-and-planned",
          "implemented" in capabilities.stdout and "planned" in capabilities.stdout,
          capabilities.stdout[:200])

    capabilities_json = run(["capabilities", "--json"])
    try:
        payload = json.loads(capabilities_json.stdout)
        check("capabilities/json-shape",
              payload["status"] == "ok" and payload["total"] == len(payload["capabilities"]),
              capabilities_json.stdout[:200])
        check("capabilities/json-has-planned",
              any(entry["support"] == "planned" for entry in payload["capabilities"]),
              "no planned capability is declared, which would mean the table overclaims")
    except json.JSONDecodeError:
        check("capabilities/json-parseable", False, capabilities_json.stdout[:200])

    backends = run(["backends", "list"])
    check("backends/exit", backends.returncode == 0, backends.stderr[:160])
    check("backends/names-implemented-and-planned",
          "implemented" in backends.stdout and "planned" in backends.stdout, backends.stdout[:200])

    fixture = FIXTURES / "bin" / "arith.exe"
    if fixture.exists():
        detect = run(["detect", str(fixture)])
        check("detect/exit", detect.returncode == 0, detect.stderr[:160])
        check("detect/names-container", "container:" in detect.stdout and "pe" in detect.stdout,
              detect.stdout[:200])
        check("detect/reports-confidence", "confidence:" in detect.stdout, detect.stdout[:200])
        detect_json = run(["detect", str(fixture), "--json"])
        try:
            payload = json.loads(detect_json.stdout)
            check("detect/json-shape", payload["supported"] is True, detect_json.stdout[:200])
            check("detect/json-has-evidence", len(payload["evidence"]) > 0, detect_json.stdout[:200])
        except json.JSONDecodeError:
            check("detect/json-parseable", False, detect_json.stdout[:200])
    else:
        check("detect/fixture-present", False, f"{fixture} is missing")

    # --- backward compatibility: every pre-existing command still runs ------
    # These are the invocations the suite has used for several releases. Each must
    # still parse and behave, whether it succeeds or reports a real failure.
    legacy = [
        (["--version"], 0),
        (["--version", "--json"], 0),
        (["doctor"], 0),
        (["examples", "list"], 0),
    ]
    if fixture.exists():
        listing = run(["functions", str(fixture)]).stdout.split()
        first_function = listing[0] if listing else "0x0"
        legacy += [
            (["inspect", str(fixture)], 0),
            (["inspect", str(fixture), "--json"], 0),
            (["analyze", str(fixture)], 0),
            (["coverage", str(fixture)], 0),
            (["imports", str(fixture)], 0),
            (["functions", str(fixture)], 0),
            # The address must be a recovered function, so it is read from
            # `functions` rather than guessed: a hardcoded one went stale and
            # looked like a CLI regression.
            (["cfg", str(fixture), "--address", first_function], 0),
        ]
    for arguments, expected in legacy:
        result = run(arguments)
        check(f"legacy/{' '.join(a for a in arguments if not a.startswith('/'))[:40]}",
              result.returncode == expected,
              f"exit {result.returncode}: {(result.stdout + result.stderr)[:140]}")

    for line in PASSES:
        print("PASS " + line)
    for line in FAILURES:
        print("FAIL " + line, file=sys.stderr)
    print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
