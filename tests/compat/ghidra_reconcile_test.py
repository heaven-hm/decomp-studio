#!/usr/bin/env python3
"""The reconciler must DISTINGUISH agreement from contradiction, and must not merge.

A reconciliation layer that reports "N functions recovered" without saying which source
found what is worse than no layer: it launders one provider's guess into a number that
looks corroborated. So this test drives the reconciler with records that are deliberately
right, deliberately wrong, and deliberately partial, and asserts it says so.

The addresses are read from the binary's own discovery rather than hard-coded, because a
hard-coded address would be a fact about one fixture's layout and would silently stop
testing anything the moment the fixture changed.
"""
import json
import subprocess
import sys
import tempfile
import pathlib
import os

CLI = sys.argv[1]
fixture_dir = tempfile.TemporaryDirectory(prefix="recomp-reconcile-")
FIXTURE = str(pathlib.Path(fixture_dir.name) / "arith.exe")
compiler = os.environ.get("CC", "x86_64-w64-mingw32-gcc")
subprocess.run([compiler, "-O2", "-nostdlib", "-ffreestanding", "-fno-asynchronous-unwind-tables",
                "-fno-stack-protector", "-fno-tree-vectorize", "-fno-tree-slp-vectorize",
                "-Wl,--no-insert-timestamp", "-Wl,-e,recomp_entry", "-Wl,--subsystem,console",
                "-o", FIXTURE, sys.argv[2], "-lkernel32", "-lgcc"], check=True)
PASSES, FAILURES = [], []


def check(name, ok, detail=""):
    (PASSES if ok else FAILURES).append(name if ok else f"{name}: {detail}")


def run(record_text):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        handle.write(record_text)
        path = handle.name
    result = subprocess.run([CLI, FIXTURE, path], capture_output=True, text=True)
    try:
        return json.loads(result.stdout), result.returncode
    except json.JSONDecodeError:
        return None, result.returncode


# The local functions, discovered independently, so the test states no addresses of its own.
local, _ = run(json.dumps({"functions": []}))
local_addresses = [f["address"] for f in local["functions"]]
check("reconcile/has-local-functions", len(local_addresses) > 0, "no functions discovered")
check("reconcile/empty-record-has-no-agreement", local["address_agreement"] == "none",
      f"a record with no functions reported {local['address_agreement']!r}")

for invalid in ('not json', '{"functions": [', '{"address":"401000"}',
                '{"functions":[{"address":"401000junk"}]}',
                '{"functions":[{"address":"401000"},{"address":"401000"}]}'):
    value, code = run(invalid)
    check("reconcile/rejects-invalid-record", value is None and code != 0, invalid)

# A record that AGREES: every local address, and nothing else.
agreed_record = json.dumps({"schema_version": 1, "functions":
                            [{"address": a, "name": "f"} for a in local_addresses]})
agreed, code = run(agreed_record)
check("reconcile/agreement-json", agreed is not None, "no JSON for an agreeing record")
if agreed:
    check("reconcile/agreement-does-not-prove-identity", agreed["binary_export_association"] == "unverified",
          f"fabricated matching addresses reported {agreed['binary_export_association']!r}")
    check("reconcile/agreement-complete", agreed["address_agreement"] == "complete",
          f"full address agreement reported {agreed['address_agreement']!r}")
    check("reconcile/agreement-counts", agreed["agreed"] == len(local_addresses),
          f"{agreed['agreed']} agreed of {len(local_addresses)}")
    check("reconcile/agreement-has-no-dissent",
          agreed["provider_only"] == 0 and agreed["local_only"] == 0,
          f"provider_only={agreed['provider_only']} local_only={agreed['local_only']}")
    check("reconcile/agreement-exit-zero", code == 0, f"exit {code}")
    check("reconcile/agreement-remains-unverified",
          all(f["verification"] == "unresolved" for f in agreed["functions"]),
          "address agreement was treated as behavioral verification")

# A record with ONE FALSE address: the association must NOT be called verified, the false
# address must be reported as the provider's alone, and the exit status must say so.
partial = json.dumps({"schema_version": 1, "functions":
                      [{"address": a, "name": "f"} for a in local_addresses] +
                      [{"address": "deadbeef", "name": "invented"}]})
mixed, code = run(partial)
check("reconcile/partial-json", mixed is not None, "no JSON for a partial record")
if mixed:
    check("reconcile/partial-is-not-verified",
          mixed["binary_export_association"] != "verified",
          f"a record with an invented address was reported {mixed['binary_export_association']!r}")
    check("reconcile/partial-names-the-provider-only-address", mixed["provider_only"] == 1,
          f"provider_only={mixed['provider_only']}")
    check("reconcile/partial-does-not-merge",
          mixed["agreed"] == len(local_addresses) and mixed["local_only"] == 0,
          f"agreed={mixed['agreed']} local_only={mixed['local_only']}")
    check("reconcile/partial-exit-nonzero", code != 0, f"exit {code}")
    invented = [f for f in mixed["functions"] if f["address"] == "deadbeef"]
    check("reconcile/invented-address-is-unresolved",
          bool(invented) and invented[0]["verification"] == "unresolved",
          "an address only the provider claims was marked resolved")

# A record that claims an address this project did NOT find must be preserved, not dropped:
# the conflict is the finding.
check("reconcile/conflict-preserved", bool(invented) if mixed else False,
      "the conflicting hypothesis was discarded instead of reported")

# CALLING CONVENTIONS, reported from the function's own `ret` and never applied. The
# reconciliation rule is that a convention is not changed without an ABI test, so the tool
# must REPORT what it derived rather than rewrite anything.
check("reconcile/reports-conventions", isinstance(agreed.get("conventions"), dict) if agreed else False,
      "no conventions reported")
if agreed and isinstance(agreed.get("conventions"), dict):
    total = sum(agreed["conventions"].values())
    check("reconcile/conventions-cover-functions", total == len(local_addresses),
          f"conventions cover {total} of {len(local_addresses)} functions")
    check("reconcile/conventions-are-named",
          all(k in ("cdecl", "stdcall", "unknown") for k in agreed["conventions"]),
          f"unexpected convention names: {list(agreed['conventions'])}")
    check("reconcile/unknown-is-not-guessed",
          "unknown" not in agreed["conventions"] or agreed["conventions"]["unknown"] < len(local_addresses),
          "every function was reported unknown, so the `ret` scan is not reading anything")

for line in PASSES:
    print("PASS " + line)
for line in FAILURES:
    print("FAIL " + line, file=sys.stderr)
print(f"{len(PASSES)} passed, {len(FAILURES)} failed")
sys.exit(1 if FAILURES else 0)
