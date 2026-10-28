# Windows EXE to macOS app run results

- Run date: 2026-10-28
- Host: macOS arm64 (`macos-arm64`)
- Source OS: Windows (PE executables)
- Command: `recomp-studio autorecomp <EXE> --output <unique-$TEMP-path> --buildrun`
- Evidence: the images below are generated terminal-style snapshots of the recorded run results. These console apps did not produce native GUI-window screenshots.

## Verified successes

| App | Source architecture | Source OS | Target host | Build/run | Exit | Differential verification | Evidence |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| `hangman_x64.exe` | x64 | Windows | macOS arm64 | Passed | 0 | Passed | ![Run evidence for hangman_x64.exe](../apps-running-screenshots/hangman_x64.png) |
| `hangman_x86.exe` | x86 | Windows | macOS arm64 | Passed | 0 | Passed | ![Run evidence for hangman_x86.exe](../apps-running-screenshots/hangman_x86.png) |
| `fillingsolver.exe` | x86 | Windows | macOS arm64 | Passed | 0 | Passed | ![Run evidence for fillingsolver.exe](../apps-running-screenshots/fillingsolver.png) |

## Batch summary

- Unique executables tested: 86
- Run attempts including timeout retries: 99
- Verified successes: 3
- Other status counts (first-pass plus retry records): `{'FAIL': 82, 'PASS': 3, 'TIMEOUT': 14}`

The retry rows are additional attempts for selected first-pass timeouts, so status totals count attempts rather than unique executables.
