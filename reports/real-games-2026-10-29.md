# Real Windows games: macOS arm64 test

These are the 15 main executables identified in `recomp-apps/games/README.md`.
The run used Recomp Studio commit `af81a1a`, `autorecomp --buildrun --timeout 5`,
and a 120-second pipeline and 1.8 GB process-group RSS limit per game. The
`win32` and `win64` folders are links to the game folders. Generated projects
are in the local temporary directory `recomp-real-games-qdk3_4q5`; captured
[terminal and pipeline logs](real-games-2026-10-29-logs/) are included here.
Missing import counts are the tool's handler census, not a claim of working APIs.

| Game and executable | PE architecture | Imports missing | Result |
| --- | --- | ---: | --- |
| Cave Story `cavestory/Doukutsu.exe` | x86 | 35 | Translation stopped at `iretd` (0x41000d). |
| GeneRally `generally/GeneRally.exe` | x86 | 130 | Translation stopped at `cvtpd2ps` (0x406a89). |
| Warning Forever `warning_forever/wf.exe` | x86 | 39 | Translation stopped at `cmpltpd` (0x434830). |
| Hero Core `herocore/herocore gm7.exe` | x86 | 310 | Translation stopped at `arpl` (0x40113a). |
| Ikachan `ikachan/dxIka.exe` | x86 | 21 | Built, native exit 3 at `kernel32.dll!OpenMutexA`; verification failed. |
| Noiz2sa `noiz2sa/noiz2sa.exe` | x86 | 60 | Translation stopped at `arpl` (0x401988). |
| rRootage `rrootage/rr.exe` | x86 | 83 | Translation stopped at `arpl` (0x401842). |
| Torus Trooper `torus_trooper/tt.exe` | x86 | 102 | Translation stopped at `jcxz` (0x42938b). |
| Parsec47 `parsec47/p47.exe` | x86 | 99 | Translation stopped at `jcxz` (0x4246df). |
| Gunroar `gunroar/gr.exe` | x86 | 82 | Translation stopped at `jcxz` (0x42fceb). |
| Tumiki Fighters `tumiki_fighters/tf.exe` | x86 | 95 | Translation stopped at `jcxz` (0x41c69b). |
| Cannonball `cannonball/cannonball.exe` | x64 | 179 | Translation stopped at `cvttpd2dq` (0x14002fe9c). |
| OpenTyrian `opentyrian/opentyrian.exe` | x64 | 96 | Translation stopped at `cmpnless` (0x140008e44). |
| Pixeltetris `pixeltetris/Pixeltetris.exe` | x64 | 51 | Translation stopped at `movntps` (0x14005cc00). |
| Snake `snake/snake-windows-x86_64.exe` | x64 | 92 | Built, native exit 3 at `_get_initial_narrow_environment`; verification failed. |

**Verified playable games: 0 of 15.** The 13 translation failures did not run;
the original CLI incorrectly displayed exit code 0 for those failures. The
instruction addresses are discovery candidates, not proof that each instruction
is reachable code. The two built programs did not pass differential verification.

## Separate PCRecomp experiment: Ikachan

PCRecomp commit `a85ea970f9e0640ab6546d2ca7a01fccb132973d` generated and
compiled low-level C, and its own Win32 runtime bound all 97 imports, including
the DirectSound ordinal. Running with a copied game directory opened a native
SDL window and reached the game's startup dialog calls, but the window remained
black. [Captured window](../apps-running-screenshots/ikachan-pcrecomp-black-window.png)
is evidence of this failure, not gameplay or a successful port. No game assets
or binaries are included in this repository.

### Follow-up: indexed bitmap experiment

An adapted PCRecomp GDI implementation fixed reads from packed 1-bit and 4-bit
bitmaps; a focused test checks the guest DIB-to-BitBlt path. In a separate
experimental SDL host, a scripted Enter dismissed the initial dialog and the
[native window displayed Ikachan's title screen](../apps-running-screenshots/ikachan-pcrecomp-title.png).
The process used the user's original assets, and was manually terminated. This
is not the standard `autorecomp` pipeline, a gameplay test, or an independent
verification. Packed bitmap writes and broader GDI coverage remain incomplete.
