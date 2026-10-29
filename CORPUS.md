# Corpus work tracker

The point of this file is to STOP rework. Before starting an application, check here.

Built from the binaries themselves -- the architecture column is read from each PE file's
COFF machine field, not from the directory it sits in, because those disagree (the
`cli-apps` directory holds both x86 and x86_64 builds of the same program).

## Status vocabulary

| status | meaning |
|---|---|
| **PORTED** | translated, built, run AND differentially verified. Do not rework; a re-run is a regression check. |
| **REFUSED** | a CORRECT refusal -- packed, managed .NET, or an unsupported input format. Not a bug, and not work. |
| **BLOCKED** | a real gap with a named cause (instruction, import, discovery, runtime). This is the work list. |
| **UNMEASURED** | nobody has run it yet. Unknown is not the same as failing. |

## Ported -- do NOT rework

These are the same four programs built for both architectures. Re-running them is a
regression check.

| application | arch | evidence |
|---|---|---|
| `arith-calc.exe` | x86 | `AUTORECOMP COMPLETE`, verified; 161 bytes |
| `arith-calc.exe` | x86_64 | `AUTORECOMP COMPLETE`, verified |
| `tetris.exe` | x86 | `AUTORECOMP COMPLETE`, verified; 220 bytes |
| `base64.exe` | x86 | `AUTORECOMP COMPLETE`, verified; 204 bytes |
| `base64.exe` | x86_64 | `AUTORECOMP COMPLETE`, verified; 218 bytes |
| `hangman.exe` | x86 | `AUTORECOMP COMPLETE`, verified; 178 bytes |
| `hangman.exe` | x86_64 | `AUTORECOMP COMPLETE`, verified; 347 bytes |

| `g64_game2048.exe` | x86_64 | `AUTORECOMP COMPLETE`, VERIFIED, 353 bytes, 2/2 checkpoints |

## Refused -- correct, and NOT work

| application | arch | reason |
|---|---|---|
| `imgview64.exe` | x86_64 | UPX-packed; the machine code is not in the file, so functions cannot be recovered. Unpack it first. |
| `micro.exe` | arm64 | Windows ARM64 PE. This build reads PE32 (x86) and PE32+ (x86-64) only. |
| `TicTacToe.exe`, `luhn.exe` | x86 | Managed .NET; the code is IL bytecode, so there is nothing for a machine-code lifter to lift. |

## The work list

Every other binary in the corpus. Status is filled in from the sweep reports
(`reports/corpus-x86-progress.md`, `reports/corpus-x64-progress.md`), not from memory.

| `blackbox.exe` | x86 | UNMEASURED |
| `blackbox.exe` | x86_64 | UNMEASURED |
| `bridges.exe` | x86 | UNMEASURED |
| `bridges.exe` | x86_64 | UNMEASURED |
| `busybox.exe` | x86 | UNMEASURED |
| `busybox.exe` | x86_64 | UNMEASURED |
| `clipjar.exe` | x86_64 | UNMEASURED |
| `cube.exe` | x86 | UNMEASURED |
| `cube.exe` | x86_64 | UNMEASURED |
| `dominosa.exe` | x86 | UNMEASURED |
| `dominosa.exe` | x86_64 | UNMEASURED |
| `dominosasolver.exe` | x86 | UNMEASURED |
| `fifteen.exe` | x86 | UNMEASURED |
| `fifteen.exe` | x86_64 | UNMEASURED |
| `fifteensolver.exe` | x86 | UNMEASURED |
| `filling.exe` | x86 | UNMEASURED |
| `filling.exe` | x86_64 | UNMEASURED |
| `fillingsolver.exe` | x86 | UNMEASURED |
| `flip.exe` | x86 | UNMEASURED |
| `flip.exe` | x86_64 | UNMEASURED |
| `flood.exe` | x86 | UNMEASURED |
| `flood.exe` | x86_64 | UNMEASURED |
| `fuzzpuzz.exe` | x86 | UNMEASURED |
| `galaxies.exe` | x86 | UNMEASURED |
| `galaxies.exe` | x86_64 | UNMEASURED |
| `galaxieseditor.exe` | x86 | UNMEASURED |
| `galaxiespicture.exe` | x86 | UNMEASURED |
| `galaxiessolver.exe` | x86 | UNMEASURED |
| `game2048.exe` | x86 | UNMEASURED |
| `game2048.exe` | x86_64 | UNMEASURED |
| `grapheditor.exe` | x86 | UNMEASURED |
| `guess.exe` | x86 | UNMEASURED |
| `guess.exe` | x86_64 | UNMEASURED |
| `guess_game_x64.exe` | x86_64 | UNMEASURED |
| `guess_game_x86.exe` | x86 | UNMEASURED |
| `imgview64.exe` | x86_64 | UNMEASURED |
| `inertia.exe` | x86 | UNMEASURED |
| `inertia.exe` | x86_64 | UNMEASURED |
| `keen.exe` | x86 | UNMEASURED |
| `keen.exe` | x86_64 | UNMEASURED |
| `keensolver.exe` | x86 | UNMEASURED |
| `lightup.exe` | x86 | UNMEASURED |
| `lightup.exe` | x86_64 | UNMEASURED |
| `lightupsolver.exe` | x86 | UNMEASURED |
| `loopy.exe` | x86 | UNMEASURED |
| `loopy.exe` | x86_64 | UNMEASURED |
| `loopysolver.exe` | x86 | UNMEASURED |
| `magnets.exe` | x86 | UNMEASURED |
| `magnets.exe` | x86_64 | UNMEASURED |
| `magnetssolver.exe` | x86 | UNMEASURED |
| `map.exe` | x86 | UNMEASURED |
| `map.exe` | x86_64 | UNMEASURED |
| `mapsolver.exe` | x86 | UNMEASURED |
| `mastermind_x64.exe` | x86_64 | UNMEASURED |
| `mastermind_x86.exe` | x86 | UNMEASURED |
| `micro.exe` | x86 | UNMEASURED |
| `micro.exe` | x86_64 | UNMEASURED |
| `mineobfusc.exe` | x86 | UNMEASURED |
| `mines.exe` | x86 | UNMEASURED |
| `mines.exe` | x86_64 | UNMEASURED |
| `mosaic.exe` | x86 | UNMEASURED |
| `mosaic.exe` | x86_64 | UNMEASURED |
| `netgame.exe` | x86 | UNMEASURED |
| `netgame.exe` | x86_64 | UNMEASURED |
| `netslide.exe` | x86 | UNMEASURED |
| `netslide.exe` | x86_64 | UNMEASURED |
| `notepad.exe` | x86_64 | UNMEASURED |
| `nullgame.exe` | x86 | UNMEASURED |
| `pageant.exe` | x86 | UNMEASURED |
| `pageant.exe` | x86_64 | UNMEASURED |
| `palisade.exe` | x86 | UNMEASURED |
| `palisade.exe` | x86_64 | UNMEASURED |
| `passgen.exe` | x86_64 | UNMEASURED |
| `passgen_x64.exe` | x86_64 | UNMEASURED |
| `pattern.exe` | x86 | UNMEASURED |
| `pattern.exe` | x86_64 | UNMEASURED |
| `patternpicture.exe` | x86 | UNMEASURED |
| `patternsolver.exe` | x86 | UNMEASURED |
| `pearl.exe` | x86 | UNMEASURED |
| `pearl.exe` | x86_64 | UNMEASURED |
| `pearlbench.exe` | x86 | UNMEASURED |
| `pearlsolver.exe` | x86 | UNMEASURED |
| `pegs.exe` | x86 | UNMEASURED |
| `pegs.exe` | x86_64 | UNMEASURED |
| `plink.exe` | x86_64 | UNMEASURED |
| `powder-toy.exe` | x86_64 | UNMEASURED |
| `prime-gen.exe` | x86 | UNMEASURED |
| `prime-gen_x86.exe` | x86 | UNMEASURED |
| `procexp64.exe` | x86_64 | UNMEASURED |
| `progress-quest.exe` | x86 | UNMEASURED |
| `psftp.exe` | x86 | UNMEASURED |
| `psftp.exe` | x86_64 | UNMEASURED |
| `putty.exe` | x86 | UNMEASURED |
| `putty.exe` | x86_64 | UNMEASURED |
| `puzzles.exe` | x86 | UNMEASURED |
| `range.exe` | x86 | UNMEASURED |
| `range.exe` | x86_64 | UNMEASURED |
| `rect.exe` | x86 | UNMEASURED |
| `rect.exe` | x86_64 | UNMEASURED |
| `samegame.exe` | x86 | UNMEASURED |
| `samegame.exe` | x86_64 | UNMEASURED |
| `signpost.exe` | x86 | UNMEASURED |
| `signpost.exe` | x86_64 | UNMEASURED |
| `signpostsolver.exe` | x86 | UNMEASURED |
| `singles.exe` | x86 | UNMEASURED |
| `singles.exe` | x86_64 | UNMEASURED |
| `singlessolver.exe` | x86 | UNMEASURED |
| `sixteen.exe` | x86 | UNMEASURED |
| `sixteen.exe` | x86_64 | UNMEASURED |
| `slant.exe` | x86 | UNMEASURED |
| `slant.exe` | x86_64 | UNMEASURED |
| `slantsolver.exe` | x86 | UNMEASURED |
| `snake-game.exe` | x86_64 | UNMEASURED |
| `snake.exe` | x86 | UNMEASURED |
| `snake.exe` | x86_64 | UNMEASURED |
| `solo.exe` | x86 | UNMEASURED |
| `solo.exe` | x86_64 | UNMEASURED |
| `solosolver.exe` | x86 | UNMEASURED |
| `sqlite3.exe` | x86_64 | UNMEASURED |
| `tents.exe` | x86 | UNMEASURED |
| `tents.exe` | x86_64 | UNMEASURED |
| `tentssolver.exe` | x86 | UNMEASURED |
| `tetris-classic.exe` | x86 | UNMEASURED |
| `tictactoe-net.exe` | x86 | UNMEASURED |
| `tictactoe.exe` | x86 | UNMEASURED |
| `tictactoe.exe` | x86_64 | UNMEASURED |
| `tictactoe_x64.exe` | x86_64 | UNMEASURED |
| `tictactoe_x86.exe` | x86 | UNMEASURED |
| `towers.exe` | x86 | UNMEASURED |
| `towers.exe` | x86_64 | UNMEASURED |
| `towerssolver.exe` | x86 | UNMEASURED |
| `tracks.exe` | x86 | UNMEASURED |
| `tracks.exe` | x86_64 | UNMEASURED |
| `trackssolver.exe` | x86 | UNMEASURED |
| `twiddle.exe` | x86 | UNMEASURED |
| `twiddle.exe` | x86_64 | UNMEASURED |
| `undead.exe` | x86 | UNMEASURED |
| `undead.exe` | x86_64 | UNMEASURED |
| `unequal.exe` | x86 | UNMEASURED |
| `unequal.exe` | x86_64 | UNMEASURED |
| `unequalsolver.exe` | x86 | UNMEASURED |
| `unruly.exe` | x86 | UNMEASURED |
| `unruly.exe` | x86_64 | UNMEASURED |
| `unrulysolver.exe` | x86 | UNMEASURED |
| `untangle.exe` | x86 | UNMEASURED |
| `untangle.exe` | x86_64 | UNMEASURED |
| `zoomit64.exe` | x86_64 | UNMEASURED |
