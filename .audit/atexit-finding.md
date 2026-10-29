# The `atexit` bucket is a MISCLASSIFICATION, and the real cause is different

Round 73 investigated the second-biggest bucket in the x86 sweep: **19 applications** it
labelled `runtime:atexit-not-run`. The label is wrong, and finding that out is worth more
than the shim I nearly wrote.

## What the sweep saw, and why it is not the cause

Every one of those applications prints this on stderr:

    recomp: the guest registered an atexit handler at 0x401010 (a recompiled function),
            which did not run; exit handlers are registered but not executed

The sweep read that line as the cause. It is not. **Applications that PASS print it too**:

| application | the atexit line | verdict |
|---|---|---|
| `base64` | present | `AUTORECOMP COMPLETE`, VERIFIED |
| `fillingsolver` | present | `AUTORECOMP COMPLETE` |
| `game2048` | present | `AUTORECOMP COMPLETE` |
| `dominosasolver` | present | FAILED |
| `fifteensolver` | present | FAILED |

Three of five pass with the identical message. A classifier that reads a diagnostic as a
root cause will bucket both groups together, which is what happened. **The stated reason a
runtime step failed is in `<project>/recomp-stderr.log`, and a line being present there does
not make it the cause.**

## What actually fails, in the one case examined closely

`dominosasolver`:

    reference executed 365 instructions, 1/1 checkpoints matched, outputs_match=yes
    candidate execution failed with exit code 1

The candidate exits **1**, the reference exits **0**, and **the outputs already match**. So
the divergence is the exit STATUS, and it is not something the handlers produce -- running
them does not change it. I measured that: with the candidate running its compiled handlers,
`dominosasolver` still exits 1.

## The change I did NOT make, and why

The obvious fix is to run the handlers. On the CANDIDATE that is easy -- they are compiled
functions. On the REFERENCE it means continuing emulation at each handler, and the code says
an earlier attempt at that "consumed the instruction budget". The reason is now clear: without
a way to recognise the handler RETURNING, emulation runs past it into the rest of the program.

I implemented the candidate half, measured it, and then **reverted it**. Running the handlers
on one side only is exactly what the existing comment warns against:

> Running them on one side only makes the two sides' output differ for every program that
> registers one, which is worse than not running them on either.

That is not a hypothetical: it is an invariant the verification depends on. A change that
breaks it would have made the differential harness report divergence for programs that are
correctly translated, and I would have been trading a mislabelled bucket for a false failure.

**The correct fix is both sides together**: a sentinel return address so the reference stops
when a handler returns, and the candidate calling its compiled handler. That is a change to
the verification core and it needs its own round, its own measurement, and a mutation test
that proves it detects a handler that does NOT run.
