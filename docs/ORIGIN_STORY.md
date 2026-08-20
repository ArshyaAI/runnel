# Origin story: from a memory incident to an evidence contract

Runnel began with a real workstation failure, but the incident and the product proof
must remain distinct.

## Confirmed historical incident

During a high-parallelism AI-development session, macOS reported severe application
memory pressure. A bounded manual investigation found one coding-agent worker that was
mechanically active but no longer producing useful work:

- its associated session file was approximately 4.5 GB;
- file size and modification time stayed unchanged across repeated checks;
- the bounded tail ended in a terminal completion event;
- CPU time continued to rise;
- descriptors and a short stack sample showed repeated read/decode work over the same
  completed file;
- parent, ownership, TTY, and network checks separated it from active sessions.

After immediate identity revalidation, only the confirmed worker received `SIGTERM`.
Unrelated Codex parents and cmux remained alive. System-wide free-memory percentage rose
from 37% to 71%. No file, session, worktree, or cache was deleted.

This is historical manual incident evidence. It is not presented as output produced by
Runnel.

## What the incident taught us

```text
high resource use  ≠  stale
CPU increasing     ≠  useful progress
same UID           ≠  coding workflow
PID                ≠  stable identity
completed file     ≠  safe to stop, by itself
```

The decision required a conjunction of independent facts and a separate action-time
identity check. That became Runnel's product boundary:

1. broad read-only workflow visibility;
2. one narrow, versioned action contract;
3. protected identities subtracted before selection;
4. exact confirmation plus durable intent;
5. identity-bound `SIGTERM` only;
6. target absence and protected presence verified afterward.

## Public claim levels

Runnel documentation and launch material distinguish four evidence levels:

1. **Historical incident** — the manual case summarized above.
2. **Synthetic harness** — owned fixtures and child processes used in automated tests.
3. **Read-only live calibration** — real scans or explanations that send no signal.
4. **Live recovery** — only if separately approved and accompanied by a reconciled
   private/share receipt.

No level is silently promoted into another. A passing fixture is not a live recovery;
a read-only live finding is not proof that a signal was sent; and an unavailable real
candidate never justifies weakening the detector.
