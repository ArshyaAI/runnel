# Runnel v0.1 threat model

## Assets to protect

1. Active coding work and its owning terminal/editor/cmux/database processes.
2. Correct binding between an observed process and any process receiving SIGTERM.
3. Local Codex conversation/session privacy.
4. Integrity and durability of recovery receipts.
5. The user's expectation that a read-only command is actually read-only.

## Trust boundaries

```text
untrusted changing host state
  ├─ process table / PID reuse / exec
  ├─ writable temp scripts and paths
  ├─ Codex SQLite WAL and rollout files
  ├─ lsof/sample/codesign output
  └─ receipt filesystem namespace
                 │
                 v
      bounded read-only adapters
                 │ typed availability + evidence
                 v
       deterministic classifier
          │                │
          │ unselectable   │ exact supported candidate
          v                v
       renderer      full action-time recheck
                              │
                    immutable prepared receipt
                              │
                kernel identity-bound SIGTERM
                              │
                   verification + result receipt
```

No renderer, user-supplied PID, model output, score, or family label can create an
action plan.

## Primary threats and controls

| Threat | Control |
| --- | --- |
| PID exits and is reused | Darwin audit-token signal includes `p_idversion`; kernel rejects mismatch with `ESRCH`; no raw-PID fallback. |
| Target `exec`s after validation | XNU changes `p_idversion` on every successful exec; old token fails; native test gates release. |
| Look-alike/mutated ChatGPT chain | Identity-bound path, Security.framework validity/designated requirement, exact version and SHA-256, parent/argv relationship. |
| Session becomes active before action | Stable SQLite snapshot plus exact row/tail/inode/descriptor/origin relationship repeated immediately before signal. |
| Protected process enters target set | Protection is subtracted structurally before opaque action-plan construction. |
| Multi-process partial action | v0.1 accepts one childless worker leaf only; new child refuses. |
| Probe hangs/leaks child | Direct argv, isolated process group, deadline/output ceiling, complete wait, bounded probe-only TERM/KILL cleanup. |
| Receipt missing after signal | Immutable prepared receipt is fsynced before signal; result is created separately exactly once. |
| Symlink/path collision | Owned 0700 traversal, `lstat`, `O_EXCL|O_NOFOLLOW`, immutable destinations, inode/mode/owner verification. |
| Private data reaches share object | Separate closed Go type and JSON Schema with forbidden-field property tests. |
| Missing permission looks healthy | Explicit unavailable enum; action classifier fails closed. |
| Terminal error leaves broken state | Bubble Tea context lifecycle plus PTY resize/cancel/panic restoration tests. |

## Adversary model

v0.1 protects against accidental PID reuse, concurrent host changes, malformed or stale
local state, same-user path races, unsupported software versions, and honest-but-buggy
adapters. It does not claim to defeat a malicious root user, a compromised kernel, or an
attacker able to replace Runnel itself. A fully compromised current user account can
already signal that user's processes and read most local session data.

## Residual risk

Apple documents libproc as private and subject to change. Runnel therefore resolves the
identity-bound symbol at runtime, tests the kernel behavior on supported releases, and
disables recovery if the primitive or its observed contract changes. Read-only radar
remains useful when recovery is unsupported.
