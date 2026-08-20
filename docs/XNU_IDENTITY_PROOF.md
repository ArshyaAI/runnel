# Why Runnel does not signal a raw PID

Runnel's recovery contract must survive two classic races:

1. the observed process exits and macOS reuses its PID;
2. the process keeps its PID but successfully `exec`s another executable.

A userspace sequence of “read start time, then call `kill(pid, SIGTERM)`” cannot close
either window. Runnel therefore has no raw-PID signal fallback.

## Current XNU path

Research was verified on 2026-08-20 against Apple XNU commit
[`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`](https://github.com/apple-oss-distributions/xnu/tree/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea).

The relevant path is:

```text
Runnel
  -> proc_signal_with_audittoken(token{pid, p_idversion}, SIGTERM)
  -> proc_find_audit_token
       rejects absent PID or mismatched p_idversion
  -> proc_ident_with_policy(EXACT)
  -> proc_find_ident
       reacquires PID + unique ID + pidversion
  -> permission checks
  -> psignal(held proc reference, SIGTERM)
```

`bsd/kern/kern_exec.c` assigns a newly incremented `p_idversion` after successful exec
and loops until it differs from the previous value. The old token therefore cannot
signal the replacement image. `bsd/kern/kern_proc.c` validates the pidversion embedded
in the token. `bsd/kern/proc_info.c` reacquires and holds the exact process reference
before signaling.

Runnel calls `proc_signal_with_audittoken` with SIGTERM. It never calls
`proc_terminate_with_audittoken`, because that separate sudden-termination API may
choose SIGKILL.

## Release proof

Every supported Darwin build must pass native tests using only children spawned by the
test:

- a wrong pidversion returns `ESRCH` and the child survives;
- after the child execs a distinct helper, the pre-exec token returns `ESRCH` and the
  replacement survives;
- a newly resolved exact token delivers SIGTERM to only that owned replacement;
- the Runnel test runner, caller process group, and protected sentinel survive.

If the symbol is unavailable or any test fails, `runnel doctor` reports recovery as
unsupported and the product remains read-only.

## API stability

Apple's `libproc.h` labels these interfaces private and subject to change. That is why
the runtime behavior is feature-detected and release-tested rather than inferred from
the OS version number. The public promise is fail-closed behavior, not permanent API
availability.
