# Detector contract

This document describes what a future action detector must prove before Runnel can
offer it in `recover`.

## Two separate concepts

```text
family adapter                 action detector
-------------                  ---------------
labels observable work         proves one exact mutation target
may be broad                   version/origin pinned
read-only only                 every positive gate required
unknown is acceptable          any unknown is unselectable
```

Adding a family label does not add a recovery capability.

## Required detector artifact

Each detector version includes:

1. Stable detector ID and exact supported tool/version/origin range.
2. Executable, signature, digest, argv, parent, and descendant grammar.
3. Required metadata and bounded file/tail/stack parsers.
4. Full positive-evidence list.
5. Every disqualifier, contradiction, unavailable code, and refusal reason.
6. Action-time repeat/check contract.
7. Privacy-safe fixture corpus and SHA-256 manifest.
8. Active, paused/ambiguous, stale, PID reuse, exec, permission, schema, tail, stack,
   TTY, socket, writable activity, new-child, and origin-negative tests.
9. Exact target/protected verification and receipt reconciliation.
10. Independent reviewer PASS with no open P0/P1.

## Fail-closed state table

| Evidence | Observation | Action capability |
| --- | --- | --- |
| All exact gates pass | `supported_stale_candidate` | Can construct opaque plan |
| Positive recent activity | `recently_active` | Never |
| Little observed activity, no contract | `quiet_unclassified` | Never |
| Protected identity/reason | `protected` | Never |
| Missing, unsupported, malformed, changing, or contradictory | `unknown` | Never |

No score or threshold can override a disqualifier.

## Review and rollout

New detectors ship disabled until their fixture suite, synthetic owned-process dogfood,
read-only live calibration, and platform identity tests pass. A real process signal
still requires the user to inspect the exact target/evidence and enter the displayed
finding token. Detector updates support one reviewed tool version at a time.
