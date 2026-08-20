# Runnel v0.1 launch packet

**Status:** draft for review. No post, release, issue, or announcement has been
published by this document.

**Tagline:** Trace the work. Stop only what the evidence proves safe.

**Repository:** [github.com/ArshyaAI/runnel](https://github.com/ArshyaAI/runnel)
**License:** Apache-2.0

## The story in one paragraph

An AI coding workstation can look busy while a worker is only rereading work that
is already finished. That happened in a real Codex session: a completed worker kept
reading an unchanged 4.5 GB rollout while memory pressure worsened. A manual,
identity-checked investigation sent one targeted `SIGTERM`; free memory moved from
37% to 71%, and unrelated Codex and cmux sessions stayed alive. Runnel is the small,
local-first tool that turns the *evidence chain* behind that decision into a
read-only radar and a fail-closed contract. The incident was manual; it was not
recovered by Runnel.

## Final single X post

My Mac ran out of application memory while I was running Codex.

One “finished” worker was still rereading a 4.5 GB session. I manually proved it
was safe to stop, sent one targeted `SIGTERM`, and free memory jumped from 37% to
71%—without killing my active Codex or cmux work.

So I built Runnel: an open-source macOS CLI that shows which AI workflows are
active, protected, or safe to stop—and refuses to act when evidence is incomplete.

No telemetry. No daemon. No blind kill button.

github.com/ArshyaAI/runnel

### Recommended first reply

The original recovery was manual. Current Runnel proof is deliberately boring:
10 real scans at 0.24 s p95 and 22.2 MiB max RSS; a live protected workflow led to
ACTION LOCKED and no signal. That refusal is the product.

## Optional four-post thread

**1/4**

An AI coding workstation can be busy without making progress.

In a real Codex incident, a completed worker repeatedly reread an unchanged 4.5 GB
rollout while memory pressure worsened. A manual, identity-checked pass found it.

**2/4**

One targeted `SIGTERM` moved free memory from 37% to 71%. Unrelated Codex and cmux
sessions stayed alive.

That was a manual recovery—not Runnel output. The distinction matters.

**3/4**

Runnel turns the decision boundary into local, testable contracts: a read-only radar,
an exact four-sample Codex detector, protected-identity subtraction, and
action-time revalidation. Unknown or contradictory evidence stays locked.

**4/4**

The current proof is deliberately modest: 10 real scans at 0.24 s p95 and 22.2 MiB
max RSS; a live test classified a protected workflow, locked action, and sent no
signal. No telemetry, daemon, API key, `SIGKILL`, raw PID, or automated action.

Trace the work. Stop only what the evidence proves safe.

Runnel v0.1 — Apache-2.0
github.com/ArshyaAI/runnel

## 20–30 second demo script

The commands below are in the current CLI help and README. Use a built binary in a
recording when available; source checkout commands are included so the demo is
reproducible before a public release archive exists.

```bash
cd runnel
go run ./cmd/runnel --help
go run ./cmd/runnel scan --json
go run ./cmd/runnel doctor --self-test
```

Suggested narration:

1. “The problem is not CPU; it is knowing whether this exact worker is still doing
   useful work.”
2. Show the command list, then run the JSON scan. It is read-only and can return
   documented partial exit code `3` when macOS withholds process metadata; that is a
   limitation to show, not hide.
3. Run the in-memory doctor self-test. “Runnel can report capability and schema
   status without signaling anything.”
4. If an actual finding ID is visible in the scan, `runnel explain <finding>` is the
   exact supported next command. Do not invent an ID or claim a live recovery. The
   current observed live rows had no closed edge and remained locked.

For a binary recording, replace `go run ./cmd/runnel` with the path to the locally
built `runnel` binary; do not imply that a GitHub release archive or release URL
exists until the release gate is complete.

## Claims and evidence

| Claim | Evidence level | What can be said publicly | Boundary |
| --- | --- | --- | --- |
| A completed Codex worker repeatedly read an unchanged ~4.5 GB rollout during a memory incident. | Historical manual incident | This was the reason for the project. | It was not Runnel output. |
| A targeted `SIGTERM` moved free memory from 37% to 71%; unrelated Codex and cmux survived. | Historical manual incident | The manual recovery was targeted and bounded. | Do not say Runnel caused or automated it. |
| Runnel has a read-only workflow radar and an exact four-sample Codex detector. | Current code/contract | Runnel makes the evidence chain executable and testable. | A detector contract is not proof of a successful live signal. |
| Ten real fast scans measured 0.24 s p95 and 22.2 MiB maximum RSS. | Current read-only live calibration | These are measurements from the documented Apple M4 Pro dogfood host. | Local calibration, not a universal hardware promise; some scans returned partial exit 3. |
| The current live test classified a protected workflow, locked action, and sent no signal. | Current read-only/live safety test | Protected or contradictory evidence remains unselectable. | No automated recovery has been demonstrated. |
| The current adapter is exact and pinned to ChatGPT embedded Codex `0.148.0-alpha.15`. | Current adapter calibration | Recovery exists only behind that exact versioned adapter and opaque authority. | Standalone Codex `0.148.0` is visible but not action-supported; upgrades fail closed. |
| Current live rows had no closed edge. | Current adapter calibration | Runnel correctly left them locked. | Do not turn a missing/open edge into completion. |
| The product is local-only and has no telemetry, daemon, API key, raw-PID command, `SIGKILL`, or automated action. | Current README/threat model/code contract | These are deliberate product boundaries. | A future adapter would need a new review and evidence. |

Primary evidence files: [origin story](ORIGIN_STORY.md),
[performance evidence](PERFORMANCE.md), [Codex adapter calibration](CODEX_ADAPTER_CALIBRATION.md),
[detector contract](DETECTOR_CONTRACT.md), and the repository [README](../README.md).

## Launch checklist

Everything below is a review gate. External actions remain unchecked until the
action-time authorization is explicit and the corresponding receipt is captured.

- [ ] Confirm the final post/thread text and exact claims.
- [ ] Confirm the demo was recorded from a clean checkout or identify the local build
      used; retain the command output and the documented partial-scan caveat.
- [ ] Re-run the release candidate's local tests and `git diff --check`.
- [ ] Reconcile README, license, security/privacy docs, and release metadata.
- [ ] Confirm no private paths, raw process identifiers, prompt/response content,
      rollout bodies, or local receipts appear in screenshots or copy.
- [ ] Confirm the current Codex adapter/version evidence has not drifted.
- [ ] **External GitHub action: unchecked.** Create/publish a release, tag, or
      release asset only with action-time authorization and a captured GitHub receipt.
- [ ] **External X action: unchecked.** Post the single post or thread only with
      action-time authorization and a captured URL/receipt.
- [ ] **External HN/Reddit action: unchecked.** Submit only with action-time
      authorization and a captured URL/receipt.
- [ ] **External GitHub discussion/issue action: unchecked.** Open or announce only
      with action-time authorization and a captured URL/receipt.
- [ ] After any authorized publication, record exactly what was published and where;
      do not infer publication from a local draft, tag, or build.

## Suggested HN copy

**Title:** Runnel: a local-first macOS radar for deciding whether an AI coding worker is safe to stop

**Body:**

An AI coding workstation can be busy without making progress. Runnel began after a
manual Codex incident in which a completed worker repeatedly reread an unchanged
4.5 GB rollout. An identity-checked targeted `SIGTERM` moved free memory from 37%
to 71% while unrelated Codex and cmux sessions stayed alive. That recovery was
manual, not Runnel automation.

Runnel v0.1 turns the evidence boundary into a local CLI: read-only workflow radar,
an exact four-sample Codex detector, protected-identity subtraction, and
action-time revalidation. Unknown or contradictory states remain locked. Current
read-only proof is 10 real scans at 0.24 s p95 and 22.2 MiB max RSS. Recovery is
behind an exact pinned ChatGPT embedded Codex `0.148.0-alpha.15` adapter; current
live rows had no closed edge and stayed locked.

No telemetry, daemon, API key, `SIGKILL`, raw-PID command, or automated action.
Apache-2.0: https://github.com/ArshyaAI/runnel

## Suggested Reddit copy

**Title:** I built a local-first macOS CLI to inspect whether an AI coding worker is actually stale

**Body:**

The motivating failure was surprisingly specific: a Codex worker kept rereading a
completed 4.5 GB rollout while the workstation ran short of memory. A manual
forensic pass established the identity and evidence chain before one targeted
`SIGTERM`; free memory rose from 37% to 71%, and unrelated Codex/cmux sessions
survived. Runnel did not perform that recovery.

Runnel's current scope is intentionally narrow: local read-only scanning, an exact
four-sample Codex detector, protected workflows excluded from selection, and a
fail-closed recovery path. Ten real scans measured 0.24 s p95 and 22.2 MiB max RSS.
The current live test found a protected workflow, locked the action, and sent no
signal. The recovery adapter is pinned to ChatGPT embedded Codex
`0.148.0-alpha.15`; rows without a closed edge remain locked.

There is no telemetry, daemon, API key, `SIGKILL`, raw-PID command, or automated
action. Feedback on evidence contracts, macOS process identity, and safe failure
modes is welcome.

## Suggested GitHub release / announcement copy

### Runnel v0.1 — evidence-first local workflow radar

Runnel is a local-first macOS CLI for developers running many AI coding workflows.
It starts with a read-only radar, then explains whether an exact worker satisfies a
versioned, fail-closed evidence contract. Protected and contradictory states are
structurally unselectable.

This release is rooted in a manual Codex memory incident: a completed worker kept
rereading an unchanged 4.5 GB rollout. After exact identity and activity evidence
was checked, one targeted `SIGTERM` moved free memory from 37% to 71% while
unrelated Codex and cmux sessions stayed alive. That historical recovery must not
be confused with a Runnel automated recovery.

Current proof includes 10 real read-only scans at 0.24 s p95 and 22.2 MiB maximum
RSS, plus a live protected-workflow test that locked the action and sent no signal.
The current recovery path is available only behind the exact pinned ChatGPT
embedded Codex `0.148.0-alpha.15` adapter and opaque authority; observed rows with
no closed edge correctly remained locked.

Runnel is local-only: no telemetry, daemon, API key, `SIGKILL`, raw-PID command, or
automated action. Apache-2.0.

## Likely technical objections and replies

**“Is this just a CPU heuristic?”**
No. High CPU and low activity are separate signals. The detector requires four
identity-preserving samples plus correlated metadata, bounded completion evidence,
stack/read evidence, and exclusion of TTYs, sockets, children, and protected
identities. Unknown or contradictory evidence stays locked.

**“Did Runnel recover the 4.5 GB incident?”**
No. The incident was recovered manually. It motivates the contract; it is not a
Runnel success metric.

**“Have you demonstrated an automated live kill?”**
No. The current live test classified a protected workflow, locked the action, and
sent no signal. Recovery is deliberately behind the exact alpha15 adapter and
opaque authority.

**“Why not accept any Codex 0.148 binary?”**
Because version labels are not identity or protocol proof. The adapter is pinned to
the ChatGPT embedded `0.148.0-alpha.15` origin/signature/digest/grammar. The
standalone `0.148.0` binary is visible but not action-supported; drift fails closed.

**“Can a PID be reused between scan and action?”**
The action contract revalidates immediately and uses Darwin's identity-bound
`proc_signal_with_audittoken` with `pidversion`; there is no fallback to a generic
`kill(pid, ...)`. This is a design claim backed by the Darwin identity tests, not a
claim that arbitrary processes are safe to stop.

**“Does it upload prompts, rollouts, or telemetry?”**
No. Runnel is local-only and does not copy prompt, response, tool payload, raw
stack, or rollout body into snapshots or receipts. Local diagnostic JSON can still
contain private process paths, so it should not be posted unreviewed.

**“What happens when macOS denies process metadata?”**
The scan can emit schema-valid partial output with documented exit code `3`. Partial
or unavailable evidence is not promoted to a candidate and does not unlock recovery.

**“Why not use `SIGKILL` to guarantee cleanup?”**
Runnel has no `SIGKILL` path. A narrow, identity-bound `SIGTERM` is the only planned
signal, and only after durable intent, confirmation, and immediate revalidation.

**“Is 0.24 seconds a benchmark guarantee?”**
No. It is a local measurement: ten real scans on an Apple M4 Pro dogfood host,
nearest-rank p95 0.24 s and maximum RSS 22.2 MiB. The project documents budgets and
limitations rather than promising every machine will match them.

## README insertion suggestion

The current README has no link to this packet. If the maintainer wants one, add a
single link near the existing introductory/Contributing links, for example:

```markdown
For the reviewable public launch copy and evidence boundaries, see
[the launch packet](docs/LAUNCH_PACKET.md).
```

This packet intentionally does not edit the README.
