# Runnel v0.1 Engineering Plan

Date: 2026-08-20  
Branch: `feat/v0.1`  
Module: `github.com/ArshyaAI/runnel`  
Status: pre-implementation engineering review  
Source product design: approved AI Workstation Doctor design, 9/10 independent review

## Outcome

Ship a macOS-first open-source binary that makes expensive AI-development workflows
understandable every day and permits one narrow recovery action only when a versioned,
fail-closed Codex detector proves an exact target set.

Product promise:

> Trace the work. Stop only what the evidence proves safe.

The first public release is useful even when it finds no action candidate. It groups
processes by coding workflow, explains resource ownership, and labels the freshness and
limits of every observation. The only mutation surface is `runnel recover`; it can send
`SIGTERM` only to a target plan produced by the exact supported Codex adapter and
revalidated immediately before action.

## Scope challenge and decision

The complete product crosses more than eight files and introduces more than two
packages. A reduced implementation could ship only a scanner and plain text table.
That would be faster but would omit the product's trust wedge, proof receipt,
distribution, and launch artifact. Arshya explicitly requested delivery from zero to
production-ready after approving the Dual-Layer design, so the complete scope is
accepted as-is.

Completeness is bounded by a strict v0.1 exclusion list rather than by skipping error
paths or tests.

## Product and safety invariants

1. The default command and `scan` are read-only.
2. A portable process identity is `(pid, start_time, uid, executable)`. Darwin action
   identity additionally requires the kernel `p_idversion` and `p_uniqueid`; PID alone
   is never used for attribution, selection, signaling, or verification.
3. Recorded session state is evidence, never a runtime-liveness claim.
4. `unknown`, incompatible, unavailable, contradictory, protected, active, and quiet
   findings are structurally unable to produce an action plan.
5. Only an exact versioned detector can produce `supported_stale_candidate`.
6. Protected identities never enter a selectable target set.
7. Immediate revalidation is followed by identity-bound Darwin signaling. Runnel sends
   `SIGTERM` through `proc_signal_with_audittoken`, whose kernel path resolves PID plus
   `p_idversion`, acquires the exact process reference, performs permission checks, and
   signals that reference. A reused PID or post-validation `exec` returns `ESRCH`
   instead of reaching a replacement image.
8. v0.1 sends `SIGTERM` only. There is no `SIGKILL` fallback.
9. A successful signal syscall is not success. Verification requires every selected
   identity to be absent and every protected identity checked by the transaction to
   remain present.
10. A local receipt and a share receipt are different schemas and encoders. Share data
    is never produced by redacting a private receipt.
11. Missing permission or probe output yields an explicit unavailable code, never a
    clean bill of health.
12. No runtime network request, account, API key, telemetry, daemon, or background
    process exists.

## What already exists

| Subproblem | Existing source | Decision |
| --- | --- | --- |
| Codex thread and spawn-edge metadata | `codex-session-live/lib/session-store.mjs` (MIT) | Port the read-only SQLite, schema gate, and stable `data_version` snapshot invariants to Go. Do not port UI/server code. |
| Privacy-safe session demo | `codex-session-live/lib/demo-sanitize.mjs` (MIT) | Reuse the separate-public-object principle, but implement a stricter enumerated allowlist. |
| Device baseline concepts | Pre-existing unlicensed local health script | Reimplement from first principles. Use only its audit-first behavior as a smoke-test oracle; do not import or publish the source. |
| Proven stale-worker incident | 2026-08-18 evidence receipt | Turn the observed unchanged completed rollout + CPU/read loop + no live ownership pattern into a synthetic, privacy-safe fixture contract. Do not copy conversation data. |
| Mole UX grammar | public Mole v1.51.0 research | Reuse interaction principles only: one command, semantic progress, visible protection, explicit selection, measurable receipt. No GPL code, names, assets, or wording. |

No existing local component safely establishes process lineage, exact start identity,
deep descriptor/stack evidence, pre-signal revalidation, or a reconciled recovery
receipt. Those are new code.

## Architecture

Use a small native Go binary with explicit capability boundaries.

```text
                     READ-ONLY CAPABILITY

 argv / TTY ──> Cobra command ──> scan.Service ──> darwin.Source
                                      │                │
                                      │                ├─ gopsutil/sysctl process facts
                                      │                ├─ bounded cwd/executable probes
                                      │                └─ global listening-socket map
                                      │
                                      ├─ workflow.Grouper
                                      ├─ protect.Policy
                                      ├─ codex.Observer (SQLite + bounded tail)
                                      └─ Snapshot ──> text / TUI / local JSON / share JSON

                  MUTATION CAPABILITY (RECOVER ONLY)

 selected group ──> codex.Detector ──> evidence.Window (t=0,2,4,6)
                                            │
                                            ├─ exact origin/version/argv
                                            ├─ unchanged completed rollout
                                            ├─ CPU delta + supported read-loop stack
                                            ├─ no TTY/listen/established connection
                                            └─ no protected identity
                                                       │
                                             gated recovery.Plan
                                                       │
 token confirmation ──> identity revalidation ──> SIGTERM ──> verify
                                                       │
                                             local Receipt + ShareReceipt
```

### Package boundaries

| Package | Responsibility | May mutate host? |
| --- | --- | --- |
| `internal/model` | Versioned enums, identities, observations, evidence codes, snapshots | No |
| `internal/platform/darwin` | Bounded macOS process, memory, TTY, socket, descriptor, and stack probes | No; signaling is a separate implementation |
| `internal/workflow` | Pure grouping, family attribution, resource aggregation, protected policy | No |
| `internal/codex` | Read-only SQLite/tail adapter, origin/version grammar, deterministic detector | No |
| `internal/recovery` | Opaque action-plan constructor, confirmation token, revalidation, SIGTERM transaction | Yes, only through injected `Signaler` and only after all gates |
| `internal/receipt` | Private receipt, allowlisted share encoder, schema validation, atomic store | Files only, `0700`/`0600` under user data dir |
| `internal/ui` | Bubble Tea state machine plus plain text and JSON rendering | No direct system capability |
| `internal/cli` | Cobra command composition, IO/context injection, exit-code mapping | Delegates; no process logic |

The UI cannot turn an observation into a candidate. `recovery.Plan` contains an
unexported validity proof and is constructed only by a recovery gate supplied with a
fully passing detector result. The signaler accepts a `Plan`, not arbitrary PIDs.

### Dependencies

Keep dependencies boring and bounded:

- Cobra for strict subcommands, help, shell completion, command contexts, and testable
  IO construction.
- Bubble Tea for terminal lifecycle, keyboard/resize handling, context cancellation,
  and a deterministic Model/Update/View loop.
- Lip Gloss for adaptive, ANSI-aware semantic styling; no color is required for state.
- gopsutil/v4 for cross-checked Darwin process identity, CPU, RSS, and host metrics.
- mattn/go-sqlite3 for a small native read-only Codex metadata adapter; CGO is already
  required by the identity and signature gates.
- santhosh-tekuri/jsonschema/v6 for embedded Draft 2020-12 validation.

The Darwin action build uses one small CGO shim for `proc_pidinfo`, dynamic lookup of
`proc_signal_with_audittoken`, and Security.framework signature validation. It never
calls `proc_terminate_with_audittoken` because that API may choose `SIGKILL`. The
identity-bound signal symbol is resolved at runtime; if absent, `runnel doctor` marks
recovery unsupported and no fallback to `kill(pid, ...)` exists.

No dependency may add runtime network behavior, telemetry, a background service, or an
LLM. Pin exact versions in `go.mod`/`go.sum`, record licenses, and scan them in CI.

## Domain model

### Process identity

```go
type ProcessIdentity struct {
    PID        int32
    StartTime  time.Time
    UID        uint32
    Executable string
    PIDVersion uint32 // Darwin action identity; zero means unavailable
    UniqueID   uint64 // Darwin action identity; zero means unavailable
}
```

`Executable` is the resolved executable path when available. Unavailable path,
`PIDVersion`, or `UniqueID` makes a Darwin action-grade identity incomplete.
Display-only observations may retain the process as `unknown` with an availability
reason. `proc_pidpath_audittoken` binds origin inspection to PID plus `PIDVersion`.

### Darwin identity proof

The action primitive is grounded in Apple XNU commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`, not in a userspace timing assumption:

- `kern_exec.c` assigns a freshly incremented `p_idversion` on every successful `exec`
  and loops until it differs from the previous value;
- `proc_find_audit_token` resolves PID and rejects a token whose embedded pidversion no
  longer matches;
- `psignal_by_audit_token` converts that token to an exact process identity, reacquires
  the process with `proc_find_ident`, holds the process reference, checks MAC and caller
  permission, then signals the held reference;
- `proc_signal_with_audittoken` accepts an explicit signal, so Runnel can require
  `SIGTERM`; `proc_terminate_with_audittoken` is forbidden because it may select
  `SIGKILL`.

Primary source:
<https://github.com/apple-oss-distributions/xnu/tree/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea>.
Runnel still feature-detects the private libproc symbol and proves PID-reuse and exec
invalidation on each supported Darwin release. A missing or changed guarantee disables
live recovery.

### Workflow observation states

```text
protected
recently_active
quiet_unclassified
unknown
supported_stale_candidate
```

There is no generic `idle` or `stale` enum. Family recognition never implies action
support. A group may be recognized as Codex, Claude, MCP, Node/Vite/Next,
Playwright/Chromium, Docker/VM, browser, local database, or other, but only the exact
Codex detector can emit the candidate state.

### Availability and contradiction

Every probe returns data plus one of:

```text
available
not_applicable
permission_denied
unsupported_platform
unsupported_version
process_exited
timeout
malformed_output
schema_incompatible
contradictory
```

Errors remain data. Renderers explain them and classifiers fail closed.

## Fast read-only workflow radar

### Collection strategy

1. Paint the READY shell before work starts.
2. Enumerate processes once.
3. Read cheap identity, PPID, CPU time, RSS, TTY, executable, and cwd facts through a
   bounded worker pool. Never call `Children()` per process because its Darwin
   implementation repeatedly enumerates the complete process list.
4. Build the complete parent/child map in memory once.
5. Mark the current Runnel process, its full ancestor chain, current terminal owners,
   cmux, databases, sync/VPN/security processes, and user allowlist as protected.
6. Build one global listening/established-connection map with a bounded platform probe.
7. Group descendants under stable workflow roots and aggregate RSS/CPU/process count.
8. Take a short second cheap sample only for plausible AI/dev workflow groups to label
   positive recent activity. Absence of activity becomes `quiet_unclassified`, never
   stale.
9. Render the first complete snapshot. Deep probes are not part of the default scan.

The collector uses a process-count-bound worker pool, per-probe deadlines, one global
context, and deterministic sorting. It retains partial groups with explicit unavailable
fields instead of dropping them.

The SQLite driver and Codex metadata database are opened lazily only for
`explain`/deep evidence. The default radar never initializes SQLite, parses rollout
tails, or samples stacks; this protects the two-second and 50 MB budgets.

### Workflow-root rules

Root selection is evidence-based and deterministic:

1. current shell/editor/cmux-owned agent root;
2. known AI CLI/app-server root;
3. known dev server/browser harness root;
4. first descendant whose cwd or executable family separates from its parent;
5. otherwise `unclassified_user_process`; current-UID ownership alone is not enough to
   call anything a coding workflow.

Each group records the exact attribution evidence codes. A named coding workflow
requires either a recognized agent/dev executable plus compatible ancestry, or at least
two independent signals among executable family, cwd/worktree, TTY owner, and known
parent grammar. Ambiguous roots remain unclassified/`unknown` rather than merging or
marketing unrelated browser/background work as a coding workflow. Rootless cycles use
one deterministic lexical-minimum anchor so every process is counted exactly once.

### Performance budgets

- First visual shell: p95 below 300 ms.
- Complete fast snapshot: p95 below 2 s on the dogfood Mac with 1,500 processes.
- Peak scanner RSS: below 50 MB.
- No goroutine, child process, temp file, or alternate-screen state remains after exit.
- Output order is stable for identical inputs.

Benchmarks use synthetic 100, 500, 1,500, and 5,000-process trees. CI enforces
allocations and asymptotic behavior; Mac dogfood enforces wall time and RSS.

## Codex action adapter v1

Adapter ID: `codex-chatgpt-trusted-worker/v1`.

The first live adapter is intentionally narrow. It recognizes only a ChatGPT-bundled
Codex `trusted-worker.js` leaf under the signed ChatGPT app's embedded sandbox chain.
Initial supported origin:

- embedded Codex version: exact `0.148.0-alpha.15` until a second reviewed fixture
  proves a safe range;
- code-signing TeamIdentifier: `2DC432GLL2`;
- embedded Codex executable identifier: `codex`;
- embedded Codex SHA-256: `7645c3caf5607e4528eb3a15b12496c284c2a918939aed34e863c760c1b421e7`;
- Node executable under `ChatGPT.app/Contents/Resources/cua_node/bin/node`;
- Node identifier/team: `node` / `2DC432GLL2`;
- Node SHA-256: `e3860ffeda3aaf7203123bd661cae18b478924215048fcfea560fc63950cc95a`;
- `trusted-worker.js` SHA-256:
  `9f936ad8addf558d3de3f415917680ae703bf51b4d63f62d718413a3acb4edb7`;
- leaf argv grammar: `node --experimental-vm-modules <bounded-temp>/trusted-worker.js <cwd>`;
- parent grammar: signed embedded `codex sandbox ... -- <same-node> ... <same-worker> <same-cwd>`;
- leaf, sandbox parent, rollout relationship, and current UID must agree.

`OriginVerifier` first resolves each running executable with
`proc_pidpath_audittoken`. It then performs Security.framework static-code validity
against a pinned designated requirement and checks the exact file digest. Negative
fixtures cover unsigned, altered, ad-hoc/re-signed, wrong-team, wrong-identifier,
wrong-digest, and mismatched-parent chains. Textual paths or `codesign -d` output alone
never establish origin.

The standalone Codex CLI remains visible in the radar but is not action-supported by
this adapter. A version or origin mismatch returns `unsupported_version` or `unknown`.

### Privacy-safe fixture manifest

`fixtures/codex/v1/manifest.json` pins:

- adapter ID and exact version/origin grammar;
- normalized process trees and identities;
- SQLite schema/version expectations;
- bounded terminal rollout-event grammar;
- descriptor relationship codes;
- stack predicate codes, never raw private stack output;
- active, paused/ambiguous, supported stale, PID reuse, truncated tail, unknown event,
  changed stack, permission denied, socket, TTY, and contradictory cases;
- SHA-256 for every fixture plus a corpus root hash.

Fixtures use synthetic users, paths, IDs, commands, session content, and timestamps.
No real conversation body, username, repository, local path, socket, or session ID is
committed.

### Codex metadata adapter

Open `~/.codex/state_5.sqlite` in read-only/query-only mode. Validate required tables,
columns, and values before any query. Read `threads` and `thread_spawn_edges` in one
stable snapshot:

```text
read PRAGMA data_version
  -> query normalized threads and edges
  -> read PRAGMA data_version again
  -> accept only when versions match; bounded retry otherwise
```

The adapter returns only metadata needed for correlation. It never copies prompts,
responses, tool payloads, or conversation bodies into snapshots or receipts.

The rollout parser reads a bounded tail and accepts only the exact terminal completion
event grammar pinned by the fixture. Truncated, malformed, unknown, or contradictory
tails are unselectable.

The exact rollout path observed through the target descriptor must match the canonical
`threads.rollout_path` row and file `(device,inode)` identity. Immediately before the
identity-bound signal, Runnel repeats the stable SQLite snapshot, exact row/tail/file
correlation, origin/version check, and descriptor relationship. Any changed
`data_version`, row value, schema, terminal event, file identity, or correlation refuses
the transaction with zero signals.

### Deep evidence window

Samples occur at `t=0s`, `t=2s`, `t=4s`, and `t=6s`. The window records:

- exact identity and parent/child set;
- CPU time and RSS;
- TTY and protected ownership;
- descriptor relationship, access mode, associated file size and mtime;
- listening and established connection counts;
- compatible Codex metadata state;
- bounded rollout-tail terminal event;
- one bounded `sample` stack only after cheaper gates pass.

Every required positive must pass:

1. exact supported origin/version/executable/argv/parent grammar;
2. compatible completed Codex metadata and completed bounded rollout tail;
3. associated file size and mtime unchanged in all four samples;
4. CPU time increases while the final bounded stack matches the supported read/decoder
   predicate over that same completed file;
5. no TTY, listener, established connection, or writable output activity;
6. no protected identity in the exact target descendants.

Any unavailable signal, identity change, contradiction, or disqualifier makes the
result unselectable.

## Protection policy

Protection is computed before classification and has absolute precedence.

Protected identities include:

- Runnel itself and its ancestors;
- the invoking TTY session, login shell, editor, terminal, and cmux ownership chain;
- any process with a controlling TTY during the deep window;
- databases and explicitly configured workflow roots;
- recognized sync, VPN, security, backup, and credential processes;
- any identity in the user protection file;
- any group whose ownership evidence is incomplete or contradictory.

The selectable target set is built by subtracting protected identities before an
action plan can exist. The UI cannot override this subtraction.

## Recovery transaction

```text
EXPLAINED
   │ exact detector passes
   v
SELECTED ──> show identities + descendants + protected exclusions
   │ displayed finding token entered exactly
   v
CONFIRM
   │
   ├─ re-resolve every target identity
   ├─ re-resolve every protected check identity
   ├─ repeat stable SQLite/rollout/descriptor/origin checks
   ├─ recheck no TTY/socket/new child/changed file/version
   └─ any mismatch => REFUSED, signals_sent=0
   │
   v
identity-bound SIGTERM to one approved childless leaf
   │
   v
VERIFYING ──> bounded poll of target absence and protected presence
   │
   ├─ all targets absent + all protected present => VERIFIED
   ├─ signal sent but target/protected verification incomplete => PARTIAL
   ├─ no signal due gate mismatch => REFUSED
   └─ syscall/store/internal failure => FAILED
```

Confirmation requires the displayed short finding token, not `y`.

v0.1 supports one exact childless `trusted-worker` leaf per transaction. A target child
at any deep sample or action-time recheck makes the finding unselectable; the sandbox
parent is observed/protected but not signaled. This avoids pretending a sequential
multi-process operation is all-or-none.

Before confirmation, the receipt store exclusively creates a transaction directory and
writes/fsyncs an immutable, schema-valid `prepared.json` containing the planned
target/protected identities and evidence. The signal path is disabled unless this
durable intent exists. Cancellation or an action outcome is finalized exactly once as a
separate, exclusively created `result.json` with `verified`, `partial`, `refused`, or
`failed`. No receipt file is ever overwritten. If final creation fails,
`prepared.json` remains recoverable and the CLI prints a bounded emergency outcome
without claiming success. `runnel receipt <id>` resolves `result.json` when present and
otherwise reports the durable prepared state.

The signaling implementation receives a complete Darwin action identity and performs
all action-time evidence checks before constructing an audit token containing PID and
`PIDVersion`. It calls the dynamically resolved `proc_signal_with_audittoken(...,
SIGTERM)`. XNU validates the embedded pidversion, reacquires the exact process by kernel
identity, applies MAC/credential checks, and signals the held process reference. There
is no raw-PID fallback and CLI arguments never accept arbitrary PIDs.

All external read-only probes use one injected launcher: direct argv (never a shell),
an isolated process group, per-command deadline, byte/line output ceiling, and complete
`Wait`. Cancellation sends TERM to the probe-only group, waits briefly, then may use
KILL only for Runnel-spawned probe processes. Tests prove the caller group and user
workflows are never targeted and escaped descendants are detected.

## Receipts and privacy

### Local receipt

The private local receipt contains:

- schema/tool versions and detector ID;
- baseline and evidence availability codes;
- exact selected and protected identities;
- confirmation and immediate revalidation result;
- signal attempts and bounded verification outcome;
- selected-process RSS observed before exit;
- coarse system metrics before and after;
- explicit uncertainty and normalized errors.

Store under the platform user-data directory in an owned `0700` root with one
exclusively created `0700` directory per receipt ID, `0600` files, and a restrictive
umask. Every path component is checked with `lstat`; symlinked or wrong-owner
directories and files refuse storage. Create `prepared.json` and `result.json` through
same-directory `O_EXCL|O_NOFOLLOW` temp files, validate, `fsync`, atomically rename only
into an absent destination, verify final inode/mode/owner, and sync the transaction and
root directories. Neither file is replaced. Symlink, collision, and replacement races
fail closed.

### Share receipt

The share encoder accepts typed aggregate inputs, not the private receipt JSON. Its
closed allowlist contains only:

- tool/schema version and coarse OS/architecture;
- detector ID and support state;
- enumerated evidence/availability codes;
- aggregate counts and bucketed durations;
- selected-process RSS total before exit;
- exact-target exit count;
- protected signaled count and protected present count;
- coarse memory-pressure before/after;
- outcome and normalized refusal/error codes.

Forbidden fields never enter the share Go type: PID, precise time, path, argv, cwd,
repository, user/host, environment, port, session/thread ID, descriptor path, raw stack,
raw error, or free-form labels. Embedded Draft 2020-12 schemas reject unknown fields.

## CLI and TUI

```text
runnel                     fast read-only radar, optional review prompt
runnel scan                read-only snapshot
runnel scan --json         versioned machine-readable snapshot
runnel explain <finding>   evidence and contradictions
runnel recover             interactive supported-candidate flow
runnel history             local receipt index
runnel receipt <id>        private local receipt
runnel receipt <id> --share  separately encoded share receipt
runnel doctor              dependencies, permissions, adapter and probe health
runnel completion <shell>  shell completion
runnel version             build and provenance information
```

`recover` rejects non-TTY stdin/stdout. JSON mode never enters the alternate screen and
never emits ANSI. The Bubble Tea program receives a context, handles resize
messages, restores the terminal on quit/error/cancel, and owns no process capability.

### Interaction state machine

```text
READY -> SNAPSHOT -> EXPLAINED -> SELECTED -> CONFIRM -> VERIFYING
  │         │            │            │          │           │
  └ error   └ no action  └ back       └ back     └ cancel    ├ VERIFIED
                                                           ├ PARTIAL
                                                           ├ REFUSED
                                                           └ FAILED
```

The footer always names current keys and the next safe action. Protected rows remain
visible. Color is semantic decoration only; state always has text and symbols.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Successful read-only output or verified action |
| 2 | CLI usage error |
| 3 | Partial/unavailable scan with valid output |
| 4 | No supported candidate or recovery refused before signal |
| 5 | Recovery partial after signal |
| 6 | Recovery failed |
| 7 | Schema/privacy integrity failure |
| 130 | User cancellation / interrupt |

## Failure modes

| Codepath | Realistic failure | Handling | Test | User-visible |
| --- | --- | --- | --- | --- |
| Process enumeration | Process exits between list and detail probe | Keep row as `process_exited`; never candidate | Unit + synthetic integration | Yes |
| Identity | PID reused before signal | Kernel audit-token/pidversion lookup returns `ESRCH`; no raw-PID fallback | Critical live-child integration | Yes |
| Grouping | Parent disappears or cycle/malformed PPID appears | Break cycle deterministically; unknown group | Unit/fuzz | Yes |
| Protection | Current terminal ancestor omitted | Cross-check own ancestry and TTY owner; structural exclusion | Integration | Yes |
| Socket probe | `lsof` denied/times out | `permission_denied`/`timeout`; unselectable | Unit + command fixture | Yes |
| SQLite | Database changes after confirmation | Repeat stable row/tail/file correlation at action boundary; refuse | WAL-writer integration | Yes |
| Schema | Codex table/column/value changes | `schema_incompatible`; detector disabled | Fixture contract | Yes |
| Tail parse | Last JSON record truncated/unknown | Unknown terminal state; unselectable | Fuzz + fixtures | Yes |
| Stack sample | `sample` missing, denied, changes, or times out | Unavailable/contradictory; unselectable | Command fixture | Yes |
| Confirmation | User enters stale token after rescan | Token mismatch; refuse | TUI integration | Yes |
| Revalidation | One descendant changes identity | Refuse entire group; zero signals | Critical integration | Yes |
| Signal | Target exits before signal | Record already absent; re-evaluate group and refuse action | Integration | Yes |
| Signal | Identity-bound SIGTERM returns error | Childless singleton means no earlier target; preserve prepared receipt, verify | Integration | Yes |
| Verification | Protected process disappears independently | Partial; never claim active work unaffected | Integration | Yes |
| Receipt store | Disk full, permission denied, rename/fsync error | No signal before durable prepared receipt; retain last durable state | Crash/fault integration | Yes |
| Receipt path | Symlink, wrong owner/mode, ID/finalization race | Exclusive transaction dir, immutable prepared/result files, no-follow/collision refusal | Filesystem fault integration | Yes |
| Share export | New/private field accidentally added | Separate type + closed schema + forbidden-key property test refuses | Unit/property | Yes |
| TUI | Panic/cancel/resize during scan | Program context cleanup and terminal restoration test | PTY integration | Yes |
| Child command | Probe ignores cancel, forks, or escapes | Isolated group, bounded TERM/KILL for probes only, wait and absence check | Integration | Yes |
| Origin | Running chain is altered/re-signed/look-alike | Identity-bound path + static-code validity + designated requirement + digest | Darwin integration | Yes |
| Attribution | Browser/background process shares current UID | Unclassified unless evidence threshold passes | Mixed-tree fixture | Yes |

No planned failure is silent and action-grade missing evidence always fails closed.

## Test coverage plan

```text
CODE PATHS                                             USER FLOWS
[+] model identities/enums                             [+] default read-only scan
  ├─ equality + missing executable                       ├─ empty/no-agent Mac
  ├─ PID reuse                                           ├─ many grouped workflows
  └─ strict JSON round trip                              └─ partial permissions
[+] Darwin source                                      [+] explain
  ├─ process exits mid-probe                             ├─ supported evidence
  ├─ command timeout/malformed/denied                    └─ unsupported/contradictory
  └─ cancellation leaves no child                      [+] recover [E2E]
[+] workflow grouping/protection                        ├─ active is unselectable
  ├─ cycles/orphans                                      ├─ paused is unselectable
  ├─ deterministic root/order                            ├─ stale fixture requires token
  └─ protected ancestry subtraction                      ├─ PID reuse refuses, zero signals
[+] Codex adapter                                       ├─ partial signal receipt
  ├─ stable query-only SQLite snapshot                   └─ verified target/protected counts
  ├─ exact origin/version/argv                         [+] receipt/history/share
  ├─ bounded completion-tail parser                      ├─ durable prepared receipt
  ├─ four-sample evidence                                ├─ schema-valid share
  └─ every disqualifier                                  └─ forbidden private fields refuse
[+] recovery transaction                              [+] terminal behavior [E2E]
  ├─ opaque plan construction                            ├─ resize/cancel/error restore
  ├─ full action-time revalidation                       ├─ non-TTY recovery refuses
  ├─ audit-token SIGTERM + bad pidversion                └─ JSON has no ANSI
  └─ verified/partial/refused/failed

Goal: 100% statement coverage plus explicit branch/property/fuzz coverage for all
classifier, protection, schema, privacy, and action branches. No live user process is
ever signaled in tests or CI.
```

### Test layers

1. Pure unit tests for identities, grouping, classification, evidence, state machine,
   share encoder, exit codes, and rendering.
2. Golden fixture tests for Darwin command parsers, SQLite snapshots, Codex tails,
   stacks, and every detector state.
3. Property/fuzz tests for process trees, PID reuse, JSON/tail parsing, forbidden share
   keys, and malformed command output.
4. Integration tests with a dedicated synthetic worker binary and injected signaler.
5. macOS PTY tests for alternate-screen restoration, resize, cancellation, and exact
   confirmation token.
6. Race tests for scan cancellation, concurrent probe completion, and receipt writes.
7. Performance benchmarks for 100-5,000 synthetic processes and real dogfood scans.
8. Release install tests on clean Darwin arm64 and amd64 runners.

Darwin integration adds: a live owned child with a deliberately wrong pidversion must
survive and return `ESRCH`; the exact audit token then delivers only `SIGTERM` to that
child. The child then `exec`s a distinct owned helper: the pre-exec token must return
`ESRCH` and the replacement must survive; its new exact token may terminate only that
replacement with SIGTERM. Further tests cover a WAL write between detector and action, prepared-receipt
crash recovery, a child appearing before revalidation, signature/digest mutations,
probe-group escape/caller preservation, mixed unclassified browser trees, and distinct
share-snapshot versus share-receipt forbidden-field properties. Receipt fault tests
cover symlinked parent/temp/final paths, wrong owner/mode, ID collisions, exclusive
create, no-follow behavior, duplicate `result.json`, and rename/fsync failures.

Coverage, race, vet, format, schema, fixture hash, privacy, license, vulnerability, and
release-reproducibility checks gate the release workflow.

## Dogfood acceptance

The action engine first runs only against the synthetic adapter and fake child harness:

1. operator-labeled active case: visible and structurally unselectable;
2. operator-labeled intentionally paused case: visible and structurally unselectable;
3. deliberately stale completed read-loop case: selectable, exact token required,
   target exit verified, protected identities signaled zero and present N/N.

After all harness tests pass, run the live adapter in read-only mode against current
Codex/ChatGPT workers. A real supported candidate may be signaled only after a separate
action-time approval showing the exact target identities and evidence. Absence of a
real candidate is a valid result and does not justify weakening the contract.

Public claims distinguish historical incident evidence, synthetic harness proof,
read-only live scans, and any separately approved real recovery.

## Distribution

### Build matrix

- `darwin/arm64`
- `darwin/amd64`

Use GoReleaser with reproducible flags, SBOM, checksums, provenance attestation, and
GitHub Actions. Because the action shim uses CGO, each Darwin architecture is built and
tested on a native macOS runner; cross-CGO is not trusted. Release archives contain the
binary, README, LICENSE, SECURITY, privacy model, schemas, and shell completions. CI
installs each archive and runs `runnel doctor --self-test` plus a real read-only
`runnel scan --json` smoke test.

### Install paths

```text
brew install ArshyaAI/tap/runnel
```

GitHub Releases is the source of truth. The project is Apache-2.0 licensed for explicit
patent terms and dependency compatibility. The initial support floor is macOS 14 on
Darwin arm64/amd64; `runnel doctor` feature-detects every private libproc symbol instead
of assuming it. Do not publish to npm because `runnel` is an occupied legacy npm name.
Homebrew tap metadata is generated only from a final tagged release checksum. The local
build must never mutate the user's Homebrew installation.

### Release gates

1. Clean full test/race/vet/format/schema/privacy/fixture suite.
2. Measured fast-scan p95 and peak RSS budgets on the dogfood Mac.
3. Three synthetic dogfood cases reconcile exactly.
4. Read-only live scan produces no secrets and no unsupported action.
5. Independent security/privacy/diff review has zero open P0/P1 findings.
6. Darwin artifacts install and self-diagnose in clean environments.
7. Name, GitHub slug, Homebrew, dependencies, competitor counts, and launch claims are
   refreshed from primary sources on launch day.
8. Exact GitHub creation/push/release and X post require action-time approval.

## Observability without telemetry

`runnel doctor --json` and the read-only `runnel doctor --self-test` report only local
probe availability and versions. The self-test uses in-memory synthetic inputs and
cannot construct a live signaler. No production `--fixture` mode is shipped. Debug logs
are opt-in, local, bounded, and redact paths/argv/session identifiers by default. No
analytics or crash data leaves the Mac. Bug reports use a separately encoded support
bundle with the same allowlist discipline as share receipts.

## Worktree and agent execution

| Lane | Modules | Depends on |
| --- | --- | --- |
| A: domain + schemas + fixtures | `internal/model`, `schema`, `fixtures` | Engineering review |
| B: Darwin read-only probes | `internal/platform/darwin` | Domain interfaces |
| C: Codex metadata/detector | `internal/codex` | Domain + fixtures |
| D: recovery + receipts | `internal/recovery`, `internal/receipt` | Domain + detector contract |
| E: CLI/TUI | `internal/cli`, `internal/ui`, `cmd` | Domain interfaces |
| F: release/docs/demo | `.github`, `docs`, release config, assets | Stable command/schema |

Launch A first. Once interfaces and fixture hashes are frozen, B and C can run in
parallel. D begins after C exposes the detector result. E can build against fixtures in
parallel with B/C. F begins after the command and schema stabilize. A single integration
owner merges shared schemas and command wiring. No two agents write the same package.

## Implementation tasks

- [ ] **T1 (P1)** — Freeze versioned domain, snapshot, evidence, private receipt, and
  share receipt schemas; add closed-schema tests.
- [ ] **T2 (P1)** — Build and hash the privacy-safe Codex adapter fixture corpus with
  all positive, unavailable, contradictory, active, paused, and PID-reuse cases.
- [ ] **T3 (P1)** — Implement bounded Darwin process/host/socket/descriptor/stack
  sources with cancellation and explicit availability.
- [ ] **T4 (P1)** — Implement deterministic workflow grouping, family attribution,
  activity observation, and structural protection.
- [ ] **T5 (P1)** — Port the stable query-only Codex metadata snapshot and bounded
  completion-tail parser; implement exact v1 detector.
- [ ] **T6 (P1)** — Implement opaque recovery plans, exact-token confirmation,
  identity revalidation, SIGTERM-only transaction, and outcome verification.
- [ ] **T7 (P1)** — Implement immutable prepared/result receipt storage and separately
  encoded, schema-validated share receipts.
- [ ] **T8 (P1)** — Implement Cobra commands, Bubble Tea workflow, text/JSON,
  history, doctor, version, completion, and deterministic exit codes.
- [ ] **T9 (P1)** — Complete unit, fixture, fuzz, property, integration, PTY, race,
  privacy, performance, and dogfood gates.
- [ ] **T10 (P2)** — Add CI, GoReleaser, SBOM, provenance, checksums, Homebrew tap
  template, install tests, contribution/security/privacy docs, and issue templates.
- [ ] **T11 (P2)** — Produce truthful demo, share-safe receipts, README hero, release
  notes, X launch packet, reply bank, and launch-day verification checklist.

## NOT in scope

- Storage/cache cleanup, worktree deletion, session deletion, or archival: Mole already
  owns broad cleanup and these are higher-blast-radius actions.
- Automatic/scheduled killing or a daemon: violates the on-demand trust contract.
- `SIGKILL`: v0.1 has no escalation path after `SIGTERM`.
- Claude, MCP, Node/Vite/Next, browser, Docker, VM, or database action detectors:
  displayed read-only now, added one reviewed contract at a time later.
- Menu-bar/native app: validate recurring CLI use first.
- Linux/Windows production support: interfaces are portable but release proof is
  Darwin-only.
- Fleet/cloud dashboard, account, telemetry, API key, or runtime network calls: local
  single-user product first.
- Token/billing/session-content analytics: separate problem and privacy boundary.
- LLM-generated safety or classification decisions: deterministic evidence only.
- Fan control, memory purge, network repair, login item, launch service, or reboot.

## Deferred roadmap, not v0.1 TODOs

- Claude action adapter after versioned public fixtures exist.
- MCP stdio lifecycle adapter.
- Node/dev-server and Playwright/browser-harness adapters.
- Foreground watch/NDJSON mode beyond bounded scan progress.
- Contributor detector SDK after the first external detector contribution.
- Native menu-bar layer only if recurring usage proves demand.

These are documented product bets, not implementation obligations for this release.

## Engineering review completion

- Step 0 Scope Challenge: full bounded v0.1 accepted; generic actions remain excluded.
- Architecture Review: 7 material issues found and resolved.
- Code Quality Review: no pre-code organization issue remains.
- Test Review: coverage diagram produced; 9 safety/privacy gaps added to the plan.
- Performance Review: one issue resolved by keeping SQLite and deep probes lazy.
- NOT in scope: written.
- What already exists: written with license/provenance boundaries.
- TODOs: zero v0.1 TODOs; post-v0.1 bets are explicitly non-obligatory.
- Failure modes: zero unhandled silent critical gaps.
- Outside voice: independent Terra reviewer ran three adversarial passes; final PASS.
- Parallelization: six lanes; domain first, then three independent implementation lanes.
- Prior learning applied: rootless process cycles require a deterministic anchor so every
  process is visible and counted exactly once.
- Lake score: 9/9 safety and completeness decisions chose the complete option.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/office-hours` | Scope & strategy | 1 | CLEAR | Dual-Layer daily radar plus one narrow action contract approved |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | SKIPPED | Already running under Codex; no nested pass |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR | 17 findings/gaps resolved, 0 critical gaps open |
| Design Review | `/plan-design-review` | UI/UX gaps | 1 | CLEAR | Final product/design consistency score 9/10 |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | PLANNED | Run against the implemented binary before release |

**CROSS-MODEL:** Sol plan and independent Terra review converged after three passes; PID reuse, exec identity, origin, metadata freshness, probe cleanup, receipts, attribution, and scope gaps are closed.

**VERDICT:** CEO + DESIGN + ENG CLEARED — implementation ready. Live recovery remains gated by native identity tests, synthetic dogfood, read-only live validation, and exact action-time approval.

NO UNRESOLVED DECISIONS
