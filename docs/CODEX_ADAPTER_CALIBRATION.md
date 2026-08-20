# Codex adapter v1 calibration

Calibration date: 2026-08-20

Target: installed ChatGPT-bundled Codex worker on macOS

Adapter: `codex-chatgpt-trusted-worker/v1`

## Verdict

The v1 adapter is current for the installed ChatGPT bundle. It intentionally supports
the embedded `0.148.0-alpha.15` build, not every binary carrying a newer Codex version.
The separately installed standalone Codex `0.148.0` remains visible in the radar but is
not action-supported by this adapter.

## Exact origin evidence

| Artifact | Identifier | TeamIdentifier | SHA-256 |
| --- | --- | --- | --- |
| embedded Codex | `codex` | `2DC432GLL2` | `7645c3caf5607e4528eb3a15b12496c284c2a918939aed34e863c760c1b421e7` |
| embedded Node | `node` | `2DC432GLL2` | `e3860ffeda3aaf7203123bd661cae18b478924215048fcfea560fc63950cc95a` |
| `trusted-worker.js` | n/a | current user owner | `9f936ad8addf558d3de3f415917680ae703bf51b4d63f62d718413a3acb4edb7` |

Strict code-signature validation passed for both executables. Each digest was repeated;
all discovered worker copies matched the worker digest.

Observed normalized process grammar matched the contract:

```text
leaf:   node --experimental-vm-modules <bounded-temp>/trusted-worker.js <absolute-cwd>
parent: codex sandbox <reviewed-options> -- <exact-leaf-argv>
```

Concrete temporary paths, cwd values, process IDs, thread IDs, and session identifiers
were not retained in this document.

## Metadata calibration

The required SQLite tables and column affinities were present and were inspected in
read-only/query-only mode. At calibration time, matching alpha15 thread rows were
either missing a spawn edge or carried an `open` edge. No matching `closed` edge was
present.

That makes the running workers correctly unselectable. It does **not** justify changing
`open` into `closed`, treating a missing edge as completion, or widening the adapter.
The exact completion contract remains:

```text
cli_version = 0.148.0-alpha.15
thread_source = subagent
spawn edge status = closed
bounded terminal envelope = event_msg / task_complete
```

No live rollout body was read for this calibration. Terminal envelope names are pinned
from the reviewed upstream protocol and the synthetic fixture corpus.

## Upstream anchors

- [`rust-v0.148.0-alpha.15`](https://github.com/openai/codex/tree/ffe1de5cec9c0cd02629eb246534e4622da0ff41)
- [`rust-v0.148.0`](https://github.com/openai/codex/tree/3ba0f711642a888aec92a611a3f3b2211157ff89)
- [tagged protocol definitions](https://github.com/openai/codex/blob/rust-v0.148.0/codex-rs/protocol/src/protocol.rs)
- [tagged thread-edge implementation](https://github.com/openai/codex/blob/rust-v0.148.0/codex-rs/state/src/runtime/threads.rs)

## Upgrade rule

When the ChatGPT bundle changes version, signature, digest, grammar, schema, or event
contract, v1 fails closed. Support requires a new exact adapter/fixture revision with
fresh origin evidence and native read-only calibration. A version range is never widened
from marketing equivalence or semver alone.
