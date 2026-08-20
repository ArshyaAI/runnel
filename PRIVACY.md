# Privacy

Runnel is local-only by design.

## What Runnel reads

Depending on the command and available permissions, Runnel may read:

- process identity, parentage, CPU time, RSS, TTY, executable, and cwd metadata;
- bounded socket and descriptor metadata;
- coarse host memory/load/thermal observations;
- the required schema and metadata rows from the local Codex state database;
- a bounded tail of one correlated Codex rollout to recognize a terminal event;
- one bounded stack sample only after every cheaper deep-evidence gate passes.

The default scan does not open the Codex database, parse rollouts, or sample stacks.

## What never leaves the Mac

Runnel has no account, API key, telemetry, analytics, crash upload, cloud service,
background daemon, or runtime network call. Private snapshots and receipts stay in the
local user-data directory with restrictive permissions.

## Share-safe objects

`runnel receipt <id> --share` and share snapshots are separately encoded closed schemas.
Their Go types cannot represent raw paths, argv, cwd, repositories, usernames,
hostnames, environment variables, ports, PIDs, session/thread IDs, exact timestamps,
descriptor paths, stack text, raw errors, prompts, responses, or tool payloads. Unknown
fields refuse export.

A share-safe object may contain only versioned enums, coarse OS/architecture, detector
support state, aggregate counts, bucketed durations, selected-process RSS totals,
exact-target/protected counts, coarse memory-pressure states, and normalized outcomes.

## Codex content boundary

The Codex adapter queries metadata needed for correlation. It never copies prompt,
response, last-agent-message, preview, or tool content into a Runnel snapshot or
receipt. The bounded rollout parser selects envelope fields required to recognize the
terminal completion event and discards free text.

## Deletion

Runnel never deletes Codex sessions, rollouts, worktrees, caches, repositories, or
receipts automatically. Users may remove Runnel's own local data manually after exiting
the program; no cleanup command is part of v0.1.
