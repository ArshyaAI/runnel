# Runnel

Runnel is a macOS-first Go CLI that maps AI-development workflows and offers
recovery only when a versioned evidence contract proves an exact target safe.

## Stack

- Go 1.24+ (`go.mod`)
- Runtime and UI dependencies are declared only in `go.mod`; never infer them

## Commands

- Build: `go build ./...`
- Test: `go test ./...`
- Race: `go test -race ./...`
- Vet: `go vet ./...`
- Format check: `test -z "$(gofmt -l .)"`

## Architecture

- `cmd/` contains binaries; `internal/` contains product code.
- Read-only scan data and mutation-capable recovery plans are separate types.
- Darwin probes are adapters; classifiers and receipt encoders are pure Go.

## Rules

- The default command and `scan` never signal, delete, upload, or change system state.
- PID alone is never identity; use PID, start time, UID, and executable together.
- Unknown or contradictory evidence is unselectable and fails closed.
- Only `recover` may signal, only with `SIGTERM`, after immediate identity revalidation.
- Share exports are separately encoded allowlists, never redacted private receipts.
- Never copy Mole implementation or visual assets; product-pattern research only.
- Never add runtime network calls, telemetry, a daemon, or an LLM safety decision.

## Skill routing

- Architecture: `/plan-eng-review`
- Developer experience: `/devex-review`
- Diff/release gate: `/review`, then `/ship`
- Browser/demo QA: `/qa-only`

## Do Not Touch

- Synthetic fixture hashes without regenerating the manifest and tests
- Approved schemas without a version bump and migration note
- User sessions, worktrees, caches, or live processes outside an explicit recovery transaction
