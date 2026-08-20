# Security policy

Runnel observes local process and session metadata and contains one narrowly gated
process-signal path. Treat a false positive, identity mismatch, privacy leak, or path
traversal as a security issue.

## Supported versions

The latest published minor release and current `main` branch receive security fixes.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/ArshyaAI/runnel/security/advisories/new).
If that form is unavailable, do not disclose vulnerability details publicly. Open a
content-free issue asking only for the private reporting channel to be restored.

Do not attach raw Runnel receipts, Codex rollouts, session databases, process command
lines, stack samples, environment variables, repository paths, or credentials to a
public issue. Start with the Runnel version, coarse macOS version/architecture, detector
ID, outcome/error code, and a share-safe receipt only.

## Security boundaries

- The default command and `scan` are read-only.
- `recover` is the only user-process mutation surface.
- Unsupported, unavailable, contradictory, protected, active, or quiet evidence is
  unselectable.
- There is no raw-PID CLI, generic kill rule, `SIGKILL` fallback, daemon, telemetry,
  runtime network request, or LLM safety decision.
- Darwin signaling uses the kernel audit-token PID-version path when available. It has
  no fallback to `kill(pid, ...)`.
- A durable prepared receipt and full action-time evidence recheck precede every signal.
- Share exports use separate closed allowlist schemas; they are not redacted private
  receipts.

See [the threat model](docs/THREAT_MODEL.md) and
[Darwin identity proof](docs/XNU_IDENTITY_PROOF.md).

## Response target

We aim to acknowledge a complete private report within 72 hours, reproduce or classify
it within seven days, and publish a fix and advisory before discussing exploit details
publicly. This is a target, not a paid support SLA.
