# Contributing to Runnel

Runnel welcomes small, evidence-backed contributions. A detector is a safety contract,
not a heuristic plugin.

## Setup

```bash
git clone https://github.com/ArshyaAI/runnel.git
cd runnel
go test ./...
go test -race ./...
go vet ./...
```

Runnel currently targets Go 1.25+ and native macOS 14+ runners. The public repository
and URL in this document become valid only after launch.

## Before changing an action detector

Open an issue that includes:

- tool and exact version/origin being supported;
- observable incident and expected versus observed behavior;
- every positive gate, disqualifier, unavailable state, and contradiction;
- privacy-safe synthetic fixtures;
- how PID reuse, exec, protected ancestry, sockets, TTY, file activity, cancellation,
  and action-time revalidation are tested;
- why a read-only explanation is insufficient.

Do not submit raw rollouts, prompts, responses, stack samples, command lines, local paths,
session IDs, credentials, or client repositories. Reconstruct the smallest synthetic
fixture and include its manifest hashes.

## Rules

- Default and scan paths remain read-only.
- Unknown never becomes stale.
- Family recognition never becomes action support automatically.
- No raw PID, generic score, LLM decision, `SIGKILL`, daemon, telemetry, or runtime
  network request.
- New action support requires an exact versioned adapter, full fixture corpus,
  action-time evidence, native identity tests, and independent security review.
- Share schemas are closed allowlists, not redaction rules.
- Never copy Mole implementation or assets; Runnel is an original Apache-2.0 work.

## Verification

Every pull request must pass format, unit, fixture, fuzz/property, race, vet, schema,
fixture-hash, privacy, vulnerability, and license gates. Darwin identity or signal code
also requires the owned-child PID-reuse and post-exec audit-token tests.

Keep commits focused and include the exact commands and outcomes in the pull request.
