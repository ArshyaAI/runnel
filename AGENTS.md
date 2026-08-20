# Agents

## explorer

- Model: configured Luna Fast explorer
- Tools: read-only filesystem, shell, Context7, web
- Use: code mapping, primary-source research, fixture evidence, release availability checks

## worker

- Model: configured Luna Fast worker
- Tools: scoped editing and verification
- Use: bounded implementation in a disjoint package after the plan and interfaces are fixed

## default

- Model: configured Sol frontier lane
- Tools: full in-scope implementation and verification
- Use: cross-package safety architecture, recovery transaction, schema and release integration

## reviewer

- Model: configured Terra reviewer
- Tools: read-only code, tests, adversarial probes
- Use: process-safety, privacy, regression, and release-gate review

## fast_worker

- Model: configured Spark writer
- Tools: exact-path deterministic writes and exact verification
- Use: mechanical docs, fixtures, or release metadata with no architecture decisions

## Project invariants

- One writer per overlapping package or shared fixture corpus.
- A detector may produce an actionable plan only through the recovery package's gated constructor.
- Tests must prove protected identities cannot enter the action set.
- No agent may signal a real user process during development or CI.
