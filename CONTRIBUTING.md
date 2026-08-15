# Contributing

## Workflow

1. Start from an issue, requirement ID, threat ID, or ADR that explains the intended behavior.
2. Use a focused branch and keep unrelated changes separate.
3. Update design documents before or with security-significant code changes.
4. Add tests for successful behavior, denial behavior, malformed inputs, and relevant cleanup/rollback paths.
5. Run formatting, unit, race, static-analysis, and applicable integration checks before review.
6. Request review with a concise security-impact and verification summary.

## Go conventions

- Use `gofmt`; keep packages small and responsibility-focused.
- Prefer the Go standard library and minimize dependencies.
- Pass `context.Context` through I/O and long-running work; enforce deadlines and cancellation.
- Wrap errors with safe context, but do not include secrets, plaintext, raw tokens, keys, or internal storage paths in client-visible messages.
- Use cryptographically secure randomness only from `crypto/rand` for keys, nonces, and security identifiers.
- Centralize authorization, lifecycle transitions, envelope parsing, and audit canonicalization rather than duplicating security logic.
- Avoid invoking a shell with user-controlled input. External tools use fixed executables, bounded arguments, timeouts, isolated working paths, and parsed outputs.

## Security review checklist

- Which assets, trust boundaries, threats, and requirements change?
- Can untrusted input influence paths, commands, parsers, allocation, or lifecycle state?
- Is authorization checked against authoritative object state for every operation?
- Are failure modes fail-closed, idempotent, audited, and safely cleaned up?
- Are key/nonce generation, AAD, and envelope versions correct?
- Can logs, errors, metrics, or tests expose plaintext or secrets?
- Does recovery preserve the current known-good version until verification completes?
- Are documentation and ADRs consistent with implemented behavior?

## Pull request evidence

Describe the change, linked requirement/threat/ADR IDs, tests run, attack/failure cases covered, known limitations, and any migration or compatibility impact. Never attach live malware or sensitive test data.

## Scope guardrails

Dynamic or behavioral analysis of uploaded files is not currently accepted. Proposals to add sample execution, sandbox detonation, machine-learning detection, or a new cryptographic construction require prior threat-model review and an accepted ADR.
