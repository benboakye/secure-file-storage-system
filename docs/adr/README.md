# Architecture Decision Records

Architecture Decision Records (ADRs) capture security-significant decisions so implementation and testing remain aligned with the design.

- [ADR 0001: Separate privileged identities and session audiences](0001-separated-privileged-identities.md)
- [ADR 0002: Provider-neutral managed key broker](0002-managed-key-broker-boundary.md)
- [ADR 0003: Independent server-attested audit checkpoint anchor](0003-independent-audit-checkpoint-anchor.md)
- [ADR 0004: Fail-closed production transport profile](0004-fail-closed-production-transport-profile.md)

## Format

Create files named `NNNN-short-title.md`:

```markdown
# ADR NNNN: Title

- Status: Proposed | Accepted | Superseded | Rejected
- Date: YYYY-MM-DD
- Decision owners: names or roles

## Context
What problem, constraints, threats, and requirements drive the decision?

## Decision
What is being chosen and what invariants must hold?

## Alternatives considered
What credible options were evaluated and why were they not chosen?

## Consequences
What benefits, risks, costs, migration work, and tests follow?

## Traceability
Requirement IDs, threat IDs, code modules, and test evidence.
```

## Initial ADR backlog

1. Go module boundaries and dependency direction
2. Persistence interfaces and transaction boundaries
3. Quarantine isolation and cleanup model
4. Static inspection adapter and fail-closed policy
5. SCA applicability and evidence format
6. AES-256-GCM envelope format and canonical AAD
7. Local key-provider contract and KEK rotation
8. Authentication/session mechanism
9. RBAC plus ownership/grant authorization model
10. HMAC audit canonicalization, checkpoint, and concurrency model
11. Immutable version and verify-before-restore semantics
12. Maximum file size and authenticated decryption strategy
