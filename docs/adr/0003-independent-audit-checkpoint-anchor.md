# ADR 0003: Independent server-attested audit checkpoint anchor

- Status: Accepted
- Date: 2026-08-14
- Decision owners: Security architecture and platform operations

## Context

The database audit chain and checkpoint detect internal edits when the HMAC keys remain trusted, but a database administrator could restore an older internally consistent database snapshot. The local JSONL anchor demonstrates the protocol yet shares the application host, administration, and HMAC signing secret. Production evidence requires an independent trust and retention boundary.

## Decision

SecureStore will use a provider-neutral remote checkpoint ledger over mutually authenticated TLS. The ledger must enforce append-only, strictly consecutive storage under independent administration, require every previous-checkpoint digest to equal its retained chain head, and return an Ed25519-signed receipt for the exact chain ID, sequence, checkpoint digest, previous checkpoint digest, audit-key version, and timestamp.

SecureStore holds only the pinned receipt public key. It rejects plaintext endpoints, redirects, unknown response fields, malformed or mismatched receipts, untrusted signatures, and unsafe posture. Production readiness is true only when the service reports enabled, immutable, independently administered, server-attested operation and the latest receipt verifies against the database checkpoint.

Database commits remain authoritative if the ledger is briefly unavailable; the resulting anchoring lag is explicit, critical, and monitored. This avoids reporting a failed business mutation after it has already committed while preserving visible evidence degradation.

## Alternatives considered

- **Database checkpoint only:** cannot distinguish rollback to an older valid state.
- **Local append-only JSONL file:** useful for development but shares host and administrators.
- **Application-HMAC-signed remote object:** external retention helps, but an application compromise retains signing authority and cannot provide independent service attestation.
- **Full audit-event replication:** offers richer investigation but expands sensitive data, privacy, and interface scope beyond the checkpoint objective.

## Consequences

Production needs an independently owned ledger, private network, certificates, workload policy, immutable retention, Ed25519 signing key, public-key distribution, monitoring, and incident ownership. Receipt-key overlap is not yet implemented and must be added before rotating a provider that cannot retain verification under one pinned key.

The local adapter remains available only for development. Backups remain a separately deferred control.

## Traceability

- Requirements: SR-AUD-06, SR-AUD-07, SR-AUD-08
- Threats: database rollback, checkpoint replacement, shared-administrator compromise
- Code: `internal/audit/remote_anchor.go`, `internal/audit/service.go`
- Deployment: `deploy/audit-anchor`
- Tests: `internal/audit/remote_anchor_test.go`, Prometheus alert-rule tests
