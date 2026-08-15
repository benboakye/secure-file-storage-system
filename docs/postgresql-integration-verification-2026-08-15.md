# PostgreSQL integration verification — 2026-08-15

## Outcome

All nine opt-in PostgreSQL integration tests passed as part of the complete Go test suite. No test used the active development database, and no disposable database data was retained after verification.

## Isolated test boundary

- Runtime: Docker Desktop Linux engine 29.5.2.
- Database image: official `postgres:18-alpine`, pinned to `sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15`.
- Container: `securestore-pg-release-test`.
- Exposure: an ephemeral port bound only to `127.0.0.1`.
- Storage: a 512 MiB `tmpfs` mounted at `/var/lib/postgresql`; no host volume was attached.
- Credentials and audit key: test-only values scoped to the validation processes.
- Cleanup: the container was stopped and removed after the suite passed. The memory-backed database was destroyed with it.

The first startup attempt used the pre-PostgreSQL-18 data mount path. PostgreSQL 18 rejected that layout before initialization. The empty failed container was removed and recreated with the required `/var/lib/postgresql` parent mount.

## Executed PostgreSQL evidence

1. `TestPostgresCapacityReservationPreventsCrossProcessOversubscription`
2. `TestPostgresLifecycleTransitionAndAuditIntentAreAtomic`
3. `TestPostgresMetadataSurvivesManagerRecreation`
4. `TestPostgresAccountStatusAndAuditIntentAreAtomic`
5. `TestPostgresPrivilegedActivationAndAuditIntentAreAtomic`
6. `TestPostgresVerificationAndSessionPersistence`
7. `TestPostgresAuditPersistsAcrossReconnect`
8. `TestPostgresRetentionAndAuditIntentAreAtomic`
9. `TestPostgresOrphanJournalAndAuditIntentAreAtomic`

## Verification command family

The test process received a disposable `SECURESTORE_TEST_DATABASE_URL`, a 32-byte test-only `SECURESTORE_TEST_AUDIT_HMAC_KEY`, and workspace-local Go caches. It then ran:

```text
go test -count=1 -v ./...
```

The full suite passed across `cmd/server`, `internal/api`, `internal/audit`, `internal/authn`, `internal/ingest`, `internal/orphan`, and `internal/protectedstore`. The verbose output showed all nine PostgreSQL tests as `PASS`; none was skipped.

## Security meaning

This run provides local integration evidence for PostgreSQL persistence, reconnect behavior, cross-process capacity admission, and the transactional coupling of protected mutations with audit-outbox intent. It does not establish production PostgreSQL TLS, certificate validation, least-privileged production roles, operational backup, or disaster-recovery readiness.
