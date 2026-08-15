# Security requirements traceability

Last reviewed: 2026-08-15

This index maps every defined security and administrator requirement to its primary implementation and evidence families. A mapping means the requirement has an identified verification path; it does not convert a deployment-dependent control into production evidence.

## Status definitions

- **Automated:** exercised by the normal Go or frontend suite.
- **Manual plus automated:** automated boundaries are supplemented by the local administrator end-to-end verification report.
- **Deployment evidence pending:** adapters, validators, and fail-closed behavior are tested, but the external production service, certificate, key, receiver, or runtime is not configured locally.

## Traceability index

| Requirements | Primary implementation | Primary evidence | Status |
| --- | --- | --- | --- |
| ADM-AUTH-01, ADM-AUTH-02, ADM-AUTH-03, ADM-AUTH-04, ADM-AUTH-05, ADM-AUTH-06, ADM-AUTH-07, ADM-AUTH-08, ADM-AUTH-09 | `internal/authn/store.go`, `internal/api/server.go`, `src/App.tsx` | `internal/authn/store_test.go`, `internal/api/server_test.go` | Automated |
| ADM-AUTH-10, ADM-AUTH-11, ADM-AUTH-12 | `internal/authn/mfa.go`, `internal/authn/step_up.go`, API authentication limiters | authentication-store, API, and rate-limiter tests | Automated |
| ADM-AUTH-13, ADM-AUTH-14, ADM-AUTH-15 | privileged invitations, separate activation, self-management prohibition, `src/identityPermissions.ts` | authentication/API tests, frontend identity-policy tests, administrator verification report | Manual plus automated |
| ADM-BOUNDARY-01, ADM-BOUNDARY-02, ADM-BOUNDARY-03, ADM-BOUNDARY-04, ADM-BOUNDARY-05 | privileged portal/API projections and absence of impersonation/download/break-glass endpoints | administrator/auditor API tests and administrator verification report | Manual plus automated; future break-glass remains prohibited |
| ADM-DATA-01, ADM-DATA-02, ADM-DATA-03, ADM-DATA-04 | administrator resource, monitoring, security, lifecycle views and stylesheet typography rules | API posture tests, live view verification, production frontend build | Manual plus automated |
| SR-AUTHN-01, SR-AUTHN-02 | session store, bcrypt password handling, opaque tokens, generic authentication errors | authentication-store and API session tests | Automated |
| SR-INPUT-01, SR-INPUT-02, SR-INPUT-03 | bounded request reader, quarantine naming, safe error projection, strict provider clients | API upload-limit, ingestion, scanner, key-provider, and telemetry tests | Automated |
| SR-ING-01, SR-ING-02, SR-ING-03, SR-ING-04, SR-ING-05, SR-ING-06 | quarantine-first ingestion state machine and deterministic development inspector | ingestion manager and API lifecycle tests | Automated |
| SR-ING-07, SR-ING-08 | ClamD adapter, signature-age parser, deployment validator, private-network template | ClamD and deployment-validator tests | Deployment evidence pending for an approved image/runtime |
| SR-CRYPTO-01, SR-CRYPTO-02, SR-CRYPTO-03, SR-CRYPTO-04, SR-CRYPTO-05 | AES-256-GCM envelope service, random DEKs/nonces, authenticated metadata, wrapped-key interface | protected-storage round-trip, mutation, lifecycle, and recovery tests | Automated |
| SR-CRYPTO-06, SR-CRYPTO-07, SR-CRYPTO-08 | remote mTLS key broker, strict response binding, versioned wrapper posture and rewrap workflow | remote-key, deployment-validator, key-rotation, and recovery tests | Deployment evidence pending for managed non-exportable keys |
| SR-STOR-01, SR-STOR-02 | immutable file versions, authoritative metadata, restricted staging/quarantine cleanup | protected-storage, ingestion recovery, and API catalog tests | Automated |
| SR-AUTHZ-01, SR-AUTHZ-02, SR-AUTHZ-03, SR-AUTHZ-04, SR-AUTHZ-05 | audience/role gates, owner/grant checks, lifecycle gates, privileged plaintext prohibition | API ownership, sharing, revocation, auditor, administrator, lifecycle, and deletion tests | Automated |
| SR-AUD-01, SR-AUD-02, SR-AUD-03, SR-AUD-04, SR-AUD-05 | canonical HMAC chain, safe projection, transactional outbox, stable event identity | audit service, atomic repository, lifecycle-denial, idempotent deletion, and disposable PostgreSQL integration tests | Automated |
| SR-AUD-06, SR-AUD-07, SR-AUD-08 | remote immutable-anchor client, mTLS, signed receipt verification, lag posture and alerts | anchor client, validator, and alert tests | Deployment evidence pending for independently administered ledger |
| SR-OBS-01, SR-OBS-02, SR-OBS-03, SR-OBS-04 | dedicated metrics bearer, bounded route labels, recent-scrape evidence | API metrics and telemetry tests | Automated |
| SR-OBS-05, SR-OBS-06 | TLS collector template, file-mounted bearer, alert rules and response runbook | deployment parser, `promtool` structural/rule tests where available | Deployment evidence pending for collector and notification receiver |
| SR-DEPLOY-01, SR-DEPLOY-02, SR-DEPLOY-03, SR-DEPLOY-04, SR-DEPLOY-05 | production startup profile, transport headers, verified PostgreSQL configuration, external-secret rules | configuration/startup and deployment-validator tests | Deployment evidence pending |
| SR-REC-01, SR-REC-02, SR-REC-03, SR-REC-04, SR-REC-05 | authorized immutable version restore and metadata-only recovery verification | API restore idempotency, protected-storage integrity, corruption, and recovery-drill tests | Automated; external backup recovery remains deferred |

## Coverage accounting

- Defined requirement identifiers: **76**.
- Requirement identifiers mapped above: **76**.
- Focused frontend tests: **6**.
- Go `Test`/`Fuzz` functions discovered during this review: **83** before the final release-readiness additions.
- PostgreSQL integration tests executed against the disposable database: **9 of 9 passed**.

The PostgreSQL gate covered authentication/session persistence, audit persistence, lifecycle/outbox atomicity, privileged activation, capacity reservation, ingestion transitions, and orphan reconciliation. The isolated execution boundary and cleanup evidence are recorded in `docs/postgresql-integration-verification-2026-08-15.md`.

## Authoritative supporting documents

- `docs/security-requirements.md`
- `docs/admin-requirements.md`
- `docs/testing-strategy.md`
- `docs/admin-e2e-verification-2026-08-14.md`
- `docs/postgresql-integration-verification-2026-08-15.md`
- `docs/release-readiness-2026-08-15.md`
