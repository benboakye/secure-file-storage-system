# Release-readiness verification — 2026-08-15

## Decision

**Not production-ready.** The application, local security controls, disposable PostgreSQL integration gate, and source-control baseline passed, but required external production services remain unresolved release blockers.

## Verification results

| Gate | Result | Evidence |
| --- | --- | --- |
| Go toolchain | PASS | Project minimum upgraded from Go 1.26.5 to Go 1.26.6. |
| Go unit/API suites | PASS | `go test ./...` passed under Go 1.26.6. |
| Race detector | PASS | `go test -race ./...` passed in the official Linux `golang:1.26.6` container with a read-only workspace mount. Image digest: `sha256:640a234f4bea3e399c056b7b8f9c667c4939befae8db2f14e9785e16eccd4205`. |
| Go vet | PASS | `go vet ./...` completed without findings under Go 1.26.6. |
| Staticcheck | PASS after correction | Staticcheck v0.7.0 identified one duplicated-expression assertion in `rate_limiter_test.go`; the test now stores and checks the first and second decisions independently. The rerun completed without findings. |
| Go vulnerability scan | PASS after toolchain update | Initial scan found six reachable Go 1.26.5 standard-library vulnerabilities. After upgrading to 1.26.6, `govulncheck` reported zero reachable vulnerabilities. One advisory exists in a required module but no project call path reaches it. |
| Frontend vulnerability scan | PASS | `npm audit --json` reported 0 info, low, moderate, high, or critical vulnerabilities across 68 dependencies. |
| Frontend focused tests | PASS | `npm run test:frontend` passed 6 of 6 tests. |
| Frontend production build | PASS | TypeScript compilation and Vite production bundling completed successfully. |
| Requirements traceability | PASS with deployment qualifications | All 76 defined identifiers map to implementation and evidence families in `docs/requirements-traceability.md`. |
| PostgreSQL integration execution | PASS | All nine opt-in tests passed against an isolated PostgreSQL 18 database using a loopback-only ephemeral port and memory-backed storage. See `docs/postgresql-integration-verification-2026-08-15.md`. |
| Revision control | PASS | The audited initial baseline was committed locally as `0b110d4` after generated artifacts, runtime data, exports, environment overrides, and local screenshots were excluded. |

## Corrections made during this stage

### Patched Go standard library

The initial `govulncheck` run under Go 1.26.5 reported these reachable advisories, all fixed by Go 1.26.6:

- `GO-2026-6218` (`net/url` path-resolution complexity);
- `GO-2026-6090` (`crypto/tls` post-handshake message limits);
- `GO-2026-6089` (`net/http` HTTP/2 header timeout enforcement);
- `GO-2026-6088` (`encoding/xml` recursion depth);
- `GO-2026-5972` (`encoding/asn1` recursion depth);
- `GO-2026-5026` (`net/http`/IDNA Punycode label handling).

The project now declares `go 1.26.6`; a build environment using an older toolchain fails before compilation rather than silently producing a vulnerable binary.

### Race-compatible API test bound

Race instrumentation increases bcrypt cost-12 request latency on constrained workers. The test-only HTTP client timeout was raised from three to twenty seconds. Production HTTP server timeouts were not changed.

### Rate-limiter assertion

The rate-limiter test previously used the same side-effecting expression on both sides of a boolean condition. It now records the first and second authorization decisions separately, allowing Staticcheck and reviewers to verify the two-attempt expectation clearly.

## PostgreSQL integration execution

The following tests passed against the disposable database:

1. `TestPostgresCapacityReservationPreventsCrossProcessOversubscription`
2. `TestPostgresLifecycleTransitionAndAuditIntentAreAtomic`
3. `TestPostgresMetadataSurvivesManagerRecreation`
4. `TestPostgresAccountStatusAndAuditIntentAreAtomic`
5. `TestPostgresPrivilegedActivationAndAuditIntentAreAtomic`
6. `TestPostgresVerificationAndSessionPersistence`
7. `TestPostgresAuditPersistsAcrossReconnect`
8. `TestPostgresRetentionAndAuditIntentAreAtomic`
9. `TestPostgresOrphanJournalAndAuditIntentAreAtomic`

The database ran from the pinned official PostgreSQL 18 Alpine image with memory-backed storage and a loopback-only random port. The complete Go suite ran with caching disabled for test results, after which the container and its database were removed. This evidence does not replace production `sslmode=verify-full`, certificate, privilege, monitoring, backup, or recovery validation.

## External deployment blockers

- approved ClamAV/ClamD image and isolated runtime with fresh signature evidence;
- managed KMS/HSM provider with non-exportable keys and workload mTLS identity;
- independently administered immutable audit checkpoint ledger;
- production TLS certificates, secure cookies, exact HTTPS origins, and hardening headers;
- PostgreSQL `sslmode=verify-full` with trusted CA and server-name verification;
- externally injected production secrets rather than `.data` files;
- deployed metrics collector, alert routing, and recent-scrape evidence;
- backup provider, backup monitoring, and disaster-recovery evidence remain explicitly deferred;
- Resend or another approved external email-delivery service for non-local verification messages.

Docker Compose packaging, Cloudflare Tunnel publication, Windows automatic startup, and the Resend adapter are intentionally deferred to the self-hosted deployment stage documented in `docs/deferred-self-hosted-deployment.md`.

## Required next actions

1. Add the verification commands to CI so PostgreSQL integration, race, vet, Staticcheck, vulnerability scans, frontend tests, and builds cannot be skipped silently.
2. Implement the deferred self-hosted Docker, Cloudflare Tunnel, Windows startup, and Resend deployment package.
3. Configure and verify the remaining external deployment boundaries before changing the readiness decision.
