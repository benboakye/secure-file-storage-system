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
| Continuous integration | PASS locally and remotely | The read-only GitHub Actions workflow passed actionlint v1.7.12 locally. Remote run [31876728937](https://github.com/benboakye/secure-file-storage-system/actions/runs/31876728937) passed all three jobs: backend/PostgreSQL/security analysis, the race-enabled PostgreSQL suite, and frontend tests/audit/build. Screenshot evidence is retained in `docs/testing/evidence/github-actions-run-31876728937-success.png`. |
| Self-hosted Docker foundation | PASS for local evaluation | The loopback-only gateway, Go API, PostgreSQL, ClamAV, persistent volumes, private networks, file-mounted secrets, health checks, and ClamAV startup barrier passed build, cold-start, isolation, browser, header, and restart checks. See `docs/self-hosted-docker-verification-2026-08-15.md`. This does not change the production-readiness decision. |
| Resend transactional delivery | PASS for local evaluation | The verified `mail.securevault.tech` sending subdomain, domain-restricted key, masked secret installation, HTTPS adapter, Docker egress boundary, automated tests, runtime initialization, and live verification-email delivery passed. See `docs/resend-email-adapter-verification-2026-08-15.md`. Public links still require the Cloudflare HTTPS origin. |

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

- production approval of the locally verified ClamAV/ClamD image, update policy, and operational monitoring;
- managed KMS/HSM provider with non-exportable keys and workload mTLS identity;
- independently administered immutable audit checkpoint ledger;
- production TLS certificates, secure cookies, exact HTTPS origins, and hardening headers;
- PostgreSQL `sslmode=verify-full` with trusted CA and server-name verification;
- externally injected production secrets rather than `.data` files;
- deployed metrics collector, alert routing, and recent-scrape evidence;
- backup provider, backup monitoring, and disaster-recovery evidence remain explicitly deferred;
- public-origin Resend verification, expiry, replay, resend, bounce, and suppression evidence after Cloudflare publication.

The loopback-only Docker Compose foundation and Resend adapter are implemented and locally verified. Cloudflare Tunnel publication and Windows automatic startup remain deferred deployment stages documented in `docs/deferred-self-hosted-deployment.md`.

## Required next actions

1. Merge only through the documented manual pull-request gate while the private repository remains on GitHub Free; all three CI jobs must pass before merge. Enable enforced branch protection if the repository later moves to a plan that supports it for private repositories.
2. Add the named Cloudflare Tunnel and Windows boot-start integration without weakening the local service-isolation boundaries, then repeat Resend tests against the public HTTPS origin.
3. Configure and verify the remaining external deployment boundaries before changing the readiness decision.
