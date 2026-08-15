# ADR 0004: Fail-closed production transport profile

- Status: Accepted
- Date: 2026-08-14
- Decision owners: Security architecture and platform operations

## Context

Development needs convenient loopback HTTP and local adapters, but those settings must never silently become a production deployment. Independent feature flags are easy to misconfigure and can make an administrator dashboard appear secure while cookies, database traffic, or service dependencies remain exposed.

## Decision

SecureStore will have explicit `development` and `production` modes. Production startup validates the complete currently implemented transport boundary and refuses to run without direct HTTPS, secure cookies, exact HTTPS browser origins, PostgreSQL `sslmode=verify-full`, ClamD, remote managed key custody, remote audit anchoring, privileged MFA, administrator step-up, and externally sourced core secrets.

The application server enforces TLS 1.2 or newer and emits HSTS only for actual TLS requests. API responses also deny framing, MIME sniffing, referrer disclosure, unnecessary browser permissions, and active content through a restrictive API CSP. Forwarded scheme and client-address headers remain untrusted until a separate trusted-proxy decision is implemented.

## Alternatives considered

- **Documentation-only checklist:** too easy to bypass and cannot prevent insecure startup.
- **Implicit production based on certificate presence:** does not validate cookies, origins, database TLS, or dependency modes.
- **TLS termination assumed at any proxy:** unsafe without an explicit proxy trust and authenticated forwarding boundary.
- **HSTS on development HTTP:** can poison localhost browser behavior and does not describe the actual transport.

## Consequences

Production packaging must mount certificates and secrets and supply the approved remote integrations before the process starts. Local development remains unchanged. SMTP, actual provider resources, trusted proxy support, and final release validation remain separate work; this decision does not represent them as complete.

## Traceability

- Requirements: SR-DEPLOY-01 through SR-DEPLOY-05
- Code: `cmd/server/deployment.go`, `cmd/server/main.go`, `internal/api/server.go`
- Deployment: `deploy/production`
- Tests: `cmd/server/deployment_test.go`, `internal/api/server_test.go`
