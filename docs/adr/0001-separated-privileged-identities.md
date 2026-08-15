# ADR 0001: Separate Privileged Identities and Session Audiences

- Status: Accepted
- Date: 2026-08-11
- Decision owners: SecureStore project owner and security architecture

## Context

An account previously used one login route and one undifferentiated session type. If the account role changed while a session remained valid, the session repository could expose the new role to that existing session. This creates a risk that authentication performed for standard file access could later authorize privileged operations without fresh privileged authentication.

The administrator interface also exposed a `User workspace` destination. Although it opened the administrator's own file view, the wording implied user impersonation and mixed privileged duties with standard file activity.

## Decision

Privileged and standard identities are operationally separate:

1. A human who performs both duties receives a standard `user` account and a separately provisioned `admin` or `auditor` account with different credentials.
2. Standard authentication uses `/api/v1/auth/login` and accepts only `user`.
3. Privileged authentication uses `/api/v1/admin/auth/login` and accepts only `admin` or `auditor`.
4. Sessions persist an immutable audience of `user` or `privileged`.
5. Admin APIs require the privileged audience plus the required current role.
6. File APIs require the user audience plus the `user` role.
7. Role changes revoke existing sessions.
8. The privileged console contains no user-impersonation or standard-workspace function.

## Alternatives considered

### One account with a role-based redirect

Rejected because the same credentials and session would span both ordinary and privileged duties, increasing accidental privilege use and making role-change session handling more dangerous.

### UI-only separation

Rejected because route hiding and redirects do not protect APIs. A modified client could still call privileged endpoints.

### Administrator impersonation

Rejected because it weakens attribution, exposes user data, complicates legal accountability, and creates a high-value abuse path. A separately designed break-glass workflow may be considered later.

## Consequences

- Administrators need a distinct privileged email identity because the current user table requires unique email addresses.
- Privileged users cannot upload or download files with their admin session.
- The UI and API have separate login destinations.
- Existing sessions created before migration are classified as standard and cannot authorize admin endpoints.
- MFA and recent re-authentication remain required production hardening work.

## Traceability

- Requirements: `ADM-AUTH-01..10`, `ADM-BOUNDARY-01..05`
- Authentication: `internal/authn/store.go`
- Persistence: `internal/authn/postgres_repository.go`
- API enforcement: `internal/api/server.go`
- Client routing: `src/App.tsx`, `src/appSession.ts`
- Tests: `internal/authn/store_test.go`, `internal/api/server_test.go`
