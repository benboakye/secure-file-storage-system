# Secure File Storage System

A Go prototype for lifecycle-integrated secure file storage. Files enter as untrusted input and move through explicit trust states: quarantine, static inspection, policy decision, authenticated encryption, controlled storage, revocable access, tamper-evident audit, and verified recovery.

The project demonstrates how established controls work together across a file's full lifecycle. Its contribution is the coordination and evaluation of those controls, not a new cryptographic algorithm or malware-detection technique.

## Objectives

- Accept uploads without treating them as trusted content.
- Isolate files in quarantine until static inspection and policy checks complete.
- Optionally run software composition analysis (SCA) for applicable software artifacts.
- Encrypt accepted files using AES-256-GCM envelope encryption.
- Enforce ownership, role, and grant-based authorization at every operation.
- Make authorization grants revocable without re-encrypting file content.
- Record security-relevant events in a tamper-evident HMAC chain.
- Recover only versions whose metadata, ciphertext, authentication tag, and policy checks verify.
- Evaluate both secure behavior and resistance to representative attacks.

## Scope

The planned prototype includes authentication, quarantine-based ingestion, static inspection, optional SCA, policy decisions, encryption, metadata and version management, revocable authorization, audit verification, and recovery testing.

Dynamic or behavioral file analysis is out of scope. The prototype will not execute uploaded content. Machine-learning detection, sandbox detonation, SGX, blockchain, and CP-ABE are also outside the current scope.

## Lifecycle

```text
untrusted -> quarantined -> inspecting -> accepted -> encrypting -> stored
                                  |                         |
                                  +-> rejected              +-> superseded
                                                               -> restore candidate
                                                               -> restored (after verification)
```

Transitions are server-controlled, validated, and audited. A file is never downloadable from quarantine, and plaintext is not retained after successful protected storage.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Security requirements](docs/security-requirements.md)
- [File lifecycle](docs/file-lifecycle.md)
- [Cryptography](docs/cryptography.md)
- [Authorization](docs/authorization.md)
- [Administrator requirements](docs/admin-requirements.md)
- [Audit design](docs/audit-design.md)
- [Recovery](docs/recovery.md)
- [Testing strategy](docs/testing-strategy.md)
- [Local hosting](docs/local-hosting.md)
- [Local end-to-end verification report](docs/local-e2e-verification.md)
- [Administrator end-to-end verification report — 2026-08-14](docs/admin-e2e-verification-2026-08-14.md)
- [Architecture decisions](docs/adr/README.md)
- [Security policy](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)

## Planned Go structure

```text
cmd/server/          application entry point
internal/authn/      identity and session handling
internal/authz/      policy decisions and revocation
internal/ingest/     upload limits, quarantine, inspection orchestration
internal/storage/    encrypted object and metadata persistence
internal/crypto/     envelope encryption and key interfaces
internal/audit/      event creation and chain verification
internal/recovery/   version verification and restore workflow
internal/policy/     acceptance and retention rules
```

The structure is a target, not yet an implementation claim.

## Local development

### Email verification

Registration creates an unverified account and never creates a session. The user must consume a single-use, 30-minute verification token and then sign in manually. Resend requests are rate-limited and registration/resend responses do not disclose whether an account already exists.

For local development and a single-host local deployment, verification messages are written with owner-only permissions to `.data/mailbox`. Set `SECURESTORE_DATABASE_URL` to use the durable PostgreSQL account, token, and session repository; without it, the API clearly warns that authentication state is in memory. No Supabase account or SMTP service is required for this workflow. See the [local-hosting guide](docs/local-hosting.md) for the trust boundary and test procedure.

`SECURESTORE_DEPLOYMENT_MODE=production` activates a fail-closed startup profile. The process refuses to run without direct HTTPS certificate files, secure cookies, exact HTTPS origins, PostgreSQL `sslmode=verify-full`, ClamD, remote key custody, remote audit anchoring, privileged MFA, administrator step-up, and externally sourced core secrets. The checked-in [production transport package](deploy/production/README.md), [deployment-hardening notes](docs/deployment-hardening.md), validator, ADR, and tests define this boundary. Authenticated SMTP remains a blocker only for a production deployment that must deliver verification messages to external inboxes; the explicitly local profile uses the private filesystem mailbox and does not claim external mail delivery.

### Administrator directory

`GET /api/v1/admin/users` returns a paginated, searchable directory containing only safe account fields. The API checks the authenticated user's current database role on every request and returns `403` unless the role is `admin`. The frontend additionally hides and redirects the Administration route for standard users, but that UI behavior is not relied upon for security. Public registration never assigns a privileged role.

Identity governance includes administrator-only suspension/reactivation and targeted session revocation. Mutations require the privileged session's CSRF token, prohibit changes to the currently signed-in administrator, and never expose session tokens. Suspending an account changes its durable status and removes its sessions in one PostgreSQL transaction; both existing sessions and later login attempts are denied.

Privileged identities are provisioned with `POST /api/v1/admin/users/invitations`, never through public registration or promotion of a standard-user account. Creating an invitation requires an administrator session, CSRF validation, and recent password-plus-TOTP step-up authorization. The recipient receives a single-use 30-minute activation link, chooses a password unknown to the inviter, and receives no session during activation. First privileged sign-in then requires authenticator enrollment. Invitation creation and activation are recorded in the audit chain.

`GET /api/v1/admin/resources` provides administrators and auditors with a safe metadata projection from durable PostgreSQL ingestion records plus quarantine usage measured from disk. It excludes content, filesystem paths, digests, idempotency hashes, wrapped DEKs, nonces, and key material. Startup reloads lifecycle records, safely resumes interrupted inspection or protection, fails records closed when required quarantine objects are missing, and reports unmatched quarantine objects without deleting them. Protected-version envelope metadata is durable in PostgreSQL and ciphertext uses opaque server-generated object names.

The same resource endpoint performs protected-storage capacity reconciliation. It measures actual ciphertext bytes on disk, compares protected-version database records with present objects, reports orphaned ciphertext and missing tracked objects, and raises a high-severity alert when less than ten percent of the hosting volume remains available. Hosting-volume totals can include unrelated files on the same volume and are therefore labelled separately from SecureStore ciphertext usage. No object is opened, decrypted, hashed, or automatically deleted during this accounting pass.

`GET /api/v1/admin/security` gives administrators and auditors a read-only, server-confirmed posture view. It reports the active password, verification, opaque-session, CSRF, privileged-boundary, TOTP MFA, timed account lockout, durable audit-chain, managed key connection/hardware evidence, aggregate DEK-wrapper rotation, and live malware-scanner posture; complete PostgreSQL account-state totals; and durable upload-decision counts. The ClamD adapter reports production-ready only when daemon health and fresh engine/database/timestamp evidence are available. Administrators with a fresh step-up proof can run bounded key-wrapper batches through `POST /api/v1/admin/security/keys/rewrap`; auditors remain read-only. Privileged password verification creates only a five-minute, single-use MFA transaction. First login enrolls an authenticator secret, subsequent login requires TOTP or one unused recovery code, and a session is issued only after MFA succeeds. The deterministic scanner, file-backed KEK, and local MFA encryption-key adapters are explicitly development-only. Actual managed KMS/HSM resources remain deployment inputs.

`GET /api/v1/admin/monitoring` provides a privileged read-only operations view: process uptime, safe persistence-class status, processing queue and failures, measured quarantine/orphan usage, scanner capability, managed key-custody evidence, independent audit-anchor evidence, telemetry scrape evidence, and effective upload, quota, inspection, session, cookie, and origin policies. It reveals neither database connection details nor filesystem paths. A bearer-protected Prometheus exporter is available at `GET /metrics`; the interface reports external telemetry connected only after a recent authenticated scrape. Certificate-verifying collector configuration, eighteen alert rules, executable rule tests, and an incident-response runbook are provided under `deploy/monitoring` and [monitoring-runbook.md](docs/monitoring-runbook.md). Actual collector deployment, notification routing, and backup monitoring remain explicitly pending. See [telemetry](docs/telemetry.md).

`GET /api/v1/admin/resources/orphans` provides an opaque, metadata-only preview of unmatched quarantine and protected-storage objects. Objects remain ineligible for one hour to protect active commit windows. Administrators may explicitly select at most 25 eligible tokens through `POST /api/v1/admin/resources/orphans/reconcile` after step-up authentication; auditors are read-only. The server revalidates current metadata, file type, size, and modification time, then journals authorization and audit intent atomically before deletion. A recovery worker safely completes only this previously authorized work after a restart. See [orphan reconciliation](docs/orphan-reconciliation.md).

`GET /api/v1/admin/lifecycle` provides administrators and auditors with durable state counts, pending and stuck-processing signals, recent safe metadata, deletion-operation history, recovery-drill evidence, alerts, and quarantine reconciliation measurements. A bounded in-process worker evaluates eligible deletions at startup and every minute; administrators may also trigger the same idempotent evaluation manually. Controlled recovery drills authenticate and digest-check an encrypted current version but never return plaintext through the admin API. Retention, legal holds, grace-period deletion, and cryptographic deletion are connected. Backup monitoring remains explicitly not configured until a deployment provider is integrated.

### Deferred backup integration

Backup creation, external backup storage, backup monitoring, restore-from-backup, recovery-point objectives, and disaster-recovery automation are intentionally outside the current implementation stage. The application reports backup posture as `not_configured` and must not be represented as backup-enabled or disaster-recovery-ready. These capabilities will be designed and tested during a later deployment-hardening stage; current encrypted-version recovery drills validate primary protected storage only and are not substitutes for backups.

`GET /api/v1/admin/audit` returns a privileged safe projection of PostgreSQL audit events and verifies the entire ordered HMAC-SHA-256 chain against its checkpoint. Structured actor, action, resource, outcome, date, free-text, and IP filters are server-enforced; IP addresses are converted to keyed fingerprints rather than stored raw. The administrator interface includes bounded pagination, 24-hour/high-risk summaries, threshold alerts, pending-evidence monitoring, and a safe CSV export whose response records the observed chain-integrity state. Administrator identity/quota controls, privileged invitation creation/activation, direct protected-file operations, ingestion lifecycle transitions, scheduled per-file deletion outcomes, and recovery drills commit sanitized stable-ID audit intents through the PostgreSQL outbox. The retrying worker signs and chains these events without turning delayed delivery into a false failed-operation response.

`GET /api/v1/uploads/{uploadId}/content` is available only to the authenticated standard-user owner of a `stored` upload. The server validates authoritative envelope metadata, unwraps the per-version DEK, authenticates the complete bounded AES-256-GCM ciphertext and AAD, verifies the plaintext digest, writes the required download audit event, and only then returns bytes. Knowledge of an upload ID does not grant access.

`GET /api/v1/files` returns stable owner-scoped logical file records ordered newest first. `GET /api/v1/files/{fileId}` returns safe immutable version history, and `GET /api/v1/files/{fileId}/content` downloads the authenticated current version. `POST /api/v1/files/{fileId}/versions/{versionId}/restore` verifies the selected source, creates a fresh AES-256-GCM envelope with a new DEK and nonce, records lineage, and atomically advances the logical file's current pointer. These responses exclude digests, storage locators, wrapped keys, nonces, and key material.

Owners can grant `read` (metadata only) or `download` access to another active, verified standard-user account, optionally with an expiry. Grants are durable, CSRF-protected, auditable, immediately revocable for new requests, and never make administrators eligible for plaintext access. `GET /api/v1/files/shared` powers the recipient's authoritative **Shared with me** view. Public links, wildcard grants, impersonation, and recipient restore are prohibited.

Owner files support a durable Trash lifecycle with a 30-day recovery period. Trash immediately blocks owner and recipient reads and revokes active grants; restoration does not silently recreate them. Administrator retention deadlines are forward-only while active, legal holds require a recorded reason, and auditors cannot mutate either control. Permanent deletion is owner-authorized, idempotent, policy-gated, and cryptographically destroys every wrapped per-version DEK before best-effort ciphertext cleanup while retaining a non-content tombstone.

Local development creates `.data/local-kek.key` with owner-only permissions and reports that custody truthfully as development-only. Production selects `SECURESTORE_KEY_PROVIDER=remote`; a private mutual-TLS key broker delegates wrap/unwrap to an approved hardware-backed managed KMS/HSM without loading a plaintext KEK into SecureStore. The checked-in [managed-key deployment package](deploy/kms/README.md), strict broker contract, tests, posture, metrics, alerts, and [operations runbook](docs/kms-operations.md) are provider-neutral. Actual provider keys, HSM policy, certificates, workload grants, and private networking remain deployment inputs.

Local development creates `.data/audit-hmac.key` with owner-only permissions when no key is configured. Production must inject `SECURESTORE_AUDIT_HMAC_KEY` from a secret manager and preserve historical keys for rotation/verification; never commit this key.

Audit writes use `SECURESTORE_AUDIT_KEY_VERSION` and retained verification keys may be supplied through `SECURESTORE_AUDIT_HISTORICAL_KEYS`. A version change creates a chained key-rotation event; removing a key still referenced by retained evidence makes verification fail closed. Protected envelopes similarly use `SECURESTORE_LOCAL_KEK_VERSION` plus a development-only historical keyring. The controlled DEK-rewrap workflow moves encrypted DEK wrappers to the configured current KEK in optimistic batches, commits a durable operation ledger and audit-outbox event atomically, and never reads or rewrites file ciphertext. Historical KEKs must be retained until the posture reports zero pending versions. This does not replace managed KMS/HSM custody.

Audit checkpoints are appended through a pluggable destination. The local adapter uses a distinct HMAC key and owner-restricted `.data/audit-checkpoints.jsonl` evidence, but remains development-only because it shares the application host. The production adapter uses mTLS to append checkpoint digests to an independently administered immutable ledger and verifies its Ed25519 receipts with a pinned public key; the receipt signing key never enters SecureStore. The provider-neutral contract, safe environment template, validator, tests, alerts, ADR, and operations runbook are under `deploy/audit-anchor` and [audit-anchor-operations.md](docs/audit-anchor-operations.md). Actual ledger resources, certificates, retention, independent ownership, and provider-native logs remain deployment inputs.

Local development also creates `.data/mfa-encryption.key` to encrypt privileged TOTP seeds before database persistence. Production must inject `SECURESTORE_MFA_ENCRYPTION_KEY` from a secret manager, keep `SECURESTORE_REQUIRE_PRIVILEGED_MFA=true`, and establish key rotation and privileged recovery procedures before deployment.

Authentication protection counts failures durably per known account. Five failed password or MFA attempts within fifteen minutes produce a fifteen-minute timed lock and revoke existing sessions; a successful complete authentication clears the counters. The API also applies a process-local network limit of ten attempts per five minutes, independently scoped to standard password, privileged password, and privileged MFA endpoints. Responses remain generic to avoid account disclosure. Multi-instance deployment must move network throttling to a shared trusted ingress or distributed limiter.

High-risk administrator mutations require step-up authorization through `POST /api/v1/admin/auth/step-up`. The administrator must re-enter the account password and a fresh six-digit TOTP code; recovery codes are not accepted. The API stores only a digest of the opaque proof, binds it to the exact privileged session, and expires it after five minutes by default. The web client keeps the returned proof in memory only. Account suspension/reactivation, session revocation, quota changes, retention and legal-hold changes, lifecycle deletion processing, and recovery drills all enforce this proof server-side.

Each standard user receives an independently enforced default storage quota from `SECURESTORE_DEFAULT_USER_QUOTA_BYTES` (1 GiB by default). Quarantined, inspecting, accepted, encrypting, and stored bytes count toward quota; rejected and failed records do not. Concurrent uploads reserve bytes under the manager lock so parallel requests cannot oversubscribe the account, and denied uploads remove partial quarantine data. The admin resource view reports per-owner charged usage and alerts at 80% utilization.

Network uploads also require an exact `X-File-Size` declaration. PostgreSQL serializes owner and global admission across API processes, reserving declared bytes against both the account quota and the configured storage pool before quarantine streaming begins. The default 50 GiB pool retains a 5 GiB safety reserve; exact byte-count enforcement, terminal-state release, one-hour expiry, and incomplete-reception restart cleanup prevent leaked or understated reservations. See [storage-capacity reservations](docs/capacity-reservations.md).

Administrators can persist a 1 MiB to 10 TiB per-owner override from the **Account quotas** panel or with `PUT /api/v1/admin/resources/owners/{ownerId}/quota`. This mutation requires an administrator-authenticated privileged session and its CSRF token, and it accepts only a separate account whose current role is `user`; auditors remain read-only. Setting an override below current charged usage is allowed as a fail-closed policy change: the account is immediately over quota and cannot add another upload until usage falls below the limit or the quota is raised.

Privileged identities sign in through `/api/v1/admin/auth/login`; standard identities use `/api/v1/auth/login`. Sessions record which authentication boundary created them. Admin APIs require a privileged session and file APIs require a standard-user session, so changing a database role cannot silently upgrade an existing standard session. Administrators who also need personal file storage use a separately registered standard account.

Go and Node.js are required. Never use real malware, production secrets, or sensitive personal files in development.

The default `SECURESTORE_SCANNER_MODE=deterministic` preserves harmless local fixtures and is never represented as production-ready. For production, set `SECURESTORE_SCANNER_MODE=clamd`, configure the private socket/address, and set `SECURESTORE_CLAMD_MAX_SIGNATURE_AGE_HOURS` (24 by default). SecureStore safely parses ClamD engine, database-version, and UTC database-timestamp evidence immediately before every scan. Missing, stale, malformed, materially future-dated, timed-out, unavailable, oversized, or otherwise uncertain inspection evidence returns `inspection_unavailable`; it never authorizes protected storage. Exact server-opened quarantine bytes are streamed with bounded `INSTREAM`, and raw signature names are discarded. The [ClamAV deployment package](deploy/clamav/README.md) persists databases, checks hourly with FreshClam, notifies ClamD after updates, and publishes no host port. See [ClamAV production operations](docs/clamav-operations.md).

Start the API in one terminal:

```text
npm run dev:api
```

Start the React application in another terminal:

```text
npm run dev
```

The Vite development server proxies `/api` to `127.0.0.1:8080`. Local quarantine data is written beneath `.data/quarantine` using server-generated opaque filenames and is excluded from version control. Configuration options are documented in `.env.example`; the API contract is maintained in `api/openapi.yaml`.

The checked-in [continuous-integration workflow](docs/continuous-integration.md) runs the full Go and PostgreSQL suite, race detection, Go static and vulnerability analysis, frontend dependency audit, focused frontend tests, and the production build. The workflow is verification-only and receives no deployment credentials.

## Status

The current executable includes durable PostgreSQL identity, ingestion, protected-file, lifecycle, sharing, quota, and audit metadata; isolated quarantine; configurable deterministic or ClamD inspection; envelope-encrypted immutable versions; separate privileged sessions; and administrator governance views. Local adapters remain intentionally non-production where the dashboard and documentation say so.
