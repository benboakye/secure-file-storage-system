# Administrator Requirements

## Purpose and boundary

The privileged console governs identities, system policy, security posture, capacity, and data lifecycle. It is not a file workspace and does not grant access to user plaintext. A person who needs both administrative duties and personal file storage uses two separately provisioned accounts with different credentials.

Public registration creates only a `user` account. Administrator and auditor identities are provisioned through a controlled administrative process; no public privileged registration endpoint exists.

## Roles

| Role | Intended capability | Explicit exclusions |
|---|---|---|
| `user` | Manage authorized files, folders, shares, personal sessions, and personal security settings | No organization-wide identity, policy, or monitoring access |
| `auditor` | Read approved audit, compliance, and security metadata | No user management, policy mutation, impersonation, or plaintext access |
| `admin` | Manage identities and global policies; monitor capacity, security, health, and lifecycle operations | No impersonation, automatic plaintext access, raw key access, or audit-history alteration |

## Authentication and session requirements

- **ADM-AUTH-01:** Standard and privileged accounts use separate credentials and login endpoints.
- **ADM-AUTH-02:** Standard login accepts only the `user` role.
- **ADM-AUTH-03:** Privileged login accepts only `admin` and `auditor` roles.
- **ADM-AUTH-04:** Every server-side session records its audience as `user` or `privileged`.
- **ADM-AUTH-05:** An admin endpoint requires both a privileged session audience and the required database role.
- **ADM-AUTH-06:** File operations require both a user session audience and the `user` role.
- **ADM-AUTH-07:** Role changes revoke existing sessions; promotion cannot upgrade an already-open standard session.
- **ADM-AUTH-08:** Role mismatch produces the generic invalid-credentials response to reduce account-role disclosure.
- **ADM-AUTH-09:** Public registration cannot assign `auditor` or `admin`.
- **ADM-AUTH-10:** Every privileged session requires password verification followed by TOTP MFA or one unused recovery code.
- **ADM-AUTH-11:** Five failed password or MFA attempts within fifteen minutes temporarily lock the known account for fifteen minutes and revoke its sessions. Authentication endpoints also enforce a bounded network-source rate limit and return generic denial responses.
- **ADM-AUTH-12:** High-risk administrator mutations require a second password check and a fresh TOTP code. The resulting opaque proof is stored only as a digest, bound to the exact privileged session, expires after five minutes by default, and cannot be obtained with a recovery code.
- **ADM-AUTH-13:** An administrator provisions a new `admin` or `auditor` identity only through a step-up-protected invitation. The recipient chooses credentials through a single-use expiring link; activation creates no session and first privileged sign-in requires TOTP enrollment.
- **ADM-AUTH-14:** A standard-user account is never promoted by the application. A person with both duties receives separate email identities and credentials, preventing one account from crossing both authentication boundaries.
- **ADM-AUTH-15:** Administrators cannot suspend or revoke their own active privileged identity. The UI fails closed by replacing self-management controls with a current-account label, while direct API attempts return a safe conflict, leave the session unchanged, and append normalized denied audit evidence. Because no role-demotion or privileged-deletion endpoint exists, the application cannot remove the final administrator through the console.

## Prohibited impersonation

- **ADM-BOUNDARY-01:** No administrator control may create a session as another user.
- **ADM-BOUNDARY-02:** No user password, password hash, verification token, session token, CSRF token, or raw encryption key is returned by an admin API.
- **ADM-BOUNDARY-03:** Administrators may view file metadata only after a dedicated metadata API applies tenant and policy scope.
- **ADM-BOUNDARY-04:** Administrators do not receive download or decryption permission by virtue of role.
- **ADM-BOUNDARY-05:** Any future emergency-access mechanism is a separate break-glass design requiring MFA, re-authentication, reason, duration, approval policy, and immutable audit events.

## Administrator control domains

### Identity and access governance

- Verified, unverified, suspended, and locked account totals.
- Administrator and auditor counts.
- Searchable safe-field identity directory.
- Controlled role assignment, session revocation, and MFA enforcement.
- Protection against deleting or demoting the final administrator.

### Resource and capacity management

- Aggregate protected-storage and quarantine usage.
- Available capacity, growth, quotas, and processing-queue depth.
- Administrator-managed per-user quota overrides with an audited reset-to-organization-default action; auditors can inspect but cannot mutate quota policy.
- File metadata inventory containing owner, size, media type, lifecycle state, timestamps, and classification.
- No plaintext preview or download through the administrative metadata view.

### Security and compliance

- Authentication-policy and MFA-enforcement status.
- Tamper-evident audit-chain verification and export.
- Quarantined, accepted, rejected, failed, and threat-detection counts.
- Encryption algorithm, key identifier, rotation status, and provider health without raw key material.
- Malware scanner health and signature currency.

### System monitoring and global controls

- API, database, worker, scanner, encryption, and primary-storage recovery health. External backup health is deferred to a later deployment-hardening stage.
- Upload-size, media-type, sharing, retention, and session-lifetime policy controls.
- Failed jobs and security conditions requiring attention.

### Data protection and lifecycle management

- Retention, quarantine expiry, version limits, deletion grace periods, and legal holds.
- Files stuck in lifecycle states and failed encryption or inspection operations.
- Backup status remains explicitly `not_configured`. Backup creation, provider monitoring, and restore-from-backup evidence are deferred and must not be presented as implemented.
- Confirmed and audited destructive global actions.

## Dashboard data integrity

- **ADM-DATA-01:** Every numeric statistic must originate from an authoritative API or database query.
- **ADM-DATA-02:** A capability without a real data source is labelled `Not connected`, `Pending`, or `Unavailable`.
- **ADM-DATA-03:** Prototype data must never be presented as a production security measurement.
- **ADM-DATA-04:** Secondary body text is at least 14px (`0.875rem`); normal body text is 14–16px, with accessible contrast.

## Current implementation status

Implemented: separate login endpoints and session audiences; three-role validation; controlled privileged invitations; administrator identity controls; quarantine-first upload authorization; durable upload, file-version, access-grant, retention, legal-hold, deletion-operation, and recovery-drill metadata; AES-256-GCM per-version encryption with random DEKs/nonces; wrapped DEKs behind a replaceable key-provider interface; authenticated owner download; restart recovery; quota enforcement; protected ciphertext capacity accounting and database-to-disk reconciliation; scheduled cryptographic deletion; runtime, resource, lifecycle, security, and audit dashboards; a durable HMAC audit chain; a separately keyed append-only development anchor; and a provider-neutral remote immutable-ledger client with server-attested receipt verification. Privileged identities cannot enter user workspaces or access plaintext. High-risk privileged mutations require CSRF protection plus session-bound password-and-fresh-TOTP step-up authorization, and download authorization uses the authenticated standard-user owner plus authoritative `stored` state.

Transactional outbox evidence is now implemented for privileged invitations, administrator account-status changes, targeted session revocation, owner-quota changes, retention, legal holds, Trash transitions, direct cryptographic deletion, sharing/revocation, and version restoration. The protected mutation and sanitized audit intent commit together; signed-chain delivery is idempotent and retried from durable pending evidence.

The same boundary now covers privileged invitation activation, quarantine completion, inspection start/result, protection start/result, startup ingestion recovery failure, scheduled per-file deletion outcomes, and recovery-drill evidence. Policy-blocked Trash and permanent-deletion attempts also append normalized denied audit events without exposing file content, filenames, encryption material, or storage paths. Approved purge derives its deletion-operation and audit-event identities from the same opaque owner/file/idempotency digest, so a completed retry cannot repeat key destruction or create duplicate audit evidence in either PostgreSQL or the in-memory development repository. Ingestion uses explicit recoverable intermediate states because encrypted storage, catalog metadata, and lifecycle metadata span more than one repository; no download authorization treats an intermediate state as stored.

Pending backend integrations: deployment of an independently hosted immutable checkpoint ledger using the prepared anchor contract, deployment of a provider-specific managed KMS/HSM plus the prepared private key broker, deployment of the prepared external metrics collector plus an approved alert-routing destination, and deployment of the prepared ClamAV service using an approved supported image. The audit-anchor client provides mTLS, strict bounded receipts, Ed25519 public-key verification, truthful posture, lag metrics, critical alerts, deployment validation, incident procedures, and fail-closed tests; actual ledger resources, receipt signing key, certificates, workload grants, immutable retention, provider-native logs, and independent ownership remain deployment inputs. Controlled privileged invitation provisioning, TOTP MFA, timed account lockout, session-bound step-up authorization, metadata-only protected capacity reconciliation, cross-process owner/global capacity reservations, signed checkpoint anchoring, versioned audit/envelope keyrings, bounded durable DEK rewrapping, a fail-closed ClamD `INSTREAM` adapter with per-scan signature-age enforcement, administrator-reviewed orphan deletion, and a dedicated-bearer Prometheus exporter with truthful recent-scrape evidence are implemented. A provider-neutral mutual-TLS key-service client, strict minimal broker contract, exact key/version/purpose binding, hardware-custody posture, metrics, alerts, deployment validator, rotation policy, compromise procedure, and fail-closed tests are implemented; actual non-exportable keys, HSM policy, certificates, workload grants, provider-native audit destination, and private network remain deployment inputs. A private-network ClamAV/FreshClam deployment package, hourly persistent signature updates, reload notification, UTC freshness policy, validator, and operations runbook are implemented but require an approved image digest and deployment environment. A certificate-verifying Prometheus template, eighteen bounded alert rules, executable rule tests, and a safe incident-response runbook are also implemented; production DNS, certificates, retention, collector runtime, and notification receivers remain deployment inputs. Capacity admission requires an exact declared size, preserves a configurable safety reserve, and releases durable reservations only after terminal metadata is committed. Orphan cleanup uses opaque selection tokens, a one-hour safety window, last-moment metadata/file revalidation, a durable reconciliation journal, transactional outbox evidence, and automatic recovery of previously authorized work; it never accepts a path or autonomously selects an object for deletion. Scanner posture distinguishes the deterministic development adapter from live daemon plus engine/database/timestamp evidence and never exposes the daemon address or raw responses. Key-service and audit-anchor posture distinguish local development adapters from independently verified production custody and never expose endpoints, certificates, credentials, key material, receipt signing secrets, event contents, or provider diagnostics. Telemetry labels are bounded to safe route templates and aggregate operational state; identities, resource identifiers, filenames, paths, credentials, tokens, content, raw addresses, and error text are prohibited. External backups and disaster recovery are separately deferred to deployment hardening and are not part of the current implementation scope.

The currently specified durable state-changing administrator and file workflows have crossed the transactional outbox boundary. Deployment review must repeat this analysis whenever a new mutation, external provider, or repository is introduced.
