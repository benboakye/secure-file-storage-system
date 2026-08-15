# Administrator end-to-end verification

## Test record

- **Executed:** 2026-08-14, 17:15–17:23 EDT
- **Environment:** local development profile on Windows
- **Frontend:** React/Vite at `http://127.0.0.1:5173`
- **API:** Go service at `http://127.0.0.1:8080`
- **Persistence:** local PostgreSQL on loopback port `55439`
- **Tester context:** an already authenticated administrator session protected by privileged MFA
- **Method:** read-only browser verification, API health checks, server-log review, frontend production build, and the complete Go package test suite

Passwords, session cookies, CSRF values, MFA secrets, TOTP codes, recovery codes, encryption keys, raw IP addresses, plaintext file contents, and database credentials were neither inspected nor recorded.

## Objective

Verify the complete administrator read path:

1. A dedicated privileged identity signs in with password and MFA.
2. The React administrator console calls administrator-only API routes.
3. The API authorizes the privileged session and reads PostgreSQL-backed identity, file, lifecycle, and audit evidence plus safe runtime signals.
4. The UI renders that evidence without permitting user impersonation or exposing file plaintext, authentication material, cryptographic keys, connection strings, or internal filesystem paths.

This run intentionally did not execute administrator mutations such as suspending accounts, revoking sessions, changing quotas, rotating key wrappers, applying legal holds, or permanently deleting data.

## Result summary

| Area | Status | Evidence observed |
| --- | --- | --- |
| Service baseline | PASS | UI and API health checks returned HTTP 200; the API reported PostgreSQL authentication, ingestion, protected-file, and audit repositories ready. |
| Privileged boundary | PASS | The console identified the session as `admin`, displayed a logout control, and exposed no standard-user workspace or impersonation control. |
| Administration overview | PASS | 10 total accounts, 2 administrators, 1 auditor, and 0 pending verifications were rendered from the directory. Each control domain reported `Connected` or a truthful `Partial` state. |
| Identity and access | PASS | 10 PostgreSQL identity records rendered with role, verification, access state, and guarded administrative actions. The current account could not apply controls to itself. |
| Resource and capacity | PASS | 3 durable uploads, 5 protected ciphertext objects totaling 34.0 KB, 28 B quarantine usage, and zero protected-storage discrepancies rendered without opening file contents. |
| Quota and capacity signals | PASS | The view showed a 1.00 GB default user quota, 50.0 GB enforced pool, 5.00 GB safety reserve, 0 active reservations, 0 quota alerts, owner-level usage, and host-volume availability labelled separately. |
| Security and compliance | PASS | Password, verification, opaque-session, CSRF/origin, privileged-boundary, fresh step-up, and privileged TOTP controls rendered as active. The earlier `productionReady` page crash did not reproduce. |
| System monitoring | PASS | API uptime, queue depth, quarantine usage, failures, persistence classes, audit integrity, global policy, security events, and integration states rendered from live signals. |
| Data lifecycle | PASS | 3 active protected files, 0 trashed files, 0 active retention deadlines, 0 legal holds, connected lifecycle controls, and prior recovery evidence rendered. Backup status remained truthfully `Not configured`. |
| Audit trail | PASS | The page verified and anchored an ordered chain through event 122, showed safe event projections and filters, and recorded successful privileged MFA plus this run's privileged reads. Network addresses were represented only as keyed fingerprints. |
| Frontend build | PASS | `npm run build` completed: TypeScript compilation and the Vite production bundle succeeded. |
| Backend test suite | PASS | `npm run test:api` passed all Go packages, including API, audit, authentication, ingestion, orphan reconciliation, and protected storage. |

## Detailed verification notes

### 1. Privileged authentication and separation

The session entered the dedicated administrator console after password and MFA verification. The sidebar showed the privileged role and a logout action. There was no route or action for switching into a user's workspace, and no user impersonation feature was exposed.

The audit view contained separate events for password verification with MFA pending and successful password-plus-MFA completion. Earlier invalid or expired MFA attempts were preserved as denied events. This confirms that privileged authentication decisions are auditable without storing the submitted code in the UI evidence.

### 2. Identity governance

The identity page rendered all 10 durable account records and the three intended roles: `user`, `admin`, and `auditor`. It showed 10 active accounts, 0 suspended accounts, and 2 administrators in the current view. Administrative actions were available for other accounts, while the current privileged account was labelled `Current account` instead of receiving self-suspension or self-revocation controls.

No account mutation was submitted during this run. Those actions require a separate destructive/control-change test plan with dedicated disposable identities.

### 3. Resource and capacity management

The resource inventory displayed only safe metadata: filename, MIME type, truncated owner identifier, lifecycle state, byte size, and creation time. The administrator did not receive a file-open, plaintext-preview, or download action.

The protected-storage reconciliation reported five ciphertext objects, three durable lifecycle records, zero missing tracked objects, and zero protected discrepancies. One 28-byte quarantine object was identified as an orphan candidate; it was not selected or deleted. The delete control remained disabled with zero selected objects.

The quota panel showed both policy and operational signals. Per-owner usage was compared with the 1.00 GB default quota, while the 50.0 GB SecureStore pool and 5.00 GB reserve were distinguished from host-volume usage and availability.

### 4. Security and compliance

The security page rendered successfully and used live server posture. It reported:

- bcrypt cost 12 password protection with SHA-256 password material;
- 30-minute single-use email verification;
- eight-hour opaque server-side sessions;
- CSRF protection and exact-origin checks for state changes;
- separation between privileged and standard-user sessions;
- password plus fresh TOTP proof for high-risk administrator actions;
- a five-minute step-up authorization window;
- privileged TOTP MFA connected;
- tamper-evident audit chaining connected;
- automatic lockout configured at five failures per 15 minutes.

The page also correctly disclosed development limitations: a deterministic scanner rather than a malware signature engine, local file-backed envelope-key custody, a local audit anchor, and no independent immutable anchor or hardware-backed managed key service.

### 5. Monitoring and lifecycle

System monitoring showed the API as operational, PostgreSQL-backed repositories as durable, zero queued or failed processing records, and the audit chain as verified. Development HTTP, localhost cookie policy, absent external telemetry, absent backup monitoring, absent managed key custody, and absent independent audit anchoring were explicitly labelled instead of being represented as production-ready.

Lifecycle management exposed metadata-only controls for retention, legal holds, scheduled deletion evaluation, and recovery verification. It reported no files currently in Trash, no active retention policies, no legal holds, and no permanent-deletion runs. The backup provider remained `Not configured`, matching the decision to defer backup integration and document it as deployment work.

### 6. Audit accountability

The audit UI displayed a verified and locally anchored chain, safe actor/resource projections, outcomes, correlation identifiers, and filter controls. Raw IP addresses were not stored or returned; only keyed network fingerprints appeared. Viewing the audit and monitoring pages generated new privileged-read audit events, demonstrating that administrative observation is itself accountable.

The available CSV export was not triggered because downloading an audit dataset was outside this read-only test's scope.

## Issues and observations

### No blocking application defect found

All administrator read views rendered and returned authoritative data. The historical `SecurityComplianceView` failure caused by missing `productionReady` posture data did not reproduce after the current services started.

### Historical outage evidence

The API error log contains database connection failures from 02:16–02:19 EDT, when PostgreSQL was down. After restart at 17:13 EDT, the current log reports all PostgreSQL repositories ready and the server listening on `127.0.0.1:8080`. The current UI and API health checks returned HTTP 200.

### Browser-extension noise

Chrome emitted context-menu errors about missing `translate-page` and `save-page` menu items. They were generated by browser/extension integration, not by SecureStore application code, and did not affect any tested view.

### Accessibility follow-up

The administrator navigation should receive a dedicated keyboard and screen-reader pass. This functional run verified readable DOM content and semantic headings/controls, but it did not certify focus order, visible focus styling, reduced motion, contrast ratios, or every responsive breakpoint.

## Current development-only boundaries

This result confirms local-development behavior, not production readiness. Before production, the project still needs:

- a real ClamAV/ClamD malware scanning service with freshness evidence;
- managed hardware-backed KMS/HSM key custody;
- an independently administered immutable audit anchor;
- external telemetry collection and alert routing;
- a deployment backup provider plus backup-health monitoring and recovery drills;
- HTTPS, secure cookies, approved origins, and production secret injection;
- SMTP or another production email-delivery provider if verification messages must reach external inboxes.

## Follow-up controlled identity test — 2026-08-15

The identity-governance mutation path was tested with the retained synthetic account `local-e2e-recipient-20260814-01@example.test`. The administrator completed password-and-TOTP step-up privately; no credential or authenticator value was inspected or recorded.

| Action | Authoritative result | Audit evidence | Final state |
| --- | --- | --- | --- |
| Revoke sessions | The UI reported that all sessions for the synthetic account were revoked. | Event `#124`, `USER_SESSIONS_REVOKED`, `success`. | Account remained `active`. |
| Suspend account | PostgreSQL changed `account_status` to `suspended`. | Event `#126`, `ACCOUNT_STATUS_UPDATED`, `success`, target state `suspended`. | Sign-in and existing sessions were denied. |
| Reactivate account | PostgreSQL changed `account_status` back to `active`. | Event `#128`, `ACCOUNT_STATUS_UPDATED`, `success`, target state `active`. | Original usable state restored. |

This confirms the UI-to-API-to-PostgreSQL mutation path and transactional audit delivery. The test did not delete the account or its files. Reactivation does not recreate previously revoked sessions; the user must authenticate again.

## Quota test precondition defect and correction — 2026-08-15

The quota-enforcement test stopped before any mutation because the administrator's eight-hour server session had expired. PostgreSQL confirmed that the intended synthetic target remained active and had no quota override.

The API correctly returned HTTP 401 with the safe message `Sign in to continue.` However, the React client retained its stale privileged `session` state, continued rendering the administrator shell, and displayed the API error inside the Resource metadata view. Navigating to `#admin-signin` was redirected back to `#admin-dashboard` because the stale client state still represented the administrator as authenticated.

**Initial status:** FAIL at the response-to-UI boundary. No quota was changed and no upload was attempted.

**Correction implemented:** HTTP 401 handling is now centralized in the API client. When an authenticated API call receives `AUTHENTICATION_REQUIRED`, the client clears its in-memory CSRF and step-up values and notifies the React session owner. React then clears the stale session and applies the existing role-bound route guard. Expected authentication failures such as `INVALID_CREDENTIALS`, `MFA_INVALID`, and `STEP_UP_FAILED` do not trigger global session expiry.

**Regression result:** PASS. Three focused frontend tests confirmed expiry notification and credential clearing, exclusion of expected login/MFA/step-up failures, and safe listener unsubscription. The production frontend build and the complete Go API test suite also passed. In a live Chrome regression, reopening `#admin-dashboard` with the expired privileged session produced `#admin-signin`, rendered the dedicated privileged sign-in form, and did not render the administrator shell.

## Controlled quota-enforcement test — 2026-08-15

The administrator applied a temporary 1 MB quota to the verified disposable account `quota-live-1786772699752@example.test`. A separate Chrome session authenticated as that standard user, preserving the privileged and standard-user audience boundary. The selected fixture was a generated, non-personal Go build-cache artifact of 1,063,438 bytes, which exceeded the enforced 1,048,576-byte account quota.

| Boundary | Result | Evidence |
| --- | --- | --- |
| Administrator policy | PASS | Resource metadata displayed `1.00 MB override` only after password-and-fresh-TOTP step-up authorization. |
| Upload admission | PASS | The standard-user UI returned `This upload would exceed the account storage quota.` and remained on the upload page. |
| Lifecycle metadata | PASS | Tracked uploads remained 3; no denied-upload lifecycle record was retained. |
| Capacity reservation | PASS | Active reservations remained 0 and reserved bytes remained 0 B. |
| Quarantine | PASS | Quarantine usage remained 28 B; the rejected admission created no quarantine object. |
| Protected storage | PASS | Protected ciphertext remained 34.0 KB across five objects. |
| Cleanup | PASS | Both temporary overrides were removed, so the affected accounts again inherit the 1.00 GB organization default. |
| Audit accountability | PASS | Events `#143` and `#144` record successful `OWNER_QUOTA_UPDATED` actions with reason `Organization Default Restored`. |

Cleanup exposed a missing product control: the original UI could replace an override but could not remove it. Setting an override equal to the current default would not be equivalent because future organization-default changes would not propagate to that account. A server-enforced `DELETE /api/v1/admin/resources/owners/{ownerId}/quota` action and **Use default** UI control were therefore added. The PostgreSQL override deletion and sanitized audit intent commit in one transaction, and the in-memory policy cache is cleared only after repository success.

The earlier disposable account `quota-e2e-1786772428327@example.test` could not be used because its randomly generated password existed only in volatile test memory and was lost when the browser-control session reset. Its password hash was not bypassed or modified directly. The verified account was suspended through the normal administrator control; audit event `#145` records the successful status change. The usable `Quota Live Test` account remains active for future controlled tests.

## Auditor authorization-boundary test — 2026-08-15

A dedicated disposable auditor identity was created through the controlled privileged-invitation flow. The invitation produced a separate verified identity and did not create a session. Chrome then completed the dedicated privileged password and TOTP flow. The authenticated sidebar identified `Auditor Boundary Test` with role `auditor`; it did not expose the standard-user workspace or the administrator-only **Identity & access** navigation item.

| Boundary | Result | Evidence |
| --- | --- | --- |
| Privileged identity separation | PASS | The auditor used a separate account, privileged sign-in route, and MFA flow. It did not reuse the active administrator identity or a standard-user session. |
| Compliance overview | PASS | The dashboard rendered **Compliance overview** and an **Auditor scope** notice instead of administrator identity statistics and account-management controls. |
| Resource metadata | PASS | Runtime inventory, capacity, quota signals, and protected-storage discrepancies were readable. Quota-edit and orphan-deletion actions were absent. |
| Security and compliance | PASS | MFA, cryptographic, scanner, and audit-integrity evidence was readable. Key-rotation controls were absent and the page disclosed the auditor's read-only scope. |
| System monitoring | PASS | Runtime health, persistence, policies, and integration status were readable with no restart, reset, or configuration mutation controls. |
| Data lifecycle | PASS | Retention, legal-hold, deletion, and recovery evidence was readable. All corresponding mutation controls were absent and an auditor read-only notice was rendered. |
| Audit trail | PASS | Safe event projections, chain integrity, pagination, and filters were readable. The **Clear** action only resets client-side filters and does not alter authoritative audit records. |
| Administrator identity directory | PASS | The navigation item was absent, and a direct API request received HTTP 403 with `ADMINISTRATOR_REQUIRED`. |
| Direct mutation attempt | PASS | A valid auditor session and CSRF token could not set an owner quota; the API returned HTTP 403 with `ADMINISTRATOR_REQUIRED`. |

The API denial is covered by `TestAuditorCanReadGovernanceButCannotUseAdministratorControls`. The test deliberately supplies a valid authenticated auditor session and valid CSRF token so the result proves server-side role authorization rather than relying on hidden UI controls. The complete Go suite, focused frontend suite, and production frontend build passed after adding this coverage.

## Administrator step-up rejection test — 2026-08-15

High-risk administrator authorization was expanded with explicit negative coverage. The API test uses an authenticated administrator session and valid CSRF token, ensuring requests reach the step-up boundary instead of failing at an earlier authentication or request-forgery control.

| Condition | Result | Authoritative behavior |
| --- | --- | --- |
| Missing step-up proof | PASS | The high-risk mutation stopped with HTTP 428 and `STEP_UP_REQUIRED`. |
| Invalid opaque proof | PASS | The same mutation stopped with HTTP 428 and `STEP_UP_REQUIRED`. |
| Incorrect administrator password | PASS | No proof was issued; the authentication store returned the generic step-up denial. |
| Incorrect TOTP | PASS | No proof was issued and the failed authentication counter was updated. |
| Replayed TOTP counter | PASS | A code already used to issue a proof could not issue another proof. |
| Proof copied to another privileged session | PASS | The proof remained bound to its originating opaque session and was rejected elsewhere. |
| Expired proof | PASS | Validation failed after the five-minute authorization window. |

`TestAdministratorMutationRejectsMissingAndInvalidStepUpProof` verifies the HTTP boundary. `TestAdministratorStepUpProofRejectsInvalidAndReplayedAuthentication` verifies password/TOTP rejection, TOTP-counter advancement, session binding, and expiry. The API test uses administrator self-suspension as a fail-safe target: if the step-up boundary ever failed unexpectedly, the independent self-management rule would still reject the state change.

The live administrator page was reloaded before attempting to open the step-up dialog, which cleared any in-memory five-minute proof. Browser inspection then timed out while the dialog was opening, so no live-dialog PASS is claimed and no password, TOTP, or authorization form was submitted. This tooling interruption does not replace or weaken the server-level results above. The complete Go suite, focused frontend tests, and production frontend build passed.

## Retention and legal-hold enforcement test — 2026-08-15

The lifecycle boundary was tested end to end in an isolated local API server using two generated text fixtures. The fixtures were created inside temporary test storage and were not copied from a user or developer workspace. A separate standard-user owner uploaded both files, and a separate administrator applied a future retention deadline to one and a legal hold to the other.

| Boundary | Result | Evidence |
| --- | --- | --- |
| Retention blocks Trash | PASS | The owner received HTTP 409 with `RETENTION_ACTIVE`; the file remained in the active catalog. |
| Legal hold blocks Trash | PASS | The owner received HTTP 409 with `LEGAL_HOLD_ACTIVE`; the file remained in the active catalog. |
| Access after blocked transition | PASS | Both files remained readable by their authenticated owner because no Trash transition committed. |
| Retention blocks permanent deletion | PASS | A retained file already in Trash could not destroy wrapped keys or ciphertext after the ordinary deletion grace period elapsed. |
| Legal hold blocks permanent deletion | PASS | A held file already in Trash could not destroy wrapped keys or ciphertext after retention and grace-period gates otherwise permitted deletion. |
| Forward-only retention | PASS | Active retention was extended rather than removed or shortened during the purge test. |
| Denied-attempt accountability | PASS | The audit chain recorded separate denied `FILE_MOVED_TO_TRASH` events with `retention_active` and `legal_hold_active` reason codes. |
| Final allowed deletion and retry | PASS | Only after the policy gates were no longer active did cryptographic purge destroy the wrapped key and remove ciphertext; a retry returned the same operation identity. |

The HTTP handlers now append a safe denied audit event when Trash or permanent-deletion requests fail a lifecycle gate. The event contains the authenticated actor, opaque file identifier, normalized reason, correlation identifier, and resulting safe state; it does not include file content, filename, encryption material, or a filesystem location.

`TestRetentionAndLegalHoldBlockOwnerTrashAndCreateDeniedAuditEvidence` covers the owner-to-API-to-protected-storage-to-audit path. `TestTrashRetentionHoldRestoreAndCryptographicPurge` covers post-Trash retention, post-Trash legal hold, grace-period enforcement, wrapped-key destruction, ciphertext cleanup, and idempotent retry. The complete Go suite, focused frontend suite, and production frontend build passed.

## Approved cryptographic-deletion and retry test — 2026-08-15

Successful deletion was tested through an isolated local API server using one generated text fixture and a deterministic protected-storage lifecycle clock. The owner completed the normal active-to-Trash transition, the test advanced only the disposable file's lifecycle clock beyond its recovery deadline, and the owner submitted the same permanent-deletion request twice with one idempotency key.

| Boundary | Result | Evidence |
| --- | --- | --- |
| Eligibility | PASS | Purge ran only after the file was in Trash, its recovery deadline had elapsed, and no retention or legal hold applied. |
| Stable operation identity | PASS | The initial request and retry returned the same opaque deletion operation ID and file ID. |
| Wrapped-key destruction | PASS | The operation reported one destroyed wrapped DEK and the durable deletion tombstone preserved that count. |
| Ciphertext cleanup | PASS | Protected-storage verification confirmed the ciphertext object was removed after key destruction. |
| Access revocation | PASS | The file disappeared from active files and Trash, and its plaintext endpoint returned the safe not-found response. |
| Durable tombstone | PASS | Lifecycle evidence contained one completed operation, one attempt, one destroyed key, and a completion timestamp. |
| Audit exactly once | PASS | The retry produced one successful `FILE_CRYPTOGRAPHICALLY_DELETED` event with reason `wrapped_keys_destroyed` and state `purged`; the signed chain remained valid. |
| Retry safety | PASS | Repeating the completed operation did not repeat key destruction, create another tombstone, or append another audit fact. |

The test exposed and corrected a development-path inconsistency: purge operation IDs were already deterministic, but the API originally generated a new random audit intent ID for every retry. PostgreSQL uniqueness and outbox delivery prevented duplicate durable events, while the in-memory development repository could append both. `PurgeOperationIDs` now derives the tombstone and audit event IDs from the same owner/file/idempotency tuple, and the in-memory audit repository mirrors PostgreSQL's event-ID idempotency. The digest is opaque and does not reveal file content, names, keys, or paths.

`TestApprovedCryptographicDeletionIsIdempotentAndAuditedOnce` verifies the complete owner-to-API-to-protected-storage-to-lifecycle-evidence-to-audit path. The existing storage test independently verifies wrapped-key removal and filesystem ciphertext cleanup. The complete Go suite, focused frontend suite, and production frontend build passed.

## Administrator self-management prohibition test — 2026-08-15

The active administrator identity was used as the target of direct status-change and session-revocation requests in the isolated API test. Each request included a valid privileged session and CSRF token, ensuring the result came from the self-management authorization rule rather than an earlier authentication failure.

| Boundary | Result | Evidence |
| --- | --- | --- |
| Self-suspension | PASS | The API returned HTTP 409 with `SELF_MANAGEMENT_PROHIBITED`; account status remained unchanged. |
| Self-session revocation | PASS | The API returned HTTP 409 with `SELF_MANAGEMENT_PROHIBITED`; the active privileged session was not deleted. |
| Session survival | PASS | A subsequent `/api/v1/session` request returned the same administrator ID and `admin` role. |
| UI prevention | PASS | The current-account policy returns false for self-targeting, and the directory renders **Current account** instead of **Suspend**, **Reactivate**, or **Revoke sessions** controls. |
| Fail-closed UI context | PASS | Empty or incomplete actor/target identity context does not expose account-management controls. |
| Denied-attempt accountability | PASS | Separate denied `ACCOUNT_STATUS_UPDATED` and `USER_SESSIONS_REVOKED` events were added with reason `self_management_prohibited`; the audit chain remained valid. |

The API remains authoritative if a client bypasses the interface. The UI decision now uses the tested `canManageIdentity` policy instead of an untested inline comparison. This is defense in depth: the server rejects self-management independently of what the browser renders.

The complete Go suite, six focused frontend tests, and production frontend build passed.

## Next test stage

The controlled administrator-action series is complete. Its planned cases were:

1. ~~confirm through a dedicated negative test that an administrator cannot suspend or revoke their own active session~~ — completed with direct API, session-survival, UI-policy, and denied-audit tests;
2. ~~enforce a temporary quota override through the upload admission path and restore the default~~ — completed with auditable cleanup;
3. ~~verify that auditor sessions can read governance evidence but cannot submit mutations~~ — completed through live UI verification and a direct API negative test;
4. ~~verify that high-risk administrator actions reject missing, stale, replayed, or incorrect step-up proof~~ — completed with API and authentication-store negative tests;
5. ~~verify that retention and legal holds prevent deletion as designed~~ — completed with isolated API and protected-storage lifecycle tests plus denied audit evidence;
6. ~~verify that approved lifecycle deletion is idempotent and produces complete audit evidence~~ — completed with stable operation/audit identity, durable tombstone, key destruction, ciphertext cleanup, access denial, and safe retry coverage.

All destructive lifecycle cases used generated disposable records in isolated temporary storage. The next stage should consolidate release-readiness evidence: race detection, static analysis, dependency vulnerability review, and a final requirement-to-test traceability pass before deployment integrations are configured.
