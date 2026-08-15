# Testing Strategy

## Principles

Tests trace to requirement IDs, exercise secure failures as well as happy paths, and use harmless synthetic fixtures. Dynamic execution of uploaded files is prohibited. Real malware is not required; use standard anti-malware test strings only when the configured scanner explicitly supports safe testing.

## Test layers

- Unit tests: state transitions, canonical encoding, policy predicates, AAD construction, envelope validation, HMAC chaining.
- Property/fuzz tests: parsers, filenames/metadata, lifecycle event sequences, envelope decoding, audit-event encoding, authorization invariants.
- Integration tests: quarantine-to-storage workflow, scanner/SCA adapter error modes, persistence transactions, key wrapping, revocation, restoration.
- End-to-end tests: authenticated upload, policy decision, download/share/revoke, audit verification, version restore.
- Security tests: IDOR, mass assignment, malformed inputs, tampering, replay/idempotency, resource exhaustion, and secret leakage.
- Performance tests: bounded upload, encryption, inspection, audit append, download, and restore latency/throughput under stated local conditions.

## Core scenarios

| Test | Expected result | Requirements |
|---|---|---|
| Upload allowed synthetic file | quarantined, inspected, encrypted, stored; plaintext cleaned | SR-ING-01..04, SR-CRYPTO-01..04 |
| Request quarantine object | denied regardless of owner or guessed ID | SR-ING-01, SR-AUTHZ-04 |
| Extension/MIME mismatch | content-based policy decides; evidence recorded | SR-INPUT-02, SR-ING-03 |
| Scanner timeout/error | file never becomes accepted/stored | SR-ING-04 |
| Applicable dependency artifact | SCA outcome recorded independently when enabled | SR-ING-05 |
| Ciphertext/envelope/AAD mutation | no plaintext; safe error and audit event | SR-CRYPTO-03..05 |
| Cross-user guessed ID | consistent denial without existence leak | SR-AUTHZ-01, SR-AUTHZ-04 |
| Revoke then access | next request denied and revocation audited | SR-AUTHZ-03, SR-AUD-01 |
| Edit/delete/reorder audit event | verification fails at/after mutation | SR-AUD-02..03 |
| Truncate log before checkpoint | checkpoint mismatch detected | SR-AUD-03 |
| Repeat identical plaintext upload | distinct ciphertext and version key material | SR-CRYPTO-01..02 |
| Mutate ciphertext or authenticated envelope metadata | no plaintext; safe integrity failure | SR-CRYPTO-03..05 |
| Guess another owner's stored upload ID | generic denial without plaintext or existence disclosure | SR-AUTHZ-01..04 |
| Restore valid prior version | new immutable current version with lineage | SR-REC-01..04 |
| Restore corrupt/unauthorized version | current good version unchanged | SR-REC-01..03, SR-REC-05 |
| Oversized/slow/concurrent upload | bounded rejection without exhausted service | SR-INPUT-01 |
| Duplicate finalize/restore | one logical effect | lifecycle/recovery idempotency |
| Admin account at standard login | generic credential denial; no session | ADM-AUTH-02, ADM-AUTH-08 |
| User account at privileged login | generic credential denial; no session | ADM-AUTH-03, ADM-AUTH-08 |
| Promote account with active user session | existing session revoked; privileged login required | ADM-AUTH-05, ADM-AUTH-07 |
| Administrator targets their own status or active sessions | HTTP 409 `SELF_MANAGEMENT_PROHIBITED`; session and role remain unchanged; denied action is audited | ADM-AUTH-15, SR-AUD-01 |
| Privileged session calls file API | denied before file processing | ADM-AUTH-06 |
| Admin requests user content | metadata only; no plaintext or decryption authority | ADM-BOUNDARY-02..04 |
| Scheduled purge retry | one deletion operation identity; attempts recorded; completed work not repeated | lifecycle idempotency |
| Owner retries an approved cryptographic deletion with the same idempotency key | same tombstone and audit event identities; no repeated key destruction, ciphertext cleanup, or signed-chain event | lifecycle idempotency, SR-AUD-01 |
| Owner Trash attempt blocked by retention or legal hold | HTTP 409 safe policy denial; file remains active/readable and a normalized denied event enters the audit chain | data protection and lifecycle management, SR-AUD-01 |
| Retained or held file already in Trash reaches purge time | wrapped key and ciphertext remain intact; purge proceeds only after every policy gate permits it | data protection and lifecycle management, SR-CRYPTO-05 |
| Recovery drill on valid encrypted version | verified evidence stored; no plaintext in admin response | SR-REC-01..05 |
| Recovery drill on corrupt encrypted version | failure evidence and audit event; no plaintext | SR-CRYPTO-03..05 |
| Backup provider absent | UI/API explicitly report not configured and not production-ready | operational truthfulness |
| Privileged password accepted | short-lived single-use MFA transaction; no session cookie | ADM-AUTH-10 |
| First privileged MFA login | encrypted TOTP enrollment, ten one-time recovery codes, privileged session only after verification | ADM-AUTH-10 |
| Reuse TOTP step or recovery code | denied without a privileged session | ADM-AUTH-10 |
| Five account failures in policy window | timed lock persisted and existing sessions revoked; response remains generic | ADM-AUTH-11 |
| Authentication burst from one network source | endpoint-scoped HTTP 429 with Retry-After; other auth scopes remain independent | ADM-AUTH-11 |
| High-risk admin mutation without step-up proof | HTTP 428 denial before the mutation is evaluated | ADM-AUTH-12 |
| Step-up with password and fresh TOTP | opaque five-minute proof authorizes the requested high-risk mutation | ADM-AUTH-12 |
| Reuse step-up proof in another session or after expiry | denied; proof remains bound to its originating privileged session | ADM-AUTH-12 |
| Step-up using a recovery code | denied; recovery codes restore login access but cannot authorize high-risk mutations | ADM-AUTH-12 |
| Invite privileged identity without step-up | HTTP 428 denial; no invitation is created | ADM-AUTH-12..13 |
| Accept administrator/auditor invitation | separate verified identity created; no session; first login requires TOTP enrollment | ADM-AUTH-13..14 |
| Reuse or expire privileged invitation | generic denial and no account creation | ADM-AUTH-13 |
| Privileged identity attempts standard login | generic credential denial | ADM-AUTH-02, ADM-AUTH-14 |
| Authenticated auditor reads governance endpoints | safe resource, security, monitoring, lifecycle, and audit evidence returned; identity directory remains administrator-only | ADM-AUTH-14, ADM-BOUNDARY-01..04 |
| Authenticated auditor submits administrator mutation with valid CSRF | HTTP 403 `ADMINISTRATOR_REQUIRED`; no policy or resource state changes | ADM-AUTH-14, ADM-BOUNDARY-01 |
| Protected capacity reconciliation | ciphertext bytes are measured from disk; tracked, orphaned, and missing objects are reported without decryption | ADM-DATA-01..03 |
| Administrator orphan reconciliation | tracked/fresh/symlink-like objects are excluded; stale preview and last-moment metadata matches fail closed; authorization and completion are journaled atomically with outbox evidence | ADM-DATA-01..03, SR-AUDIT-01 |
| Reconciliation crash recovery | authorized work is idempotent; deletion-before-completion is repaired; newly tracked/changed objects are retained; transient errors remain pending | ADM-DATA-01..03, SR-AUDIT-05 |
| Hosting volume below ten percent available | high-severity capacity alert is returned without exposing a filesystem path | resource and capacity management |
| Concurrent capacity admission across managers/processes | PostgreSQL advisory-lock transaction admits only bytes that fit both owner quota and usable global pool | resource and capacity management |
| Restore organization quota default | audited override deletion survives restart, removes the account from the override inventory, and subsequent reservations use the current organization default | resource and capacity management |
| Declared upload size differs from streamed bytes | request fails, partial quarantine data and metadata are removed, and reservation is released | T-05 |
| Crash during request reception | zero-byte pre-commit row is failed and partial object/reservation are removed before inspection | T-05 |
| Metrics request without the dedicated bearer | HTTP 401 when enabled; no metrics payload or browser-session fallback | SR-OBS-01 |
| HTTP request containing a resource identifier | exported label contains only the registered route template; identifier and token are absent | SR-OBS-02 |
| Exporter enabled without a recent scrape | monitoring reports exporter enabled but external telemetry not connected; authenticated scrape connects until stale | SR-OBS-03..04 |
| Prometheus deployment template | structural validator rejects plaintext scraping, inline bearer credentials, missing CA/name verification, or disabled TLS verification | SR-OBS-05 |
| Monitoring alert catalog | `promtool check rules` validates all rules; executable rule tests verify hold periods, critical missing-object detection, and capacity accounting outside the safety reserve | SR-OBS-06 |
| Signed checkpoint agrees with PostgreSQL | audit page reports the exact latest anchored sequence and valid signature | SR-AUD-03 |
| Anchor evidence edited, unavailable, stale, or mismatched | critical anchor alert; interface does not claim independent assurance | SR-AUD-03 |
| Remote receipt signed by an untrusted key or containing unknown/mismatched fields | fail closed without accepting the checkpoint | SR-AUD-07 |
| Remote anchor reports mutable, shared-administration, or non-attested posture | production readiness remains false | SR-AUD-06 |
| Verified events exceed the latest trusted receipt | nonzero lag metric and critical alert after the hold period | SR-AUD-08 |
| Signed-chain delivery fails after an atomic administrator mutation | mutation evidence remains pending, retry delivers the stable event once, and monitoring reports the backlog | SR-AUD-05 |
| Protected policy mutation receives invalid audit evidence | file state remains unchanged because the PostgreSQL transaction rolls back | SR-AUD-05 |
| Ingestion transition receives invalid audit evidence | lifecycle status remains at its prior durable state | SR-AUD-05 |
| Privileged activation receives invalid audit evidence | invitation remains unused and no privileged identity is created | ADM-AUTH-13, SR-AUD-05 |
| Recovery drill receives invalid audit evidence | no drill record is committed; valid evidence commits with the drill result | SR-REC-05, SR-AUD-05 |
| Rotate audit key from v1 to v2 | transition is chained under v2 and the mixed-version history verifies after restart | SR-AUD-02..04 |
| Remove a retained audit key | verification fails at the first event requiring that version | SR-AUD-02..04 |
| Rotate local envelope KEK | new wraps use the current version; historical wrapped DEKs remain decryptable only while their version is retained | SR-CRYPTO-02..05 |
| Rewrap protected DEKs | ciphertext is byte-for-byte unchanged; wrapper metadata advances optimistically; the historical wrapping key can be removed after completion; mutation and audit intent are atomic | SR-CRYPTO-02..05, SR-AUDIT-01 |
| Managed key broker round trip | authenticated client contract sends one 32-byte DEK with bounded purpose/key identity; wrap and historical unwrap responses must match the exact requested identity | SR-CRYPTO-06..07 |
| Managed key broker unsafe response | plaintext HTTP, unknown fields, identity mismatch, extra plaintext in a wrap response, malformed/oversized bodies, redirects, and non-success status fail closed without provider error disclosure | SR-CRYPTO-06..07, SR-INPUT-03 |
| Managed key deployment boundary | validator proves remote mode, HTTPS, mounted CA/client identity files, safe key aliases, minimal mutual-TLS OpenAPI surface, and absence of local KEK material | SR-CRYPTO-06..08 |
| Production startup profile | table tests reject missing TLS, insecure cookies/origins, plaintext PostgreSQL, local providers, disabled privileged controls, and `.data` secrets | SR-DEPLOY-01..05 |
| HTTPS response hardening | TLS requests receive HSTS, CSP, frame denial, referrer protection, and MIME protection; development HTTP omits HSTS | SR-DEPLOY-01..02 |
| ClamD stream inspection | exact quarantine bytes use framed bounded chunks; clean and detected responses map to safe decisions; connection, timeout, oversize, malformed, and daemon-error responses fail closed | SR-ING-01..04, SR-INPUT-03 |
| ClamD signature freshness | fresh UTC timestamp permits bounded inspection; stale, missing, malformed, and materially future-dated timestamp evidence fails closed and prevents production-ready posture | SR-ING-07 |
| ClamAV deployment boundary | validator and Compose parser prove no host port publication, persistent shared database, hourly updates, reload notification, signed-only bytecode, bounded streams, and an approved feature-tag requirement | SR-ING-08 |

Backup-provider and disaster-recovery tests are deferred with the corresponding implementation. Until that stage, release verification checks only that every API and UI surface truthfully reports backups as not configured.

## Go-specific assurance

- Run `go test ./...` and `go test -race ./...`.
- Use built-in fuzzing for untrusted decoders and state-machine inputs.
- Run `go vet ./...` and an agreed static security analyzer once the module exists.
- Pin and review dependencies; use `govulncheck` for Go dependency/reachability findings.

The checked-in GitHub Actions workflow applies these gates to every push and pull request targeting `main`. It also runs the nine opt-in PostgreSQL tests and the race-enabled suite against separate disposable PostgreSQL services. See `docs/continuous-integration.md` for job boundaries, pinned dependencies, and branch-protection follow-up.
- SCA of uploaded artifacts is distinct from SCA of the project's own Go dependencies.

## Test data safety

Fixtures contain no secrets or personal data. Test keys are clearly marked and never reused outside tests. Zip/parser-bomb behavior is simulated with bounded fixtures. Any anti-malware test marker is documented, isolated, and never a live malicious binary.

## Evidence and exit criteria

Each security requirement has at least one automated test or a documented manual verification where automation is not practical. A release candidate requires:

- identity-governance tests proving suspension revokes existing sessions, blocks new login with a generic response, supports explicit reactivation, rejects self-management, and reserves automated lockout state
- all mandatory tests passing, including race tests
- no unresolved critical/high findings without written risk acceptance
- demonstrated rejection of tampered ciphertext and audit history
- demonstrated immediate authorization revocation behavior
- successful valid restore and safe failure of corrupt restore
- performance results with file sizes, concurrency, hardware, configuration, and tool versions recorded

Coverage percentage is supporting evidence, not proof of security. Results will be summarized in the final report with requirement IDs and reproducible commands.
