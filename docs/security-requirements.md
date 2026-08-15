# Security Requirements

`MUST` statements are release-blocking acceptance criteria for the prototype. Each identifier should map to design, code, automated tests, and demonstration evidence.

## Identity and request handling

- **SR-AUTHN-01:** The system MUST authenticate every non-public operation and reject expired, invalid, or disabled identities.
- **SR-AUTHN-02:** Authentication secrets MUST use an established password-hashing or token-validation library and MUST NOT be logged.
- **SR-INPUT-01:** The API MUST enforce configured request, file-size, filename-length, metadata, duration, and concurrency limits while streaming uploads.
- **SR-INPUT-02:** Server-generated identifiers MUST determine storage locations; client paths and lifecycle fields MUST NOT be trusted.
- **SR-INPUT-03:** Errors MUST avoid exposing secrets, internal paths, file existence across authorization boundaries, or scanner internals.

## Ingestion and inspection

- **SR-ING-01:** Every upload MUST enter quarantine before inspection and MUST be unavailable through retrieval interfaces.
- **SR-ING-02:** Inspection MUST use the exact quarantined bytes identified by a cryptographic digest.
- **SR-ING-03:** Static inspection MUST include content-type identification and configured signature/policy checks without executing uploaded content.
- **SR-ING-04:** Scanner failure, timeout, malformed output, or missing required evidence MUST result in a non-accepted state.
- **SR-ING-05:** SCA MAY run only for supported software artifacts and MUST record its tool/version and policy result separately from malware inspection.
- **SR-ING-06:** Rejected content MUST remain inaccessible and follow an explicit retention/deletion policy.
- **SR-ING-07:** Production ClamD inspection MUST require a safely parsed database timestamp no older than the configured maximum; missing, stale, malformed, or materially future-dated timestamp evidence MUST fail closed.
- **SR-ING-08:** ClamD MUST be isolated from public ingress, receive only bounded `INSTREAM` bytes, and share its persistent database only with an approved FreshClam updater that performs verified periodic updates and daemon reload notification.

## Cryptography and storage

- **SR-CRYPTO-01:** Each accepted file version MUST be encrypted with AES-256-GCM using a fresh randomly generated 256-bit DEK.
- **SR-CRYPTO-02:** Each encryption under a DEK MUST use a unique nonce generated with a cryptographically secure source.
- **SR-CRYPTO-03:** Security-critical immutable metadata MUST be authenticated as AAD, including schema, file ID, version ID, owner ID, and algorithm version.
- **SR-CRYPTO-04:** DEKs MUST be stored only in wrapped form; KEKs MUST be accessed through a replaceable key interface and MUST NOT be stored beside ciphertext in plaintext.
- **SR-CRYPTO-05:** Authentication-tag or envelope validation failure MUST return no plaintext and MUST produce a security audit event.
- **SR-CRYPTO-06:** Production KEKs MUST remain non-exportable in an approved managed KMS/HSM boundary; SecureStore MUST authenticate with a workload identity over certificate-verified mutual TLS and MUST NOT load a plaintext KEK.
- **SR-CRYPTO-07:** Remote wrap, unwrap, and status responses MUST be bounded, strictly decoded, bound to the exact key ID/version and envelope purpose, and fail closed without provider diagnostics or local-key fallback.
- **SR-CRYPTO-08:** Historical KEK versions MUST remain available until durable wrapper posture reaches zero pending versions and controlled recovery succeeds; destructive retirement MUST account for retention, legal holds, incidents, and external backups.
- **SR-STOR-01:** Stored versions MUST be immutable and associated with authoritative metadata and inspection evidence.
- **SR-STOR-02:** Plaintext temporary data MUST be access-restricted, bounded, and removed after all terminal outcomes and crash reconciliation.

## Authorization

- **SR-AUTHZ-01:** Every read, write, share, revoke, delete, audit, and restore operation MUST call centralized authorization using authenticated identity and authoritative resource state.
- **SR-AUTHZ-02:** Policies MUST deny by default and prevent ownership, role, grant, or lifecycle changes through client-controlled fields.
- **SR-AUTHZ-03:** A revoked grant MUST cease authorizing new requests immediately; any cache MUST not extend access beyond its defined invalidation bound.
- **SR-AUTHZ-04:** Knowledge of a file, version, or object identifier MUST NOT confer access.
- **SR-AUTHZ-05:** Administrative capability MUST be explicit, least-privileged, and audited; administrators MUST not automatically receive file plaintext access unless policy grants it.

## Audit

- **SR-AUD-01:** Security-relevant attempts and outcomes MUST be recorded with sequence, UTC timestamp, actor, action, resource, outcome, reason code, and correlation ID.
- **SR-AUD-02:** Each event MUST use canonical encoding and an HMAC that binds the previous event MAC and current event data.
- **SR-AUD-03:** Audit verification MUST detect edited, deleted, inserted, reordered, or truncated events when checked against a trusted checkpoint.
- **SR-AUD-04:** Audit events MUST NOT contain credentials, keys, plaintext content, or unnecessary sensitive metadata.
- **SR-AUD-05:** If a required audit append fails, sensitive state-changing operations MUST fail closed or enter an explicitly recoverable state.
- **SR-AUD-06:** Production checkpoints MUST be retained by an independently administered immutable service that application and database administrators cannot rewrite.
- **SR-AUD-07:** Remote checkpoint operations MUST use mutually authenticated TLS and return a server-attested receipt verifiable without loading the service signing key into SecureStore.
- **SR-AUD-08:** Anchor unavailability, invalid receipts, checkpoint mismatch, and anchoring lag MUST be visible through administrator posture and critical operational alerts.

## Observability

- **SR-OBS-01:** Machine-readable telemetry MUST require a dedicated secret and MUST NOT accept an interactive browser session as collector authorization.
- **SR-OBS-02:** Metric names and labels MUST be bounded and MUST NOT contain identity data, resource identifiers, filenames, paths, credentials, tokens, raw addresses, content, or error text.
- **SR-OBS-03:** Monitoring MUST distinguish an enabled exporter from evidence of a recent successful collector scrape.
- **SR-OBS-04:** Unauthorized or failed scrape attempts MUST NOT refresh external-telemetry connection evidence.
- **SR-OBS-05:** Production collection MUST use certificate-verified TLS, a file-mounted dedicated bearer, and a management-network path that is not exposed through public ingress.
- **SR-OBS-06:** Alert rules MUST use aggregate safe metrics, apply a bounded hold period, declare severity and ownership, and reference a response runbook that prohibits sensitive data in notifications.

## Deployment boundary

- **SR-DEPLOY-01:** Production startup MUST fail when an HTTPS certificate/private key is absent or session cookies are not Secure, HttpOnly, and SameSite=Strict.
- **SR-DEPLOY-02:** Production public URLs and browser origins MUST use exact HTTPS origins, and HTTPS responses MUST emit HSTS and approved browser-hardening headers.
- **SR-DEPLOY-03:** Production PostgreSQL transport MUST verify both certificate authority and server identity with `sslmode=verify-full`.
- **SR-DEPLOY-04:** Production MUST select approved remote scanner, key-custody, and audit-anchor boundaries and MUST keep privileged MFA and administrator step-up enabled.
- **SR-DEPLOY-05:** Production core secrets MUST be injected or externally mounted; startup MUST NOT create or consume `.data` secret files.

## Recovery

- **SR-REC-01:** Restore MUST require explicit authorization for the target file and source version.
- **SR-REC-02:** Restore MUST verify metadata consistency, manifest/digest, key unwrap, AES-GCM authentication, and lifecycle eligibility before making data current.
- **SR-REC-03:** Restore MUST stage output separately and MUST NOT destroy the current good version on a failed attempt.
- **SR-REC-04:** A successful restore MUST create an immutable version lineage record and audit event.
- **SR-REC-05:** Recovery tests MUST demonstrate detection of ciphertext, envelope, manifest, and authorization tampering.

## Assurance and traceability

| Control domain | Architecture | Primary tests | Evidence target |
|---|---|---|---|
| Quarantine and inspection | API, quarantine, inspector, policy | SR-ING, abuse cases | state history and inspection record |
| Authenticated encryption | crypto, key interface, storage | SR-CRYPTO | round-trip and tamper rejection |
| Revocable authorization | authz, grants, metadata | SR-AUTHZ | object-level matrix and revocation test |
| Tamper-evident audit | audit service/checkpoint | SR-AUD | valid-chain and mutation failures |
| Verified recovery | recovery, versions, crypto | SR-REC | successful restore plus corrupt rejection |
