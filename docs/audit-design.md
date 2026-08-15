# Tamper-Evident Audit Design

## Goals and limits

The audit log supports accountability and makes unauthorized editing, deletion, insertion, reordering, and truncation detectable. It is tamper-evident, not magically tamper-proof: assurance depends on a protected HMAC key and a trusted checkpoint outside the mutable event sequence.

## Event schema

Each event includes:

- schema version and monotonically increasing sequence
- event ID and UTC timestamp
- actor type and stable actor ID
- action and resource type/ID
- outcome and safe reason code
- request/correlation ID
- relevant lifecycle transition (`from`, `to`) when applicable
- policy/tool/version references when applicable
- previous event MAC
- current event MAC and audit-key version

Events exclude credentials, tokens, plaintext content, encryption keys, raw scanner output that may contain secrets, and unnecessary filenames or personal data.

## Chain construction

Let `C(event)` be a deterministic, versioned, length-delimited encoding excluding the current MAC. For sequence `i`:

```text
mac_i = HMAC-SHA-256(audit_key_version, domain || sequence_i || mac_(i-1) || C(event_i))
```

The genesis event uses a fixed, versioned genesis value. Domain separation prevents this HMAC format from being confused with other uses of the key. Constant-time comparison is used during verification.

## Append and checkpoint behavior

Only the audit service appends events. Sequence allocation, previous-MAC read, event insertion, and protected operation commit must have defined transactional behavior. For sensitive mutations, failure to obtain required audit durability fails the operation or records a recoverable pending state.

A verifier needs a trusted checkpoint containing at least chain ID, latest sequence, latest MAC, key version, and checkpoint time. Without it, removal of a valid suffix cannot be distinguished from an older valid log. SecureStore signs each committed checkpoint with a separate anchor key and appends the evidence to a pluggable checkpoint destination.

## Verification

Verification checks schema, continuity, sequence ordering, canonical encoding, key version availability, every MAC, and agreement with the selected checkpoint. Results include the first failing sequence and a safe category, not secret material. Verification itself is audited in a separate chain-safe manner that avoids recursive append ambiguity.

## Events in scope

- authentication successes/failures and account-state changes
- upload start/finalization and limit rejection
- inspection start/result/error and acceptance decision
- encryption/storage success or failure
- authorization denial, download, share, revoke, delete
- audit verification and checkpoint operation
- restore request, verification result, commit, cancellation, failure
- policy or key-version change

## Key rotation and concurrency

An event records the audit-key version. Rotation creates a signed/chained transition event and a checkpoint, after which new events use the new key. Verification may require historical key access under verification-only policy.

Concurrent appends are serialized per chain or use an atomic compare-and-swap on the chain head. Multiple independent chains require an explicit partition and anchoring design; the initial prototype favors one logical ordered chain for clarity.

The implementation now uses a versioned audit keyring. New events select `SECURESTORE_AUDIT_KEY_VERSION`; retained events select the key named by their stored `key_version`. When the configured current version differs from the durable checkpoint, startup appends a chained `AUDIT_KEY_ROTATED` transition under the new key before ordinary writes continue. Verification fails at the first affected sequence with `historical_key_unavailable` when a required verification key is missing. Historical keys are verification-only in policy and must remain configured for the full evidence-retention period.

## Prototype implementation notes

- The active PostgreSQL schema and HMAC domain are version 2. Event timestamps are converted to UTC and truncated to PostgreSQL microsecond precision before canonical encoding and signing, ensuring identical bytes after a database/process round trip.
- Sequence allocation, event insertion, and checkpoint update execute in one serializable PostgreSQL transaction protected by a chain-specific advisory transaction lock.
- Administrator account-status changes, targeted session revocation, privileged invitation creation/activation, owner-quota changes, retention policy, legal holds, Trash transitions, direct or scheduled cryptographic deletion, access-grant creation/revocation, version-restore commits, recovery-drill results, and ingestion lifecycle transitions insert a sanitized stable-ID intent into `securestore_audit_outbox` in the same PostgreSQL transaction as the authoritative mutation. A dispatcher signs and chains pending intents immediately after request commit and every five seconds. Delivery is idempotent; an interruption leaves the intent pending and raises an operational alert instead of losing evidence.
- The transactional outbox contains only the approved audit projection. Password hashes, invitation tokens, session tokens, MFA secrets, file content, encryption material, and raw network addresses are prohibited from this boundary.
- The local development key is generated once in `.data/audit-hmac.key`; production must inject the base64 key from a secret manager and retain historical verification keys during rotation.
- Each committed database checkpoint is anchored through a pluggable provider. The local development adapter signs it with a distinct HMAC key and appends it to `.data/audit-checkpoints.jsonl`. The production boundary sends the digest over mTLS to an independently administered immutable ledger and verifies the ledger's Ed25519 receipt with a pinned public key. Verification checks the trusted receipt and exact agreement between the latest anchored sequence/MAC and PostgreSQL checkpoint.
- The local file demonstrates append-only anchoring and detects database-only manipulation, but it shares the application host and is not independent production assurance. Deployment must replace it with an external immutable ledger, object-lock store, transparency service, or equivalent independently administered destination.
- Audit reads append an `AUDIT_READ` event before the requested page is listed, so the returned verification covers the read event without recursive verification logging.
- Unit tests cover valid chaining, exact tamper location, concurrent ordering, and durable timestamp normalization. The opt-in PostgreSQL integration test appends a synthetic event, closes and recreates the repository, then verifies persistence and the full chain with the same key.
- A pre-release integration event created with the version-1 nanosecond format remains preserved in the version-1 development table. It is not part of the active version-2 chain and was intentionally not deleted because audit evidence is immutable.
- Transactional mutation evidence is implemented for the currently defined durable administrator, protected-file, ingestion, scheduled-deletion, recovery-drill, and privileged-activation workflows. Multi-repository ingestion remains a recoverable state machine: encrypted candidate/catalog commits may precede the atomic `stored` transition, but the file is not exposed as stored until that final transition and audit intent commit together.

## Administrator investigation and monitoring

The privileged API exposes structured server-side filters for actor ID, action, resource type, outcome, time range, free-text correlation, and client IP address. Results are bounded and paginated; administrators and auditors receive the same read-only safe projection. CSV export is capped at 5,000 events and carries an `X-Audit-Chain-Valid` response header. Every audit read and export is itself appended before evidence is released.

Raw client IP addresses are not stored. The API derives a keyed `network_source` fingerprint and stores only its truncated encoded value. An investigator may enter an IP address in a filter; the API fingerprints it with the same key and performs an equality match. This supports correlation without making raw network identifiers available to database readers. The application intentionally ignores forwarding headers until deployment establishes an explicit trusted-proxy boundary.

Current in-process detections are deterministic signals over the durable audit repository:

- five or more denied authentications in 15 minutes;
- three or more denied downloads in 15 minutes;
- any audit-chain integrity failure.
- any committed mutation evidence awaiting signed-chain delivery.

The monitoring page also reports 24-hour event, denial, high-risk, independent-anchor validity, and anchoring-lag evidence. These local control-plane signals do not replace a production SIEM. Alert acknowledgement, notification delivery, case management, geo-velocity analysis, deployment of the prepared independent anchor, and long-term warehouse retention remain deployment integrations.
