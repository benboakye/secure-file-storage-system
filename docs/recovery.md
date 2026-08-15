# Verify-Before-Restore Recovery

## Trash and deletion recovery

Owner deletion is staged rather than immediate. Moving a file to Trash sets an authoritative deletion timestamp and a 30-day `purge_after` deadline. The file disappears from active and shared views immediately, metadata and plaintext reads fail closed, and active recipient grants are revoked. Restoring during the grace period returns the file to the active catalog but deliberately does not reactivate those grants.

Retention and legal holds are independent deletion gates. A future retention deadline prevents Trash entry and cannot be shortened while active. An administrator may apply or release a reason-bearing legal hold; auditors remain read-only. Both controls operate only on safe metadata and every privileged change enters the tamper-evident audit chain.

Permanent deletion requires the owner, CSRF protection, a valid idempotency key, an expired grace period, no active retention, and no legal hold. The durable deletion transaction nulls every wrapped DEK for every immutable version, revokes remaining grants, commits a purged tombstone, and records the idempotent operation. Ciphertext removal follows as cleanup. Destruction of wrapped DEKs is the cryptographic deletion boundary.

Automatic purge scheduling, backup monitoring, and proof that external backup copies have aged out remain deployment-specific integrations.

## Deferred backup scope

External backup creation, provider selection, retention of backup copies, recovery-point objectives, recovery-time objectives, and disaster-recovery restoration are intentionally deferred until deployment planning. The current recovery implementation verifies and restores encrypted versions held in primary protected storage only. It does not provide independent backup copies and must not be used as evidence that the system is disaster-recovery-ready.

## Objective

Recovery demonstrates that availability is a security property only when restored data is authentic, authorized, and traceable. A stored historical version is treated as untrusted input until its envelope and content verify.

## Recovery point

Each immutable version records file/version identity, lineage, ciphertext reference and digest, envelope, inspection decision reference, creation time, and lifecycle status. A manifest binds the versions included in a recovery set and is authenticated or anchored so silent substitution is detectable.

## Restore workflow

1. Authenticate the requester and authorize `restore` for the file and selected source version.
2. Create an idempotent restore job and audit the request.
3. Read source metadata, envelope, ciphertext, and required manifest into an isolated staging context.
4. Validate schema, lineage, lifecycle eligibility, expected identifiers, sizes, and digests.
5. Resolve the named KEK version, unwrap the DEK, reconstruct authoritative AAD, and perform AES-GCM authentication/decryption.
6. Apply any current policy checks required for restoration. The initial policy must state whether earlier inspection evidence remains sufficient or a static rescan is required.
7. Compare the verified plaintext digest and size with authenticated metadata.
8. Commit the result as a new immutable version (preferred) and atomically set it current. Never overwrite the last known-good version in place.
9. Remove staging plaintext and audit success. On any failure, keep the current version unchanged and audit a safe failure reason.

## Recovery invariants

- No plaintext is published before AEAD authentication succeeds.
- The requester cannot restore a version they cannot identify and access by policy.
- Corrupt, incomplete, mismatched, deleted-beyond-retention, or cryptographically unverifiable versions fail closed.
- Restore preserves lineage: new version -> restored-from version -> original file.
- Restore requires an idempotency key bound to the owner, logical file, and source version; transport retries return the same restored version.
- Recovery tooling does not bypass normal authorization, audit, or key boundaries.

## Implemented prototype boundary

The local PostgreSQL implementation maintains a stable `securestore_files` row and append-only `securestore_file_versions` rows. Restore is restricted to the authenticated standard-user owner, authenticates the selected source envelope and digest, re-encrypts the verified bytes with a fresh DEK and nonce, records `source_version_id`, and advances `current_version_id` under a serializable row-locked transaction. The context-bound SHA-256 operation identity makes retries return the previously committed version without storing the raw idempotency key. The UI displays only this authoritative history; the unimplemented owner-scoped activity view does not show sample data.

The encrypted object and envelope are committed before the catalog transaction, so a catalog failure can leave an unreachable encrypted object for later reconciliation. Current-policy rescanning, external backup manifests, historical KEK recovery drills, and atomic coupling of the completion audit record remain hardening work. The request audit is fail-closed before restore; the completion audit is currently best effort after the catalog commit.

## Objectives and evidence

Prototype objectives will be measured, then baselined rather than guessed:

- Recovery Point Objective (RPO): version-level; a successfully committed immutable version is the smallest recovery unit.
- Recovery Time Objective (RTO): report p50/p95 restore time for defined file sizes and local test conditions.
- Integrity: 100% rejection of intentionally mutated test envelopes/ciphertexts/manifests.
- Repeatability: documented restore drill produces the same verification outcome from the same artifacts.

## Restore drills

- restore the prior valid version after a simulated logical deletion
- reject modified ciphertext, tag, nonce, AAD, wrapped DEK, or manifest
- reject an unauthorized or revoked requester
- handle missing historical key version without publishing plaintext
- race restore with a newer upload without losing either immutable version
- interrupt restore and prove staging cleanup and safe retry
- verify audit events and version lineage after success and failure
