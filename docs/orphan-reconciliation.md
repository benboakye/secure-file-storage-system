# Orphan-object reconciliation

## Purpose and role boundary

Reconciliation addresses opaque files present in quarantine or protected storage without corresponding authoritative metadata. It is not ordinary file deletion and cannot target a user-selected file, file name, path, upload ID, or protected version.

Administrators and auditors may call `GET /api/v1/admin/resources/orphans` to inspect a safe preview. Only administrators may call `POST /api/v1/admin/resources/orphans/reconcile`, and the mutation requires the normal CSRF control plus a fresh password-and-TOTP step-up proof. Auditors remain read-only.

## Safe candidate identity

The API returns an opaque token, zone, byte count, modification time, eligibility flag, and safe reason code. It never returns the storage object name or path. The token is a SHA-256-derived identifier over the zone, server-generated object name, size, and normalized modification time. It is an optimistic revalidation token, not a durable object identifier or authorization credential.

Candidates must be regular files, absent from the authoritative tracked-object set, and at least one hour old. The age window prevents deletion during the protected-storage interval in which ciphertext can be written just before its metadata transaction commits. Symbolic links, directories, and special files are never candidates.

## Deletion sequence

1. Load a fresh candidate preview and resolve each selected token server-side.
2. Reject duplicates, unknown tokens, ineligible candidates, and batches larger than 25.
3. In one PostgreSQL transaction, create an `authorized` reconciliation operation and its `ORPHAN_DELETION_AUTHORIZED` audit-outbox intent. If either write fails, stop before touching the filesystem.
4. Reload authoritative tracking data. Protected storage also performs a final database existence query for the journaled opaque object immediately before removal.
5. Re-stat the regular file and require the size and normalized modification time to match the journaled values.
6. Remove only that exact server-resolved path.
7. In one PostgreSQL transaction, close the operation as `completed` or `failed` and enqueue matching `ORPHAN_DELETION_COMPLETED` evidence.
8. Deliver both stable outbox events to the signed audit chain; the normal outbox dispatcher retries any delayed delivery.

Filesystem removal cannot participate in the PostgreSQL transaction. The durable operation journal closes this crash-consistency gap without claiming false atomicity. A recovery worker runs at startup and every minute, selecting only operations that an administrator already authorized. It revalidates the journaled object and authoritative metadata before acting. If removal occurred before a crash, an absent object closes successfully as `object_absent_after_authorization`; if removal never started, the worker performs it; if metadata appeared or attributes changed, the object is retained and the operation closes failed. Transient I/O or repository failures leave the operation authorized for a later retry.

The journal's `storage_object` value is internal recovery state. It is excluded from JSON and never copied into audit events. Client requests continue to contain only opaque preview tokens.

## Non-goals

- No autonomous discovery or deletion: the worker can resume only a previously administrator-authorized operation.
- No deletion of metadata-backed or missing protected objects.
- No plaintext access, decryption, download, or content inspection.
- No acceptance of client paths, object names, wildcards, or directory selections.
- No backup-object reconciliation; backups remain deferred to deployment planning.

## Verification

Tests prove that tracked objects are excluded, fresh objects remain protected, object names do not appear in tokens, modified files invalidate stale previews, a last-moment metadata match blocks removal, and an unchanged eligible regular file can be removed. Crash-window tests prove that an authorized operation survives until completion, an already absent object is repaired as success, a newly tracked object is retained, unsafe storage identities fail closed, token authorization is idempotent, and completed operations leave the pending queue. API tests verify the empty-array contract, reported one-hour policy, privileged read boundary, and CSRF denial for mutation.
