# File Lifecycle

## State model

| State | Meaning | Permitted next states |
|---|---|---|
| `quarantined` | upload finalized in isolated storage | `inspecting`, `rejected` |
| `inspecting` | static checks and policy evaluation in progress | `accepted`, `rejected` |
| `accepted` | evidence satisfies policy; awaiting protection | `encrypting`, `rejected` |
| `encrypting` | protected version is being created atomically | `stored`, `rejected` |
| `stored` | ciphertext, wrapped DEK, metadata, and evidence committed | `superseded`, `deleted` |
| `superseded` | immutable non-current version retained for policy/recovery | `restore_candidate`, `deleted` |
| `restore_candidate` | selected version is being verified in isolation | `restored`, `restore_failed` |
| `restored` | verified content committed as a new current version | `superseded` when replaced |
| `rejected` | policy or processing did not allow acceptance | `deleted` after retention |
| `restore_failed` | candidate failed verification or commit | retry to `restore_candidate` if eligible |
| `deleted` | recoverable Trash tombstone; access and active grants blocked | `stored` before grace expiry, `purged` after policy gates pass |
| `purged` | wrapped DEKs destroyed; non-content evidence retained | none |

The user-facing file record may summarize state, while every content version remains immutable.

## Upload sequence

1. Authenticate the requester and authorize `file:create`.
2. Allocate server-generated file/upload IDs and a quarantine destination.
3. Stream bytes with limits while computing a digest; never construct a path from the display filename.
4. Finalize quarantine metadata atomically and audit the upload outcome.
5. Move to `inspecting` with compare-and-swap semantics.
6. Identify content from bytes, run configured static checks, and optionally run SCA for recognized applicable artifacts.
7. Bind evidence to the exact digest, tool versions, and policy version.
8. Reject on malicious result, policy violation, error, timeout, or missing required evidence.
9. For acceptance, generate a DEK and nonce, build AAD, encrypt, wrap the DEK, and commit the immutable protected version.
10. Only after the commit succeeds, remove quarantined plaintext and publish `stored` metadata.

## Access sequence

1. Authenticate and load authoritative file, version, grant, and lifecycle state.
2. Authorize the requested action at object level.
3. Load the envelope and ciphertext without exposing their storage locator.
4. Reconstruct and validate AAD, unwrap the DEK, and authenticate/decrypt.
5. Stream plaintext only after or in a way that cannot release unauthenticated content.
6. Audit success or categorized failure without logging plaintext or keys.

## Revocation sequence

The grant issuer or authorized administrator revokes a grant using a transactional update. The revocation time and actor are recorded. Subsequent authorization reads the authoritative active-grant state; revocation does not require ciphertext re-encryption because access is mediated by the application and key interface. Already exported plaintext cannot be recalled and is a documented limitation.

## Failure and retry rules

- State transitions require the expected prior state and are idempotent.
- Retried finalization or restore requests use an idempotency key.
- Workers lease jobs; expired leases may be reclaimed without skipping verification.
- Orphaned quarantine and staging objects are reconciled from authoritative metadata.
- Reconciliation reports unmatched objects without deleting them; cleanup waits for an explicit retention policy and auditable operation.
- Restart recovery reloads durable upload metadata. Missing required quarantine objects transition to `failed` with a safe reason, while interrupted inspection is resumed.
- No failure path changes a file to `stored` or `restored` without all required artifacts.
- Administrative overrides do not silently bypass inspection; any future override requires a dedicated ADR, policy, and high-severity audit event.

## Scheduled deletion and recovery assurance

- The in-process lifecycle worker evaluates a bounded batch at startup and once per minute.
- Selection requires an expired Trash grace period, no active retention deadline, and no legal hold.
- A deterministic operation identifier makes repeated attempts idempotent. Failed attempts retain a categorized reason and attempt count, then remain eligible for retry.
- Cryptographic deletion nulls every wrapped per-version DEK before ciphertext cleanup. Cleanup failure cannot restore decryptability.
- An administrator recovery drill opens the current encrypted version only inside the storage service, authenticates its envelope and digest, clears the temporary plaintext buffer, and returns metadata-only evidence.
- Backup posture is intentionally `not_configured`; the application does not claim backup health or production recovery readiness without a provider integration.
