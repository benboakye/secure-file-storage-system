# Threat Model

## Method and scope

This model uses STRIDE across upload, quarantine, inspection, encryption, storage, authorization, audit, and recovery. It covers the Go application and its local development dependencies. Dynamic analysis and production infrastructure threats are outside the current design scope, but external-tool failure is considered.

## Assets

- File plaintext, ciphertext, metadata, versions, and availability
- User credentials, sessions, grants, and ownership records
- Data-encryption keys (DEKs), key-encryption keys (KEKs), and audit keys
- Inspection evidence and policy decisions
- Audit-event integrity and ordering
- Recovery points and restore results

## Adversaries

- Unauthenticated remote attacker
- Authenticated user attempting cross-tenant or elevated access
- User uploading malicious, malformed, oversized, or misleading content
- Attacker with partial read or write access to stored objects or metadata
- Operator or compromised component attempting to alter audit history
- Attacker replaying requests, grants, versions, or restore operations

## STRIDE analysis

| ID | Category | Threat | Risk | Primary mitigations | Verification |
|---|---|---|---|---|---|
| T-01 | Spoofing | Stolen or forged session acts as another user | High | hardened authentication, expiring sessions, secure cookies/tokens, generic failures | invalid/expired/replayed session tests |
| T-02 | Tampering | File bytes or metadata change after inspection | Critical | immutable versions, digest binding, AES-GCM AAD, transactional transition | mutate ciphertext/AAD tests |
| T-03 | Repudiation | Actor denies upload, grant, download, delete, or restore | High | actor/correlation metadata and HMAC-chain audit | event completeness and chain verification |
| T-04 | Information disclosure | Quarantined or another user's file is downloaded | Critical | separate namespace, generated IDs, object-level authz, deny-by-default | IDOR and quarantine download tests |
| T-05 | Denial of service | Oversized, compressed, numerous, or slow uploads exhaust resources | High | byte/count/time limits, streaming, bounded workers, quotas, cancellation | boundary and concurrency tests |
| T-06 | Elevation of privilege | User changes owner, role, grant, or lifecycle fields | Critical | server-owned fields, centralized policy, admin separation | mass-assignment and role tests |
| T-07 | Spoofing | Filename or extension misrepresents content | Medium | server-generated locator, content-based identification, normalized display name | extension/MIME mismatch tests |
| T-08 | Tampering | Scanner result is skipped, forged, stale, or ambiguous | High | evidence tied to content digest and policy/tool versions; fail closed | timeout/error/stale evidence tests |
| T-09 | Information disclosure | Plaintext or DEK leaks through logs, errors, or temporary files | Critical | structured redaction, restrictive temp storage, DEK wrapping and zeroization best effort | log and cleanup tests |
| T-10 | Tampering | GCM nonce is reused or envelope metadata is swapped | Critical | cryptographic randomness, per-version DEK, AAD binding, uniqueness checks | deterministic fault/property tests |
| T-11 | Elevation of privilege | Revoked grant remains usable through cache or direct object access | Critical | request-time authoritative check, bounded cache invalidation, storage not public | immediate revocation tests |
| T-12 | Tampering | Audit records are edited, removed, reordered, forked, or rolled back with their database checkpoint | High | canonical encoding, sequence numbers, previous-MAC link, independent immutable anchor, server-attested receipts | edit/delete/reorder/truncate/receipt tests |
| T-13 | Tampering | Corrupt or unauthorized backup is restored | Critical | restore authorization, manifest/digest and AEAD checks, isolated staging | corruption and unauthorized restore tests |
| T-14 | Repudiation | Destructive operation is replayed | High | idempotency key, freshness/CSRF controls as applicable, audit correlation | duplicate request tests |
| T-15 | Denial of service | Archive or parser bomb triggers excessive work | High | no extraction by default, parser limits, worker isolation, timeouts | crafted archive/parser tests |
| T-16 | Information disclosure | Error response reveals file existence or policy internals | Medium | consistent authorization errors and minimal client detail | enumeration tests |

## Abuse cases

1. Upload a file with an allowed extension but executable content.
2. Request a quarantined object through a guessed file or object identifier.
3. Replace ciphertext, nonce, wrapped DEK, or AAD fields independently.
4. Download through a grant immediately after its revocation.
5. Remove a middle audit entry and present the remaining log as valid.
6. Restore a corrupt older version or race restore against a new upload.
7. Force scanner timeout and attempt to interpret uncertainty as acceptance.

## Residual risk

Static inspection cannot prove that a file is harmless and may miss novel threats. The system therefore treats inspection as risk reduction, keeps retrieval controlled, and does not execute content. A compromised application process may access plaintext while serving an authorized operation; process isolation and production key-management hardening are future concerns. HMAC chaining detects alteration only when the verifier has a trusted key and a protected latest checkpoint, so checkpoint protection is a required part of the design.

The threat model is reviewed whenever a trust boundary, lifecycle transition, file parser, authentication mechanism, key interface, or restore behavior changes.
