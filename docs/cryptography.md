# Cryptography

## Goals

The cryptographic design provides confidentiality and integrity for stored file versions, separates bulk-data keys from wrapping keys, supports key rotation, and makes metadata substitution detectable.

## Envelope encryption

For every accepted file version:

1. Generate a fresh 32-byte DEK using Go's `crypto/rand`.
2. Create AES-256 and GCM using Go's standard `crypto/aes` and `cipher` packages.
3. Generate a nonce of the AEAD-required size from `crypto/rand`; never derive it from time, counters shared across processes, filenames, or user input.
4. Canonically encode the version's AAD.
5. Seal plaintext to ciphertext plus authentication tag.
6. Wrap the DEK through the KEK interface.
7. Persist ciphertext and the versioned envelope; discard plaintext DEK references as soon as practical.

The prototype does not invent cryptographic primitives and will not use raw AES modes, unauthenticated encryption, or a separate ad hoc ciphertext MAC.

## Envelope schema

An envelope contains at least:

```text
schema_version
algorithm = AES-256-GCM
kek_id and kek_version
wrapped_dek
nonce
file_id
version_id
owner_id
plaintext_size
plaintext_digest (for workflow correlation, authenticated as AAD)
inspection_record_id
created_at
ciphertext locator/digest as needed by storage format
```

The AAD canonical form binds immutable identity and interpretation fields: schema version, algorithm version, file ID, version ID, owner ID, plaintext size/digest, and inspection record ID. Encoding must be deterministic, length-delimited, and versioned; ordinary map serialization is not sufficient unless canonicalized.

## Key hierarchy and rotation

- A unique DEK protects one file version.
- A KEK wraps DEKs through an interface such as `Wrap`, `Unwrap`, and `Rewrap`.
- The audit HMAC key is separate from encryption keys.
- Key IDs and versions are metadata, not secret; key material is never logged.
- KEK rotation rewraps DEKs without decrypting file ciphertext. The immutable `kek_id` and `kek_version` remain part of the original ciphertext AAD, while `wrapping_kek_id` and `wrapping_kek_version` select the KEK currently protecting the DEK.
- DEK rotation requires decrypt-and-re-encrypt into a new immutable version.

For local development, a non-production key provider may be used with test-only keys supplied outside source control. Its limitations must be explicit.

## Decryption rules

The service validates schema, algorithm, identifiers, sizes, authorization, and envelope consistency before key use. It reconstructs AAD from authoritative metadata and calls AEAD open. Any error is indistinguishable to an unauthorized client, releases no plaintext, and emits a categorized audit event.

Because streaming GCM can expose unauthenticated chunks if implemented carelessly, the initial prototype should bound file size and authenticate into protected temporary storage before returning bytes. A chunked authenticated format requires a separate ADR defining per-chunk nonces, ordering, truncation protection, and final-manifest authentication.

## Tests

- encryption/decryption round trip over boundary sizes
- non-deterministic ciphertext for repeated plaintext
- nonce length and uniqueness under generated test samples
- rejection after mutations to ciphertext, tag, nonce, wrapped DEK, or any AAD field
- inability to unwrap using the wrong KEK version
- rewrap preserves decryptability without changing ciphertext
- logs and serialized errors contain no plaintext DEK or secret key material

## Current prototype implementation

- `internal/protectedstore` implements the envelope boundary with Go's standard `crypto/aes`, `cipher.NewGCM`, and `crypto/rand` packages.
- Every stored upload receives a fresh 32-byte DEK and GCM nonce. Repeated plaintext produces different ciphertext.
- Versioned, length-delimited AAD binds the schema, algorithm, upload ID, immutable version ID, owner ID, plaintext size/digest, media type, inspection record, KEK ID/version, and normalized creation time.
- PostgreSQL stores authoritative envelope metadata. Ciphertext is written with mode `0600` under an opaque version-derived object name and is atomically renamed from an access-restricted staging directory before metadata commit.
- The upload ID is an idempotency boundary for restart recovery. An existing committed protected version is reused rather than creating a second DEK or ciphertext.
- Owner download validates lifecycle state, envelope fields, KEK identity/version, GCM authentication, plaintext length, and digest before returning any bytes. A required audit append occurs before response headers or plaintext are released.
- The local file-backed KEK provider is deliberately marked development-only. The production adapter delegates wrap, unwrap, and status to a private mutually authenticated key broker backed by an approved managed KMS/HSM. SecureStore never loads a plaintext KEK, rejects redirects and plaintext HTTP, strictly bounds and decodes responses, binds every operation to the exact key ID/version and `securestore-envelope-dek-v1` purpose, and fails closed without local-key fallback.
- The development adapter supports a versioned KEK keyring. New envelopes record both the immutable authenticated origin and current wrapping-key identity. A missing wrapping version fails closed.
- Administrators can execute bounded, step-up-authorized rewrap batches. Each update uses optimistic comparison of the prior wrapped DEK and key identity, records `securestore_dek_rewrap_operations`, and enqueues `FILE_DEK_REWRAPPED` evidence in the same PostgreSQL transaction. Interrupted batches are resumable because unchanged candidates remain visible as pending.
- A historical KEK may be retired only after aggregate posture reports zero protected versions still wrapped by it and a recovery test succeeds. Production executes this policy through managed KMS/HSM controls; destructive retirement is prohibited until retention, legal-hold, incident, and deferred external-backup dependencies have been evaluated.
- The initial implementation authenticates a bounded file completely in memory before release. A future chunked format requires a separate ADR for nonce derivation, ordering, truncation protection, and final-manifest authentication.
