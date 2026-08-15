# ADR 0002: Provider-neutral managed key broker

- Status: Accepted
- Date: 2026-08-13
- Decision owners: application security and platform security

## Context

SecureStore envelope encryption already separates per-version DEKs from versioned KEKs and supports bounded DEK rewrapping. The local file-backed keyring proves cryptographic behavior but places plaintext KEK material on the application host and cannot provide production custody, hardware assurance, independent authorization, or provider-native key-operation evidence.

Directly embedding one cloud SDK would couple the application to a provider-specific identity model, resource syntax, error surface, rotation semantics, and dependency lifecycle before the deployment provider is selected. The administrator also needs truthful evidence that distinguishes durable encrypted storage from production-grade key custody.

## Decision

SecureStore will use a minimal private key broker contract with three operations: status, wrap, and unwrap. The application authenticates with a workload client certificate over certificate-verified mutual TLS. The broker maps bounded application key aliases and versions to approved non-exportable managed KMS/HSM resources.

Every operation is bound to `securestore-envelope-dek-v1` and an exact key ID/version. Responses use strict bounded JSON and cannot contain provider debug fields. Redirects, plaintext HTTP, identity mismatches, malformed or excessive responses, disabled/software-only keys, and dependency failures are not production-ready; cryptographic operations fail closed without falling back to the local keyring.

The application exposes safe aggregate connection, hardware, and production-readiness posture. It does not expose broker endpoints, certificates, credentials, DEKs, wrapped DEKs, or provider diagnostics. Provider-native administrative and cryptographic audit logging remains mandatory at deployment.

## Consequences

- SecureStore remains independent of the final cloud/HSM provider.
- KEKs never need to be exported to the application process.
- The broker becomes a critical private availability dependency; upload protection, download, recovery, and rewrap fail closed when it is unavailable.
- Deployment must implement and independently secure the broker, certificates, provider identities, key policies, network boundary, audit destination, rotation, compromise response, and disaster recovery.
- Historical key versions remain required until all wrappers are rotated and recovery succeeds. Because external backups are deferred, destructive historical-key retirement is also deferred.
