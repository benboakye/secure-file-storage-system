# Managed KMS/HSM operations

## Custody model

SecureStore uses envelope encryption: a random 256-bit DEK encrypts one immutable file version with AES-256-GCM, while a managed KEK wraps only that DEK. The KEK must remain non-exportable in the approved managed KMS/HSM boundary. The private key broker authenticates the SecureStore workload with mutual TLS and maps the application's bounded key alias/version to the provider resource.

Production readiness requires a successful authenticated status response for the exact current key ID/version, `status=enabled`, and `hardwareBacked=true`. Repository durability alone is not evidence of managed custody. The local file-backed provider always reports development-only posture.

## Authorization policy

The SecureStore workload identity receives only:

- status/read-metadata for approved key aliases;
- wrap using the exact active version;
- unwrap using the active and explicitly retained historical versions.

It must not create, import, export, disable, schedule deletion, change policy, alter aliases, or administer certificates. Key administrators must use separate privileged identities with MFA, approval, and provider-native audit evidence. No person or application role may retrieve plaintext KEK material.

## Rotation

1. Create and approve a new non-exportable hardware-backed key version in the provider.
2. Grant the workload bounded wrap/unwrap access and verify status through the broker.
3. Change `SECURESTORE_KMS_KEY_VERSION` and deploy through the controlled release process. New file versions immediately use the new wrapping version.
4. Run bounded, step-up-authorized DEK-rewrap batches. This unwraps and rewraps DEKs but never decrypts or rewrites file ciphertext.
5. Monitor pending wrappers, failures, key-service alerts, provider audit records, and application audit-outbox delivery.
6. When pending wrappers reach zero, perform controlled download and recovery drills covering current and historical file versions.
7. Disable historical unwrap only after documented approval. Schedule destruction only after retention, legal hold, recovery, external-backup, and incident requirements have been satisfied.

Backup remains deferred, so destructive retirement of historical production keys is prohibited until the backup design explicitly accounts for encrypted copies and their KEK dependencies.

## Availability failure

When the broker, managed provider, private network, certificate identity, or HSM is unavailable, wrap and unwrap fail closed. New protection, download, recovery, and rewrap operations must not fall back to a local file KEK or return partial plaintext. Preserve ciphertext and wrapped metadata while restoring the dependency.

Investigate private DNS, certificate validity and rotation, workload identity, network policy, provider/HSM status, quota/throttling, exact key state, and broker deployment health. Do not place endpoints, certificate contents, wrapped DEKs, plaintext DEKs, file identifiers, or provider error bodies into ordinary incident messages.

## Compromise and revocation

1. Declare a security incident and preserve application, broker, provider, certificate-authority, and deployment audit evidence.
2. Determine whether the event affects a workload certificate, broker authorization, KEK administration, one key version, or the provider account boundary.
3. Revoke compromised workload certificates and issue a new identity through the approved process.
4. If a KEK version is suspected, stop new wraps, create a clean hardware-backed version, and rewrap affected DEKs in bounded audited batches.
5. Do not destroy the suspected version until recovery requirements and forensic preservation are resolved.
6. Validate ciphertext authentication, wrapper inventories, signed application audit evidence, provider audit records, and controlled recovery before closing the incident.

## Monitoring and evidence

The application exports only aggregate connection, production-readiness, and hardware-custody gauges. Key IDs and versions appear only in the privileged security posture and wrapper-rotation summary; they are never metric labels. Alert response uses `SecureStoreKeyServiceUnavailable` and `SecureStoreKeyCustodyNotProductionReady`.

Retain key inventory, purpose, owner, provider resource mapping, creation/activation/retirement dates, cryptoperiod, policy versions, administrators, workload grants, certificate lifecycle, rotations, rewrap evidence, recovery tests, and compromise actions in the approved control system.
