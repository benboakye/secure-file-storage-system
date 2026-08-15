# Independent audit-anchor operations

## Control objective

SecureStore's HMAC chain detects changes inside the ordered audit log. The independent anchor makes removal or replacement of a valid database suffix externally observable by retaining server-attested checkpoint receipts outside the application and PostgreSQL administrative boundary.

Production readiness requires all of the following:

- an independently administered append-only or immutable ledger;
- mutual-TLS workload authentication and least-privilege append/read-latest authorization;
- strictly monotonic checkpoint sequences with conflicts rejected;
- provider-native access logging and retention controls unavailable to SecureStore administrators;
- Ed25519 receipt signing whose private key never enters SecureStore;
- a pinned receipt public key mounted read-only into the application;
- monitoring for reachability, posture, receipt validity, and anchoring lag.

The local JSONL adapter is useful for development and database-tamper demonstrations, but it is on the same host and is never production-ready.

## Receipt and verification flow

1. PostgreSQL atomically commits an audit event and database checkpoint.
2. SecureStore sends only the chain ID, sequence, checkpoint digest, previous checkpoint digest, audit-key version, and UTC checkpoint time over mTLS.
3. The external service enforces authorization, consecutive sequence and previous-digest continuity, and immutable retention.
4. The service signs the exact receipt using its Ed25519 private key.
5. SecureStore verifies the returned and latest receipts using the pinned public key, then compares the receipt to the database checkpoint.

No event body, actor identity, filename, token, encryption key, audit HMAC key, or receipt private key crosses this boundary.

## Failure behavior

An audit event already committed to PostgreSQL is not rolled back when the remote ledger is unavailable. The checkpoint becomes visibly unanchored: verification reports an invalid or lagging anchor, administrator posture changes, and Prometheus raises a critical alert. Operators should avoid discretionary privileged changes until anchoring catches up.

Do not fabricate receipts, disable verification, replace the pinned public key, truncate the database, or repoint the service to a locally administered substitute during an incident.

## Receipt-key rotation

Receipt-key rotation must be a controlled two-stage deployment:

1. preserve the prior public key for the full receipt-retention period;
2. publish and independently verify the new public key fingerprint;
3. update the service signing policy and SecureStore trust bundle through reviewed deployment changes;
4. append a rotation checkpoint and confirm both provider logs and SecureStore verification;
5. remove a historical verification key only after every retained receipt signed by it expires.

The current client pins one active Ed25519 public key. A provider deployment requiring overlapping receipt keys must extend the contract to carry a bounded receipt-key ID and a verification-only public-key ring before rotation.

## Incident response

### Anchor unavailable

Confirm DNS, certificate validity, private routing, service health, and workload authorization without exposing key material. Preserve application and provider-native logs. Restore the existing independently administered service; do not switch to the local adapter as a production workaround.

### Invalid receipt or checkpoint mismatch

Treat this as a security incident. Freeze nonessential privileged mutations, preserve PostgreSQL and external ledger evidence, compare the full immutable receipt history with database checkpoints, and involve the independent ledger owner. A mismatch can indicate database rollback, ledger misuse, key compromise, or an unauthorized configuration change.

### Signing-key compromise

Disable new receipt issuance, preserve immutable history and provider audit logs, rotate through the approved independent key ceremony, distribute a newly verified public key, and document which receipts require secondary validation. Never erase receipts signed by the affected key.

## Deployment acceptance

- `python deploy/audit-anchor/validate.py` passes.
- Certificate validation and mutual TLS cannot be bypassed.
- The service rejects duplicate, skipped, decreasing, conflicting, or previous-digest-mismatched checkpoints.
- A receipt signed by any untrusted key fails verification.
- Unknown JSON fields, redirects, plaintext endpoints, oversized responses, and malformed receipts fail closed.
- An intentional outage produces anchor-unavailable and lag alerts.
- Application/database administrators cannot delete or rewrite retained provider receipts.
