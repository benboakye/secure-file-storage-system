# Independent audit-anchor deployment boundary

This package defines the production contract between SecureStore and an independently administered immutable checkpoint ledger. It does not provision a cloud account, ledger, certificates, DNS, private network, retention policy, or notification destination.

The deployment must provide:

- an HTTPS endpoint reachable only from approved workloads;
- mutual-TLS client authentication and authorization scoped to this chain;
- strictly consecutive, append-only checkpoint retention that verifies each `previousCheckpoint` equals the retained chain head and that application administrators cannot alter;
- an Ed25519 signing key held only by the anchor service;
- a pinned public verification key mounted read-only into SecureStore;
- independent administrative ownership and provider-native access logs;
- retention and legal-hold settings aligned with the audit-evidence policy.

Run `python deploy/audit-anchor/validate.py` before packaging. The validator checks the safe environment template, minimal mTLS API surface, and absence of local signing secrets. See [audit-anchor operations](../../docs/audit-anchor-operations.md) for incident and rotation procedures.
