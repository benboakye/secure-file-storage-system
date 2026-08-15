# SecureStore monitoring and alert-response runbook

## Purpose and authority boundary

This runbook covers aggregate operational telemetry. It does not authorize administrators or monitoring operators to open, download, decrypt, or impersonate a user's files or account. Metrics contain no identity or resource dimensions. Investigation begins with aggregate state and sanitized audit evidence; access to infrastructure logs or database maintenance tools follows the organization's separate privileged-access process.

Alert notifications must contain only the alert name, deployment, instance, severity, summary, and a reference to this runbook. Do not attach metric payloads, credentials, internal paths, filenames, account data, raw addresses, or error bodies to tickets or chat systems.

## Severity and ownership

| Severity | Initial response | Owner | Examples |
|---|---:|---|---|
| Critical | 15 minutes | On-call platform and security operators | target loss, non-durable repository, scanner not production-ready, missing protected object |
| Warning | 1 hour | Platform operations | server-error ratio, latency, audit backlog, ingestion failures/backlog, capacity pressure, orphan objects |

Acknowledgement is not remediation. Record the alert start, acknowledgement, safe observations, actions, outcome, and closure reason in the approved incident system. Never silence a critical alert without an expiry and documented owner.

## Alert procedures

### SecureStoreTargetDown

1. Confirm Prometheus itself is healthy and the target is still configured.
2. Check DNS, certificate validity, management-network policy, and the SecureStore `/healthz` endpoint from the collector network.
3. Distinguish an API outage from an expired or mismatched collector bearer; never paste the bearer into logs or a command history shared with others.
4. Restore service through the approved deployment rollback or restart procedure and confirm two consecutive successful scrapes.

### SecureStoreMetricsTargetMissing

1. Inspect the deployed Prometheus configuration and service-discovery state.
2. Confirm the expected environment and target identity were not removed during deployment.
3. Validate the configuration with `promtool` before reloading it.
4. Confirm the target produces `up{job="securestore-api"} == 1` after reload.

### SecureStoreElevatedServerErrors

1. Compare affected instances and route templates; route labels never contain concrete identifiers.
2. Review sanitized application logs by correlation fingerprint and deployment event history.
3. Check database, protected-storage, scanner, and audit-outbox posture before restarting components.
4. Escalate if errors affect authentication, authorization, upload protection, or audit evidence.

### SecureStoreSustainedRequestLatency

1. Confirm traffic volume meets the alert's minimum sample threshold.
2. Compare instances and bounded route templates, then check queue, database, scanner, storage, CPU, and memory signals.
3. Do not disable inspection or integrity controls to improve latency.
4. Scale or roll back through the approved deployment process and confirm recovery for two evaluation windows.

### SecureStoreScannerNotProductionReady

1. Suspend new upload admission at the trusted ingress if production inspection cannot be restored promptly.
2. Verify ClamD daemon health, engine version, signature freshness, private-network reachability, and socket permissions.
3. Do not switch production to the deterministic development adapter.
4. Resume admission only after the posture gauge is `1` and a controlled harmless upload completes inspection.

### SecureStoreScannerSignaturesStale

1. Keep upload processing fail-closed; do not weaken or extend the freshness threshold to clear the alert.
2. Check FreshClam update status, egress DNS/HTTPS access, database-directory ownership, available disk space, and the ClamAV CDN status.
3. Confirm FreshClam and ClamD use the same persistent database directory and that ClamD reloads the updated databases.
4. Confirm the database timestamp is in UTC, `securestore_scanner_signatures_fresh` returns `1`, and a harmless controlled upload completes inspection before restoring normal admission.

### SecureStoreRepositoryNotDurable

1. Treat this as a deployment configuration failure; prevent state-changing traffic.
2. Verify PostgreSQL connectivity and repository initialization without exposing the connection string.
3. Restore the durable configuration or roll back the deployment.
4. Confirm both durability gauges are `1` before reopening traffic.

### SecureStoreKeyServiceUnavailable

1. Stop new upload protection and DEK-rewrap batches; do not fall back to the local file keyring.
2. Verify private DNS, certificate validity, workload client identity, network policy, key-broker health, and provider/HSM availability without printing credentials or endpoint internals into tickets.
3. Preserve encrypted objects and wrapped DEKs. An unavailable KEK service is an availability incident, not evidence that ciphertext should be replaced or deleted.
4. Resume only after mutually authenticated status succeeds and controlled wrap, unwrap, download, and recovery tests pass.

### SecureStoreKeyCustodyNotProductionReady

1. Treat software-only, disabled, scheduled-for-deletion, or otherwise non-hardware custody as a production release blocker.
2. Confirm the configured key ID/version maps to the approved HSM-backed key and the workload identity has only wrap, unwrap, and status permissions.
3. If rotation is in progress, retain historical versions until pending wrappers reach zero and a recovery drill succeeds.
4. Do not change posture responses or monitoring thresholds to represent an unapproved key as production-ready.

### SecureStoreProtectedObjectMissing

1. Stop automated lifecycle deletion and prevent actions that could overwrite reconciliation evidence.
2. Use the metadata-only Resource and Data lifecycle administrator views to determine scope.
3. Preserve audit, catalog, and storage evidence; do not manually fabricate or rename protected objects.
4. Escalate to a security incident and follow the approved recovery procedure. External backup restoration remains unavailable until the deferred backup stage is implemented.

### SecureStoreAuditEvidenceBacklog

1. Check audit repository integrity and outbox delivery health.
2. Avoid discretionary privileged mutations while evidence delivery is degraded.
3. Restart or repair the outbox worker through the controlled deployment process.
4. Confirm pending evidence returns to zero and chain verification remains valid.

### SecureStoreAuditAnchorUnavailable

1. Treat loss of the independently administered ledger as an evidence-control outage.
2. Verify private routing, certificate validity, workload authorization, and provider health without exposing trust material.
3. Avoid discretionary privileged mutations while checkpoints cannot be anchored.
4. Restore the approved remote service; never substitute the local file adapter in production.

### SecureStoreAuditAnchorNotProductionReady

1. Confirm the active service is independently administered, immutable, and issuing server-attested receipts.
2. Compare deployment identity, endpoint, pinned public-key fingerprint, and retention policy with the approved change record.
3. Treat any shared administration or mutable retention as a release blocker.
4. Do not alter posture responses or alert thresholds to represent a development adapter as production-ready.

### SecureStoreAuditAnchorInvalidOrLagging

1. Freeze nonessential privileged mutations and preserve PostgreSQL, application, and provider-native evidence.
2. Compare the immutable receipt history with the database checkpoint; do not fabricate, delete, or replace a receipt.
3. Escalate as a security incident because mismatch can indicate database rollback, ledger misuse, key compromise, or unauthorized configuration.
4. Resume normal operations only after receipt verification succeeds, lag returns to zero, and the incident owner records the evidence disposition.

### SecureStoreIngestionFailures

1. Inspect aggregate lifecycle states and sanitized failure categories in the administrator Resource view.
2. Verify quarantine capacity, scanner health, protected storage, and database connectivity.
3. Preserve failed records for analysis; do not delete quarantine objects outside the reviewed reconciliation workflow.
4. Confirm the underlying fault is corrected before retrying a bounded test upload.

### SecureStoreProcessingBacklog

1. Check scanner, worker, database, and protected-storage health.
2. Compare queue growth with incoming request rate and available capacity.
3. Scale the worker or restrict new admissions through approved controls; never bypass quarantine or inspection.
4. Confirm the queue falls below threshold and records continue reaching terminal states.

### SecureStoreCapacityPressure

1. Confirm configured capacity and safety-reserve values match the approved deployment settings.
2. Review protected ciphertext and active reservations; do not count the safety reserve as available admission capacity.
3. Reduce new admission, expand protected storage through the approved change process, or apply authorized lifecycle policies.
4. Never delete user objects directly from disk to clear the alert.

### SecureStoreOrphanObjectsDetected

1. Review the metadata-only reconciliation preview and wait for the one-hour safety window.
2. Determine whether ingestion recovery or an active upload explains the object.
3. Use only the administrator-reviewed opaque-token cleanup workflow; never submit or delete a filesystem path directly.
4. Preserve the reconciliation journal and audit-outbox evidence for every decision.

## Deployment and validation checklist

- Validate configuration and rules with both `deploy/monitoring/validate.py` and `promtool`.
- Mount the bearer and CA files read-only; verify the Prometheus service identity is the only reader.
- Verify HTTPS certificate name and CA validation; `insecure_skip_verify` is prohibited.
- Confirm `/metrics` is reachable only from the management network and is absent from public ingress routes.
- Confirm an invalid bearer receives `401` and does not update the administrator's last-successful-scrape evidence.
- Confirm a valid scrape receives `200`, contains no identity/resource labels, and changes External telemetry to Connected.
- Exercise every alert in a non-production environment and record notification delivery, acknowledgement, resolution, and inhibition behavior.
- Set explicit Prometheus retention time and size limits, then document the approved values and capacity assumptions.
- Configure an approved Alertmanager receiver and escalation policy before representing notification delivery as operational.
- Keep backup monitoring marked Not connected until the separately deferred backup design is implemented and tested.
