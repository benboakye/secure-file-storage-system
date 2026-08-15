# ClamAV production operations

## Security boundary

SecureStore sends only server-opened quarantine bytes through ClamD's bounded `INSTREAM` protocol. It never sends a client filename or filesystem path for daemon-side resolution. ClamD TCP has no built-in authentication or encryption, so the deployment must keep port 3310 on a private service network with no host or public-ingress publication. Network policy must allow the SecureStore workload to reach ClamD and deny unrelated workloads.

FreshClam is the only component that requires outbound access to the signature distribution service. ClamD and FreshClam share `/var/lib/clamav`; successful updates notify ClamD to reload. The database volume must not be shared with untrusted workloads and must not contain application uploads.

## Freshness policy

Production uses a 24-hour maximum database age and hourly FreshClam checks. ClamD's `VERSION` response must contain a safely parsed engine token, database version token, and database build timestamp. SecureStore interprets the timestamp in UTC because the deployment sets `TZ=UTC` and requires synchronized clocks. More than five minutes of future skew is invalid.

Production readiness requires all of the following:

- the daemon answers `PING` with the exact expected response;
- engine, database version, and database timestamp evidence parse safely;
- database age is no greater than the configured maximum;
- the scanner remains fail-closed;
- bounded `INSTREAM` inspection is configured.

Every inspection rechecks signature timestamp evidence immediately before streaming the quarantined object. Unavailable, malformed, stale, or materially future-dated evidence returns `inspection_unavailable`; it is never interpreted as a clean verdict.

## Rollout checklist

1. Select a supported feature release and record its lifecycle/EOL date, digest, approval, and rollback digest.
2. Validate the repository configuration and the exact image's ClamD/FreshClam parsers.
3. Initialize the persistent database volume and wait for a successful verified update.
4. Confirm UTC synchronization and private-network restrictions before connecting SecureStore.
5. Confirm administrator security and monitoring views show fresh signatures and production-ready posture.
6. Exercise harmless clean, harmless standard anti-malware, daemon-down, malformed-version, stale-database, timeout, and oversize scenarios.
7. Confirm scan results and audit evidence contain only safe decision categories—never signature names, daemon replies, paths, or uploaded content.

## Updates and engine lifecycle

Fresh signature databases do not make an unsupported engine safe. Operations must track both the feature release's security-support window and database freshness. Test a newer feature release in a non-production environment with clean/rejected/error fixtures, memory limits, queue load, timeouts, and rollback before promotion.

Use immutable image digests for the final deployment even when a feature tag is used during qualification. Replace instances through the orchestrator rather than modifying a running container. Preserve the database volume only after compatibility has been verified.

## Stale or failed updates

1. Keep upload decisions fail-closed and restrict new upload admission if the outage will create an unacceptable queue.
2. Check FreshClam status, DNS/HTTPS egress, database ownership, disk space, clock synchronization, and CDN availability.
3. Confirm FreshClam and ClamD reference the same database directory and that ClamD reloaded after the update.
4. Do not delete database files or increase the freshness threshold merely to clear monitoring without an approved incident action.
5. Resume normal admission only after the freshness gauge is `1`, production-ready posture is true, and controlled clean/rejected fixtures behave correctly.

## Detection and false positives

SecureStore deliberately stores only `malware_detected`, `policy_accepted`, or `inspection_unavailable`; raw signature names are not persisted or returned to users. A suspected false positive must be reproduced in an isolated security-analysis environment under the organization's malware-handling process. Do not email, attach, or export the user's file through ordinary support channels, and do not add unreviewed allow-list signatures to production.

## Evidence and monitoring

Retain deployment digest, engine version, database version, database timestamp, freshness policy, validation results, alert history, and change approvals in the approved operations system. Never place internal socket addresses, raw daemon responses, filenames, account data, or file content in external notifications.

The relevant alerts are `SecureStoreScannerNotProductionReady` and `SecureStoreScannerSignaturesStale`. Backup and disaster-recovery monitoring remain outside this scanner stage.
