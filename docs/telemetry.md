# External telemetry foundation

## Export boundary

SecureStore exposes Prometheus-compatible metrics at `GET /metrics`. The endpoint is disabled when no metrics token is configured and returns `404` in that state. When enabled, it accepts only `Authorization: Bearer <token>` and does not accept browser sessions, cookies, administrator roles, query-string credentials, or CSRF tokens as substitutes.

Local development creates a persistent 32-byte token in `.data/metrics-token.key`. Production must inject `SECURESTORE_METRICS_BEARER_TOKEN` as exactly 32 random bytes encoded with base64 through a secret manager. The token must be delivered to the collector separately, never placed in a URL, committed to source control, or written to application logs. TLS and network-level access control remain mandatory at deployment because bearer authentication does not encrypt transport.

## Privacy and cardinality

HTTP metrics use only a bounded method, the registered route template, and status class. For example, a request for `/api/v1/uploads/upl_secret` is labelled `/api/v1/uploads/{uploadId}`. The following values are prohibited from metrics and labels:

- user IDs, names, and email addresses;
- upload, file, version, grant, session, or correlation identifiers;
- filenames, media contents, object names, filesystem paths, or digests;
- bearer tokens, cookies, credentials, keys, raw IP addresses, or error messages.

Operational gauges contain aggregate queue depth, failed-record count, quarantine bytes, orphan counts, configured capacity, safety reserve, active reservations, protected-object counts, pending audit evidence, persistence posture, and scanner capability. Labels do not contain owner or file dimensions.

## Connection evidence

An enabled exporter is not automatically described as an external telemetry connection. The administrator monitoring endpoint reports:

- whether the exporter is enabled;
- successful authenticated scrape count;
- last successful scrape time;
- the configured stale threshold.

`externalTelemetryConnected` becomes true only after a successful authenticated scrape and returns false when the last scrape is older than `SECURESTORE_METRICS_STALE_AFTER_SECONDS` (five minutes by default). Unauthorized attempts do not refresh this evidence.

## Exported metric families

- `securestore_http_requests_total`
- `securestore_http_request_duration_seconds_sum` and `_count`
- `securestore_telemetry_scrapes_total`
- API uptime and ingestion queue/failure gauges
- quarantine, capacity-reservation, and protected-object gauges
- audit-outbox backlog
- durable-repository flags; scanner connection, production-readiness, signature-freshness, database-age, and maximum-age gauges; and aggregate key-service connection, production-readiness, and hardware-custody gauges

The exporter is process-local for HTTP counters and duration sums. Durable business-state gauges are rebuilt from authoritative repositories on every scrape. A production collector should aggregate across instances using its own instance labels; SecureStore deliberately does not accept an instance label from clients.

## Deployment package and remaining work

`deploy/monitoring` now supplies a certificate-verifying Prometheus scrape template, eighteen availability/security/integrity/scanner/key-custody/audit-anchor/capacity alerts, executable rule tests, and project-specific security validation. The accompanying [monitoring runbook](monitoring-runbook.md) defines severity, ownership, investigation boundaries, and safe response procedures. The package keeps the bearer in a mounted secret file and never embeds it in configuration.

Deployment must still provide the real internal DNS names and certificates, install the production bearer through a secret manager, select explicit TSDB retention limits, restrict the metrics network path, deploy the collector, and connect Alertmanager to an approved incident-management destination. Until those actions are completed, the checked-in package is deployment-ready configuration rather than evidence that external notification delivery is operational. Backup monitoring remains deferred and is not represented as connected.
