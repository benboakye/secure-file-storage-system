# SecureStore monitoring deployment package

This directory provides a production-oriented Prometheus scrape template, an alert catalog, and a security-focused structural validator. It does not launch a collector, contact an external notification service, or contain deployment secrets.

## Files

- `prometheus.example.yml`: HTTPS scrape and internal Alertmanager template.
- `rules/securestore.rules.yml`: eighteen availability, security, integrity, scanner-freshness, managed-key-custody, independent-audit-anchor, processing, and capacity alerts.
- `validate.py`: repository-safe structural and security checks.
- `../../docs/monitoring-runbook.md`: response procedures and deployment checklist.

## Secret and certificate mounts

Provision these outside source control with access limited to the Prometheus service identity:

- `/etc/prometheus/secrets/securestore-metrics-token`: the same base64 bearer string injected into SecureStore through `SECURESTORE_METRICS_BEARER_TOKEN`;
- `/etc/prometheus/tls/securestore-ca.pem`: CA used to verify the SecureStore API certificate;
- `/etc/prometheus/tls/monitoring-ca.pem`: CA used to verify the internal Alertmanager certificate.

Do not copy `.data/metrics-token.key` into a production image. Create and distribute the production secret through the deployment secret manager. The example DNS names must be replaced with identities covered by the deployed certificates.

## Validation

From the repository root:

```powershell
python deploy/monitoring/validate.py
promtool check config deploy/monitoring/prometheus.example.yml
promtool check rules deploy/monitoring/rules/securestore.rules.yml
promtool test rules deploy/monitoring/tests/securestore.rules.test.yml
```

`promtool` is the authoritative Prometheus syntax checker. The Python validator adds project-specific security rules that `promtool` does not know about. Run both before deployment and after every monitoring change.

## Runtime controls

- Place Prometheus on a restricted management network; the public ingress must not expose `/metrics`.
- Run Prometheus as a non-root service with read-only configuration, rule, secret, and CA mounts.
- Configure explicit TSDB time and size retention through Prometheus startup flags based on approved evidence-retention requirements.
- Protect the Prometheus and Alertmanager web interfaces with TLS and organizational authentication.
- Do not enable remote write until its destination, encryption, authentication, retention, and data residency have been approved.
- Rotate the collector bearer by updating SecureStore and the mounted collector secret as one controlled change, then verify a successful scrape.

Backup monitoring is deliberately excluded from this package and remains deferred.
