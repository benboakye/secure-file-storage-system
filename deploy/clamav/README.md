# SecureStore ClamAV deployment package

This package defines the production scanner boundary without starting or connecting a daemon in the development environment. It uses ClamD for bounded `INSTREAM` scanning and FreshClam for hourly database checks. The database persists across container replacement and is shared by both processes.

## Required deployment decisions

1. Set `CLAMAV_FEATURE_TAG` to a currently supported, security-approved ClamAV feature release. Do not use `latest`, `stable`, or `unstable` in a controlled production deployment.
2. Make the SecureStore API join the `securestore-scanner` network and set:
   - `SECURESTORE_SCANNER_MODE=clamd`
   - `SECURESTORE_CLAMD_NETWORK=tcp`
   - `SECURESTORE_CLAMD_ADDRESS=clamav:3310`
   - `SECURESTORE_CLAMD_MAX_SIGNATURE_AGE_HOURS=24`
3. Keep TCP 3310 absent from host and public-ingress port mappings. ClamD TCP provides neither authentication nor transport encryption.
4. Permit narrowly scoped outbound DNS and HTTPS from FreshClam to the approved ClamAV database distribution service. ClamD does not need public ingress.
5. Configure container and host clocks for UTC synchronization. SecureStore permits at most five minutes of future skew in database timestamp evidence.

## Validation

```powershell
python deploy/clamav/validate.py
$env:CLAMAV_FEATURE_TAG='approved-feature-tag'
docker compose -f deploy/clamav/compose.example.yml config --quiet
```

During deployment qualification, validate `clamd.conf` and `freshclam.conf` with the exact approved image, wait for the database volume to initialize, and confirm container health before sending any SecureStore upload. Then verify:

- `PING` returns `PONG` only over the private scanner network;
- `VERSION` includes safely parseable engine, database version, and UTC database timestamp fields;
- administrator posture reports `signaturesFresh=true` and `productionReady=true`;
- `securestore_scanner_signatures_fresh` equals `1`;
- the standard harmless anti-malware test fixture is rejected, while a harmless ordinary fixture is accepted;
- stopping ClamD, corrupting VERSION output, or exceeding the 24-hour threshold causes uploads to fail closed as `inspection_unavailable`.

See [ClamAV operations](../../docs/clamav-operations.md) for rollout, rotation, incident response, and evidence requirements.
