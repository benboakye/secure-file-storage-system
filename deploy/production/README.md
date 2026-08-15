# Production transport and startup boundary

This package defines the fail-closed production transport profile. It does not provision certificates, DNS, a load balancer, private networks, PostgreSQL, SMTP, ClamAV, Prometheus, KMS/HSM resources, or the immutable audit ledger.

When `SECURESTORE_DEPLOYMENT_MODE=production`, SecureStore refuses to start unless:

- an HTTPS certificate and private-key file are configured;
- session cookies are `Secure`, `HttpOnly`, and `SameSite=Strict`;
- the public URL and every allowed browser origin use exact HTTPS origins;
- PostgreSQL uses `sslmode=verify-full`;
- ClamD, remote managed key custody, and remote audit anchoring are selected;
- privileged MFA and high-risk administrator step-up remain enabled;
- core secrets are injected or mounted outside the local `.data` directory.

TLS responses add HSTS, denial of framing, a restrictive API content-security policy, referrer protection, MIME sniffing protection, and a restrictive permissions policy. Development HTTP deliberately does not emit HSTS, preventing localhost testing from poisoning browser policy.

Run `python deploy/production/validate.py` before packaging. The next deployment-hardening slice is authenticated SMTP with certificate verification and bounded delivery behavior; until that is implemented and connected, production account verification remains a release blocker.
