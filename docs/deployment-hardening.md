# Deployment hardening

## Implemented transport boundary

SecureStore has explicit `development` and `production` startup modes. Development preserves the current loopback HTTP workflow and local adapters. Production fails closed when HTTPS, secure cookies, verified PostgreSQL transport, remote scanner/key/anchor providers, privileged MFA, administrator step-up, or external secret sources are missing.

The API serves TLS directly in production with TLS 1.2 as the minimum protocol and bounded request headers and timeouts. HTTPS responses include HSTS and additional browser hardening headers. The checked-in transport template contains paths and public aliases only; it contains no private keys, bearer values, passwords, or certificates.

## Reverse-proxy boundary

Direct application TLS is the currently supported production mode. If a deployment later terminates TLS at a trusted reverse proxy, it must add an explicit trusted-proxy configuration and authenticated forwarding policy before the application may rely on forwarded scheme or client-address headers. SecureStore intentionally ignores forwarding headers today. Do not disable direct TLS or secure-cookie enforcement merely because an untrusted proxy supplies `X-Forwarded-Proto`.

## Remaining release blockers

- authenticated SMTP with certificate verification and secret-managed credentials when verification messages must be delivered to external inboxes (not required by the single-host local profile);
- actual private-network deployments of ClamAV, Prometheus, KMS/HSM broker, and immutable audit ledger;
- provider certificates, workload authorization, DNS, retention, and notification routing;
- final end-to-end security, failure-injection, and release validation;
- backups, which remain explicitly deferred.

These are production-release blockers, not claims about the supported single-host local workflow. Local hosting deliberately uses PostgreSQL on loopback, a private filesystem mailbox, local key material, a local audit checkpoint, and the development scanner unless the operator connects local ClamAV. See [Local hosting](local-hosting.md).
