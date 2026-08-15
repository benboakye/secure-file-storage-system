# Deferred self-hosted deployment plan

Last reviewed: 2026-08-15

The Docker foundation entered implementation on 2026-08-15 after the baseline pull request and remote CI gates passed. Resend delivery was implemented and locally verified later that day. Cloudflare Tunnel publication, Windows boot startup, and the remaining production service boundaries are still deferred to subsequent slices.

The selected direction is a Docker Compose deployment hosted on the owner's Windows laptop. A named Cloudflare Tunnel will publish the application domain without router port forwarding. Containers will cover the production web gateway, compiled SecureStore API, PostgreSQL, ClamAV/FreshClam, and `cloudflared`. Resend now provides external HTTPS verification and privileged-invitation delivery; the development filesystem mailbox remains an explicit fallback.

The deployment stage must include production static-file serving, loopback/private-only service networking, verified TLS, secure cookies, exact HTTPS origins, persistent encrypted-storage volumes, secret-file injection, health checks, restart policies, separate public and privileged host boundaries, and documented Windows boot behavior. Docker Desktop start-on-sign-in is not equivalent to unattended startup immediately after boot, so the final implementation must explicitly test the chosen Windows startup mechanism.

The first implemented slice is documented in `deploy/self-hosted/README.md`. It deliberately uses a loopback-only local gateway and the existing fail-closed development profile. Containerization alone does not satisfy the production validator or authorize public exposure.

This decision does not waive the existing production requirements for a live ClamAV service, PostgreSQL certificate verification, managed non-exportable key custody, an independently administered immutable audit anchor, monitoring and alerts, or external backup evidence. Backup implementation remains deferred separately.
