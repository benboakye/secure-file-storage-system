# Deferred self-hosted deployment plan

Last reviewed: 2026-08-15

Implementation is intentionally deferred until the remaining local release-control work is complete.

The selected direction is a Docker Compose deployment hosted on the owner's Windows laptop. A named Cloudflare Tunnel will publish the application domain without router port forwarding. Containers will cover the production web gateway, compiled SecureStore API, PostgreSQL, ClamAV/FreshClam, and `cloudflared`. Resend will remain an external HTTPS email provider and will replace the development filesystem mailbox for verification and privileged-invitation delivery.

The deployment stage must include production static-file serving, loopback/private-only service networking, verified TLS, secure cookies, exact HTTPS origins, persistent encrypted-storage volumes, secret-file injection, health checks, restart policies, separate public and privileged host boundaries, and documented Windows boot behavior. Docker Desktop start-on-sign-in is not equivalent to unattended startup immediately after boot, so the final implementation must explicitly test the chosen Windows startup mechanism.

This decision does not waive the existing production requirements for a live ClamAV service, PostgreSQL certificate verification, managed non-exportable key custody, an independently administered immutable audit anchor, monitoring and alerts, or external backup evidence. Backup implementation remains deferred separately.
