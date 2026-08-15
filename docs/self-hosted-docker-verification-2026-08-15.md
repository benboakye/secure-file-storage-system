# Self-hosted Docker verification — 2026-08-15

## Decision

**Pass for loopback-only local evaluation. Not approved for public production.**

The Docker profile builds and cold-starts the SecureStore frontend gateway, Go API, PostgreSQL database, and ClamAV scanner on the owner's workstation. Durable state survived a controlled API restart and a full Compose down/up cycle. The production deployment validator remains fail-closed because the external controls listed under “Deferred production boundaries” are not connected.

## Verified architecture

| Service | Runtime boundary | Host exposure | Persistent data |
| --- | --- | --- | --- |
| `gateway` | Nginx serving the compiled React application and reverse-proxying same-origin API requests | `127.0.0.1:8088` only | none |
| `api` | Compiled Go binary running as UID/GID 10001 with a read-only root filesystem | none | encrypted objects, quarantine, local mailbox, and local audit checkpoints |
| `postgres` | Pinned PostgreSQL 18 image on an internal database network | none | named database volume |
| `clamav` | ClamAV 1.5.3 with FreshClam updates and an internal scanner network | none | named signature database volume |
| `clamav-ready` | One-shot post-health reload and ping barrier | none | none |

The API is isolated from the host-facing ingress network. PostgreSQL and ClamAV are available only to services on their dedicated internal networks. ClamAV alone joins the outbound signature-update network. Compose secret files are read-only container mounts and are excluded from revision control.

## Verification evidence

| Gate | Result | Evidence |
| --- | --- | --- |
| Compose validation | PASS | `deploy/self-hosted/validate.ps1` accepted all required secret files and `docker compose config --quiet`. |
| Image build | PASS | The multi-stage API and gateway images built successfully. The frontend build reported 0 npm vulnerabilities across its production build dependency set. |
| Cold start | PASS | `docker compose down` followed by `up -d` recreated the stack while retaining named volumes. |
| Service health | PASS | Gateway, API, PostgreSQL, and ClamAV reported healthy after cold start. |
| Scanner admission barrier | PASS | `clamav-ready` exited with code 0 before API admission. `clamdscan --version` reported ClamAV `1.5.3/28093`. |
| Host exposure | PASS | Only the gateway published a port: `127.0.0.1:8088->8080/tcp`. API, PostgreSQL, and ClamAV published no host ports. |
| HTTP health | PASS | `GET /healthz` returned HTTP 200 with `{"status":"ok"}`. |
| Authentication boundary | PASS | An unauthenticated request to `/api/v1/session` returned HTTP 401. |
| Browser rendering | PASS | The sign-in page rendered at `http://127.0.0.1:8088/#signin` with no browser console warnings or errors. |
| Response headers | PASS | The gateway returned the configured Content Security Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. |
| Restart recovery | PASS | A controlled API restart returned to healthy state while PostgreSQL retained its durable volume. |
| Backend tests | PASS | `go test ./...` completed under the project-declared Go 1.26.6 toolchain. |
| Frontend tests | PASS | `npm run test:frontend` passed 6 of 6 tests. |
| Frontend build | PASS | `npm run build` completed TypeScript compilation and the Vite production bundle. |

## Security decisions retained

- The gateway and API run as non-root users with read-only root filesystems, dropped capabilities, `no-new-privileges`, PID limits, and resource limits.
- The published gateway port is bound to Windows loopback. The current profile is not reachable from another device without a separately configured ingress boundary.
- The API starts only after PostgreSQL is healthy and the ClamAV reload barrier succeeds. This prevents uploads from being admitted while the scanner is still using a stale startup database.
- The application remains in `development` deployment mode. Production validation was not relaxed to make the local stack pass.
- Secret values were never printed during verification. Generated secret files and runtime screenshots remain ignored by Git.

## Local visual evidence

The browser-verification screenshot is stored at `deploy/self-hosted/runtime/docker-signin-verified.png`. The runtime directory is intentionally ignored because it may later contain copied local verification email messages or other sensitive operational evidence. A report-ready copy should be reviewed and moved to an approved documentation evidence directory before publication.

## Deferred production boundaries

The local pass does not resolve these production requirements:

1. Resend or another approved transactional email provider and verified sender domain;
2. a named Cloudflare Tunnel with explicit public and privileged-route access policy;
3. Windows boot startup and post-reboot health verification;
4. HTTPS origins, secure cookies, edge and origin TLS controls;
5. PostgreSQL `sslmode=verify-full` with trusted certificate and server-name verification;
6. managed KMS/HSM key custody and independently administered audit anchoring;
7. external monitoring, alert delivery, backup, and recovery evidence.

Backup and recovery remain intentionally deferred, as recorded in the project deployment notes.

## Reproduction commands

From the repository root in PowerShell:

```powershell
pwsh -File .\deploy\self-hosted\init-secrets.ps1
pwsh -File .\deploy\self-hosted\validate.ps1
docker compose -f .\deploy\self-hosted\compose.yml build
docker compose -f .\deploy\self-hosted\compose.yml up -d
docker compose -f .\deploy\self-hosted\compose.yml ps --all
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8088/healthz
```

