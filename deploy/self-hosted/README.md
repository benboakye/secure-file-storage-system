# Self-hosted Docker profile

## Scope

This profile packages SecureStore for controlled local hosting on the owner's Windows workstation. It provides a compiled React gateway, compiled Go API, durable PostgreSQL state, persistent encrypted-object storage, and ClamAV/FreshClam on isolated Docker networks.

This is not the public production profile. The API intentionally remains in `development` deployment mode because managed KMS/HSM custody, independently administered audit anchoring, verified PostgreSQL TLS, Resend delivery, Cloudflare edge configuration, monitoring, and backup evidence are not yet connected. The production validator remains fail-closed and has not been weakened.

## Security boundaries

| Component | Host exposure | Persistent state | Network access |
| --- | --- | --- | --- |
| Gateway | `127.0.0.1:8088` by default | none | private application network |
| API | none | encrypted objects, quarantine, local mailbox, local audit checkpoints | private application, database, and scanner networks |
| PostgreSQL | none | `postgres-data` volume | private database network only |
| ClamAV | none | signature database volume | private scanner network plus outbound signature updates |
| ClamAV readiness barrier | none | none | private scanner network only; reloads startup signatures before API admission |

The gateway and API run as non-root users with read-only root filesystems, dropped Linux capabilities, `no-new-privileges`, PID limits, memory limits, CPU limits, health checks, and `unless-stopped` restart policies. PostgreSQL and ClamAV are never published to the Windows host.

Compose secrets are files protected by Windows ACLs and mounted read-only into containers. Docker Compose secrets do not provide the encrypted-at-rest secret management of a managed orchestrator, so this remains a single-owner local boundary.

## First start

Run these commands from the repository root in PowerShell:

```powershell
pwsh -File .\deploy\self-hosted\init-secrets.ps1
pwsh -File .\deploy\self-hosted\validate.ps1
docker compose -f .\deploy\self-hosted\compose.yml build
docker compose -f .\deploy\self-hosted\compose.yml up -d
docker compose -f .\deploy\self-hosted\compose.yml ps
```

ClamAV's first signature download can take several minutes. A one-shot readiness barrier reloads the downloaded database after ClamD is healthy. The API waits for PostgreSQL and that barrier, and the gateway waits for the API.

Open [http://127.0.0.1:8088](http://127.0.0.1:8088). To choose another loopback port for the current PowerShell session, set `$env:SECURESTORE_HOST_PORT` before starting the stack.

## Local verification email

The filesystem mailbox is retained for this stage. List messages without printing their contents into container logs:

```powershell
docker compose -f .\deploy\self-hosted\compose.yml exec api sh -lc 'ls -1t /var/lib/securestore/mailbox'
```

Copy a selected message to an ignored host runtime directory, then open it locally:

```powershell
New-Item -ItemType Directory -Force .\deploy\self-hosted\runtime | Out-Null
docker compose -f .\deploy\self-hosted\compose.yml cp api:/var/lib/securestore/mailbox/<message-name>.txt .\deploy\self-hosted\runtime\verification-message.txt
```

Do not publish mailbox files: they contain active single-use verification links.

## Operations

View service health and bounded recent logs:

```powershell
docker compose -f .\deploy\self-hosted\compose.yml ps
docker compose -f .\deploy\self-hosted\compose.yml logs --tail 100 gateway api postgres clamav
```

Stop the running containers while retaining all durable volumes:

```powershell
docker compose -f .\deploy\self-hosted\compose.yml stop
```

`docker compose down` removes containers and networks but retains named volumes. Do not add `--volumes` unless permanent deletion of the database, encrypted objects, quarantine, mailbox, and ClamAV database is explicitly intended and separately backed up.

## Remaining deployment stages

1. Add the Resend HTTPS mail adapter and rotate from the filesystem mailbox.
2. Add a named Cloudflare Tunnel and separate public/privileged host routing.
3. Define and test Windows boot startup rather than relying only on interactive sign-in.
4. Connect managed key custody, independent audit anchoring, external monitoring, verified PostgreSQL TLS, and approved TLS boundaries.
5. Implement and test backup/recovery later, as explicitly deferred in the release plan.
