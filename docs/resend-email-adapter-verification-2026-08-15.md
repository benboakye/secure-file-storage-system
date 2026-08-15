# Resend email-adapter verification — 2026-08-15

## Decision

**Pass for local transactional-email delivery.**

SecureStore successfully delivered a real account-verification message through Resend using the verified `mail.securevault.tech` sending subdomain. The recipient received the message and its single-use verification link. No recipient address, token, or API-key value is retained in this evidence document.

The verification link intentionally used the loopback application origin because the public Cloudflare boundary is not connected. Before public deployment, `SECURESTORE_PUBLIC_APP_URL` must change from `http://127.0.0.1:8088` to the approved HTTPS origin.

## Implemented boundary

- `ResendMailer` implements the existing `VerificationMailer` interface; token generation, hashing, expiry, one-time consumption, and manual post-verification sign-in remain unchanged.
- The provider request uses HTTPS, a fixed official API endpoint, a sending-only domain-restricted API key, and a ten-second timeout.
- Redirects are refused so the bearer credential and message payload cannot be forwarded to another endpoint.
- A deterministic SHA-256 idempotency key permits safe provider/network retry without placing the raw verification token in an HTTP header.
- Provider response bodies are discarded within a fixed bound and are not included in returned errors or logs.
- The Docker API reads the key from `/run/secrets/resend_api_key`; the key is absent from source code, Compose environment values, command history, logs, and revision control.
- Only the API joins the outbound `email-delivery` network. No additional inbound host port is published.
- `SECURESTORE_MAILER_MODE=file` preserves the private filesystem mailbox as an explicit development fallback.
- Production validation rejects the filesystem mailer and development secret paths.

## Verification evidence

| Gate | Result | Evidence |
| --- | --- | --- |
| Sending domain | PASS | Resend reported `mail.securevault.tech` verified in North Virginia (`us-east-1`) after DKIM, SPF, and return-path MX records were published. |
| Key scope | PASS | A dedicated key was created with Sending access restricted to `mail.securevault.tech`. |
| Secret installation | PASS after correction | The key was written through a masked prompt and passed non-disclosing format validation. An unnecessary ACL ownership reassignment failed under the ordinary Windows account and was removed; the file inherits the protected deployment-secret directory ACL. |
| Adapter tests | PASS | Tests cover request authentication, payload shape, token-safe idempotency, invalid configuration, official endpoint restriction, and provider-error redaction. |
| Complete Go suite | PASS | `go test ./...` passed after integration. |
| Compose validation | PASS | The required Resend secret and generated Compose configuration passed validation. |
| Runtime initialization | PASS | The API logged `verification mailer ready` with provider `resend` and reached healthy state without logging the key. |
| Live delivery | PASS | A newly registered standard user received the external verification message and local single-use link. |

## Operational guidance

To rotate the key, create a replacement key with Sending access restricted to `mail.securevault.tech`, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\deploy\self-hosted\set-resend-secret.ps1" -Replace
docker compose -f .\deploy\self-hosted\compose.yml up -d --force-recreate api
```

Complete a delivery test before revoking the previous key in Resend. Never include the key, recipient addresses, or active verification links in screenshots or project reports.

## Remaining work

1. Publish the application through the approved Cloudflare Tunnel boundary.
2. Set `SECURESTORE_PUBLIC_APP_URL` and allowed origins to `https://securevault.tech` and enable secure cookies.
3. Repeat registration, verification, expiry, replay, and resend testing using the public HTTPS origin.
4. Add DMARC monitoring for the sending subdomain, then strengthen its policy only after reviewing legitimate delivery results.
5. Add delivery-event webhook processing later for bounce, complaint, and suppression evidence.

