# Local hosting

## Supported boundary

SecureStore can run entirely on one trusted workstation without Supabase or an external SMTP provider. This profile is intended for development, coursework demonstrations, and controlled local evaluation. It is not a public-internet production profile.

The local components are:

- the React interface on `127.0.0.1:5173`;
- the Go API on `127.0.0.1:8080`;
- PostgreSQL on a loopback address for durable accounts, sessions, metadata, and audit state;
- `.data/quarantine` and `.data/protected` for isolated and encrypted objects;
- `.data/mailbox` for private email-verification messages;
- owner-restricted local files for development KEK, MFA-encryption, audit-HMAC, audit-anchor, and metrics secrets.

Keeping every listener on loopback is essential. Plain HTTP, development keys, the filesystem mailbox, deterministic scanning, and a same-host audit anchor must not be exposed to another machine or represented as production controls.

## Configuration

Use the development deployment mode and keep the browser/API origins on loopback:

```text
SECURESTORE_DEPLOYMENT_MODE=development
SECURESTORE_LISTEN_ADDR=127.0.0.1:8080
SECURESTORE_PUBLIC_APP_URL=http://127.0.0.1:5173
SECURESTORE_ALLOWED_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
SECURESTORE_SECURE_COOKIES=false
SECURESTORE_DATABASE_URL=postgres://securestore:<local-password>@127.0.0.1:<port>/securestore?sslmode=disable
SECURESTORE_MAILBOX_DIR=.data/mailbox
SECURESTORE_QUARANTINE_DIR=.data/quarantine
SECURESTORE_PROTECTED_DIR=.data/protected
SECURESTORE_KEY_PROVIDER=local
SECURESTORE_AUDIT_ANCHOR_PROVIDER=local
SECURESTORE_SCANNER_MODE=deterministic
```

Use a strong local PostgreSQL password and do not commit it. `sslmode=disable` is acceptable only because both processes communicate over the same host's loopback interface. The application warns and falls back to volatile in-memory repositories if `SECURESTORE_DATABASE_URL` is absent; that fallback is unsuitable for meaningful persistence testing.

## Verification-message test

1. Register a standard-user account in the interface.
2. Confirm that registration does not create an authenticated session.
3. Open the newest owner-restricted text file in `.data/mailbox`.
4. Copy its verification URL into the same local browser.
5. Confirm the account, return to the sign-in page, and sign in manually.
6. Attempt to reuse the verification URL and confirm that the single-use token is rejected.

This is an integration test of account creation, token generation, token hashing and persistence, message rendering, verification consumption, and the no-automatic-login rule. It is not a test of DNS, SMTP authentication, sender reputation, delivery latency, spam filtering, or an external mailbox.

## Optional local services

ClamAV can be hosted locally and selected with `SECURESTORE_SCANNER_MODE=clamd`; its TCP listener must remain on loopback or a restricted private service boundary. A local SMTP capture tool can also be added later, but it offers no advantage over `.data/mailbox` unless testing SMTP protocol behavior is itself a requirement.

Backups remain deferred and the local audit anchor remains on the same host as the application. Consequently, this profile is not disaster-recovery-ready and cannot provide independently administered audit immutability.
