# Local end-to-end verification

## Run: 2026-08-14

This run exercised the live React application, Go API, local PostgreSQL repositories, filesystem mailbox, quarantine, and protected storage through the browser. Synthetic identities and a harmless 164-byte text artifact were used. Passwords and verification tokens are intentionally excluded from this record.

## Passed

- Standard-user registration created a pending account and did not create a session.
- The verification message was written to the private `.data/mailbox` adapter.
- Opening a verification URL did not activate the account until the explicit confirmation button was pressed.
- Successful verification still created no session and required manual sign-in.
- Reusing the consumed token returned the generic invalid-or-expired response.
- The verified standard user signed in through the standard audience and reached the user workspace.
- A harmless text file moved through upload, quarantine, inspection, policy acceptance, AES-256-GCM protection, and the durable protected-file catalog.
- Owner download triggered only through an authenticated session.
- A second verified standard user received an explicit `download` grant and discovered the file through the authoritative **Shared with me** endpoint.
- Recipient download triggered while the grant was active.
- Revocation removed the file immediately from the recipient's authoritative shared-file view.
- A standard-user session could not enter `#admin-audit`; routing returned it to the standard workspace.
- The Go package suite and the frontend production build passed immediately before this browser run.

## Not fully browser-verified

- The browser client blocked direct navigation to the old download URL after revocation before the request reached the application. Server-side grant-revocation denial remains covered by the passing Go authorization tests.
- Organization audit-chain verification requires a dedicated administrator or auditor identity plus MFA. No privileged credential or TOTP secret was reused or extracted during this run.
- The in-app browser continued to report a 1265-pixel document viewport after a requested 390-pixel override. Mobile layout therefore needs a dedicated responsive-browser pass before it can be marked verified.

## Truthful product limitations observed

- The standard-user **Audit activity** page is not connected to an owner-scoped audit API. It states this limitation and shows no invented demonstration events.
- Historical browser logs contained `SecurityComplianceView` errors involving missing `productionReady` posture data. They were not reproducible from the unprivileged route because the privileged boundary correctly denied access; reproduce and resolve them in a fresh privileged session.
- The local scanner, key provider, audit anchor, mailbox, and secret files remain development controls. This run does not establish production readiness, external email delivery, independent audit immutability, managed HSM custody, or disaster recovery.

## Test records created

- `local-e2e-20260814-01@example.test` — verified standard user and file owner.
- `local-e2e-recipient-20260814-01@example.test` — verified standard user and temporary recipient.
- `outputs/local-e2e-upload.txt` — harmless source artifact.
- One protected logical file named `local-e2e-upload.txt`; its temporary access grant was revoked at the end of the sharing test.

The database identities and protected file are intentionally retained so the administrator dashboards can be checked against real local records. Remove them later only through the application's controlled lifecycle and account-governance workflows.
