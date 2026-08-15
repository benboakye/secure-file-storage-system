# Continuous integration

## Purpose

`.github/workflows/ci.yml` turns the local release gates into required, repeatable evidence on every push and pull request targeting `main`. It may also be started manually through `workflow_dispatch`.

The workflow is verification-only. Its repository token has `contents: read`, checkout does not persist credentials, and no deployment, Cloudflare, Resend, database-production, KMS, audit-anchor, or application secret is supplied.

## Jobs

### Backend, PostgreSQL, and security analysis

The backend job starts a disposable PostgreSQL 18 service pinned by digest. It runs the complete Go suite with all nine opt-in PostgreSQL tests enabled, followed by `go vet`, Staticcheck v0.7.0, and `govulncheck` v1.7.0. Database credentials and the audit HMAC value are fixed CI-only test material and must never be reused outside the disposable job.

### Race detector with PostgreSQL

The race job uses an independent disposable PostgreSQL database and runs `go test -race -count=1 ./...`. This covers both in-memory paths and the database-backed tests under race instrumentation. Its longer timeout accounts for bcrypt cost and race-detector overhead without changing production server timeouts.

### Frontend tests, audit, and production build

The frontend job installs exactly `package-lock.json` through `npm ci`, fails on any npm vulnerability severity, executes the focused frontend tests, and compiles the production Vite bundle. Package-manager caching is disabled to reduce hidden state in this security-sensitive workflow.

## Supply-chain controls

- GitHub-maintained actions are pinned to immutable full commit SHAs, with the reviewed release tag retained in a comment.
- Go, Node.js, Staticcheck, and `govulncheck` versions are explicit.
- PostgreSQL is pinned to the reviewed official-image digest used by local integration verification.
- The workflow does not use mutable `latest` action or container references.
- Jobs have bounded execution time and concurrent runs for the same ref cancel obsolete work.

Action and container pins must be updated through a reviewed change that confirms the upstream release, reruns all gates, and records any security-relevant behavior change.

## Branch protection

The private repository currently uses GitHub Free, which does not provide protected branches for private repositories. The project therefore applies a documented manual merge gate: work remains on a feature branch, all three checks must complete successfully, the pull-request result must be reviewed, and only then may the change be merged to `main`. Force pushes and direct pushes to `main` are prohibited by project procedure even though GitHub cannot enforce that prohibition on the current plan.

If the repository moves to GitHub Pro, Team, or Enterprise, settings should enforce these controls technically by requiring all three job checks, requiring pull-request review, dismissing stale approvals after new commits, and preventing force pushes or deletion of `main`.

## First remote run evidence

Pull request [#1](https://github.com/benboakye/secure-file-storage-system/pull/1) produced the first successful remote run on August 15, 2026. [GitHub Actions run 31876728937](https://github.com/benboakye/secure-file-storage-system/actions/runs/31876728937) completed with status **Success** in 5 minutes 28 seconds:

- Backend, PostgreSQL, and security analysis: **PASS** in 2 minutes 19 seconds.
- Go race detector with PostgreSQL: **PASS** in 5 minutes 23 seconds.
- Frontend tests, audit, and production build: **PASS** in 20 seconds.

The captured run summary is retained as [`testing/evidence/github-actions-run-31876728937-success.png`](testing/evidence/github-actions-run-31876728937-success.png). The two earlier `startup_failure` records were GitHub account-billing admission failures: no job runner started and no project code was executed. A fresh run queued normally after the account-plan issue was resolved.
