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

After the workflow exists on GitHub, repository settings should require all three job checks before merging to `main`, require pull-request review, dismiss stale approvals after new commits, and prevent force pushes or deletion of `main`. Branch protection is external GitHub configuration and is not established merely by committing the workflow file.
