# Authorization

## Model

Authorization combines coarse roles with object ownership and explicit grants. Authentication establishes who the subject is; authorization independently decides whether that subject may perform a specific action on a specific resource in its current lifecycle state.

Initial roles:

- `user`: manage owned files and grants within policy.
- `auditor`: view permitted security/audit metadata and run verification, but not file plaintext by default.
- `administrator`: manage accounts and policy-defined operations; no automatic plaintext access.

Privileged duties use separately provisioned credentials. A privileged session cannot be reused for standard file operations, and a standard session cannot become privileged through a role change. See [ADR 0001](adr/0001-separated-privileged-identities.md) and [Administrator Requirements](admin-requirements.md).

## Permission matrix

| Action | Owner | Active grantee | Auditor | Administrator |
|---|---:|---:|---:|---:|
| Upload/create | Yes | No | No | Policy only |
| View own metadata | Yes | If granted | Audit fields only | Policy only |
| View file/version metadata | Yes | `read` or `download` grant | No | Safe admin projection only |
| Download stored version | Yes | `download` grant | No | No |
| Create/update grant | Yes | No | No | Policy only |
| Revoke grant | Yes or issuer | No | No | Policy only |
| Delete/tombstone | Yes | No | No | Policy only |
| Restore version | Yes | No | No | No |
| Verify audit chain | Own/allowed scope | No | Yes | Yes |
| Change user role/status | No | No | No | Yes |

All `Yes` entries remain conditional on authentication state, resource state, policy, and any separation-of-duty rule.

## Grant model

A grant contains immutable IDs for grant, file, subject, issuer, allowed action set, creation time, optional expiry, and mutable revocation metadata. The authoritative predicate is roughly:

```text
allow if subject is active
  and resource is in a state valid for action
  and (subject is owner or matching grant is active or explicit role policy allows)
  and no higher-priority deny applies
```

An active grant has no revocation timestamp, is not expired, matches the resource and requested action, and was issued by an authorized actor. Wildcard grants are excluded from the initial prototype.

## Implemented prototype boundary

The owner can create or update one active grant per file/recipient with either `read` (metadata only) or `download` (metadata and authenticated plaintext download), plus an optional expiry. Recipients must be active, email-verified standard users; pending, suspended, auditor, and administrator identities are deliberately reported as unavailable. The **Shared with me** view is derived from active PostgreSQL grants, and revocation or expiry removes discovery and blocks new metadata/download requests immediately. Public links, group/wildcard grants, delegated grant administration, recipient restore, and administrator plaintext access are prohibited.

## Enforcement rules

- Route/middleware authentication is necessary but insufficient; the use-case layer performs object checks.
- Storage locators and wrapped keys are never direct authorization capabilities.
- Queries include tenant/owner/resource scope to reduce insecure direct object reference risk.
- Client-provided owner, role, grant state, and lifecycle state are ignored.
- Authorization checks include the server-side session audience (`user` or `privileged`) as well as the current database role.
- Role changes revoke existing sessions so a new privilege requires fresh authentication through the correct login boundary.
- User impersonation is prohibited; future emergency access requires a separately approved break-glass design.
- Batch operations authorize every object and use an explicit all-or-nothing or partial-result policy.
- Background workers carry a constrained service identity plus original actor/correlation context.
- Caches, if introduced, use short bounds and active invalidation; tests prove revocation behavior.
- Denials use consistent external responses while audit records retain safe reason codes.

## Revocation limitations

Revocation stops new mediated access. It cannot retract plaintext already downloaded or screenshots/copies made by an authorized user. Very long downloads may require cancellation checks or short-lived capabilities; the initial contract must define whether revocation affects an already authorized in-flight response.
