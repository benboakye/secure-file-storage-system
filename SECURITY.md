# Security Policy

## Project status

This repository is an educational prototype under active design. It must not be used to protect production or sensitive data until its implementation, review, and operational controls are complete.

## Reporting a vulnerability

Do not publish exploit details, credentials, keys, or sensitive files in a public issue. Contact the repository owner privately through an appropriate GitHub security-reporting channel. Include the affected revision, impact, reproduction steps using safe synthetic data, and any suggested mitigation. Allow time for validation and remediation before public disclosure.

## Safe research and testing

- Test only systems and accounts you own or are authorized to assess.
- Do not upload live malware. Use harmless fixtures or a recognized anti-malware test string where supported.
- Do not execute uploaded samples; dynamic file security analysis is out of scope.
- Do not commit credentials, tokens, private keys, real user data, scanner licenses, or production configuration.
- Use test-only keys and synthetic files; assume anything committed to Git history is public.
- Avoid denial-of-service testing against shared services. Resource-limit tests must be bounded and local.

## Sensitive data handling

Plaintext, DEKs, authentication secrets, and session values must not appear in logs, audit records, errors, fixtures, screenshots, or bug reports. Suspected secret exposure requires revocation/rotation and history review; deleting the visible file alone is not sufficient.

## Security update expectations

Security-relevant changes should include threat and requirement references, tests for the failure mode, and updates to affected architecture or ADR documents. Dependency findings are triaged by reachability, exploitability, impact, and available remediation rather than score alone.
