# SecureStore managed key custody package

SecureStore remains cloud-provider neutral by communicating with a small private key broker over mutual TLS. The broker maps a bounded SecureStore key alias/version to an approved managed KMS or HSM key and exposes only status, wrap, and unwrap operations.

The SecureStore process never loads a plaintext KEK. A plaintext 32-byte DEK exists in application memory only while encrypting or decrypting one file and is cleared on completed paths where Go permits best-effort zeroization. Wrapped DEKs remain in PostgreSQL metadata; encrypted file ciphertext remains in protected storage.

## Deployment requirements

- Implement [key-broker.openapi.yaml](key-broker.openapi.yaml) in the chosen trusted key-management environment.
- Require client certificates issued to the SecureStore workload identity. Do not add shared bearer tokens or query-string credentials.
- Grant that identity only status, wrap with the active version, and unwrap with explicitly retained historical versions.
- Back every production-ready key with an approved HSM/managed hardware cryptographic module. Software-only custody must report `hardwareBacked=false`.
- Keep the broker on a private management network and prohibit public ingress, redirects, and plaintext HTTP.
- Disable request/response body logging, tracing payload capture, crash dumps containing bodies, and debug error forwarding.
- Configure provider-native immutable audit logging for key administration and cryptographic operations without recording DEK material.

Validate the checked-in boundary:

```powershell
python deploy/kms/validate.py
python -c "import yaml; yaml.safe_load(open('deploy/kms/key-broker.openapi.yaml', encoding='utf-8')); print('key-broker OpenAPI parsed successfully')"
```

Actual provider credentials, key creation, HSM policy, certificate issuance, audit destination, and network controls remain deployment inputs. See [KMS/HSM operations](../../docs/kms-operations.md).
