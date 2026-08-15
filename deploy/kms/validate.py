"""Validate the repository-safe managed-key deployment configuration."""

from __future__ import annotations

from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(bool(separator and key and value), f"invalid environment entry: {raw}")
        values[key] = value
    return values


def main() -> int:
    try:
        environment = read_environment(ROOT / "securestore.env.example")
        require(environment.get("SECURESTORE_KEY_PROVIDER") == "remote", "production template must select remote custody")
        require(environment.get("SECURESTORE_KMS_ENDPOINT", "").startswith("https://"), "key broker must use HTTPS")
        require(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", environment.get("SECURESTORE_KMS_KEY_ID", "")) is not None, "key ID must be a safe broker alias")
        require(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", environment.get("SECURESTORE_KMS_KEY_VERSION", "")) is not None, "key version must be bounded")
        for variable in ("SECURESTORE_KMS_CA_FILE", "SECURESTORE_KMS_CLIENT_CERT_FILE", "SECURESTORE_KMS_CLIENT_KEY_FILE"):
            require(environment.get(variable, "").startswith("/run/secrets/"), f"{variable} must reference a mounted secret")
        require("SECURESTORE_LOCAL_KEK" not in environment, "production template must not contain a local KEK")

        contract = yaml.safe_load((ROOT / "key-broker.openapi.yaml").read_text(encoding="utf-8"))
        require(contract.get("openapi") == "3.1.0", "key-broker contract must use OpenAPI 3.1")
        require(set(contract.get("paths", {})) == {"/v1/status", "/v1/wrap", "/v1/unwrap"}, "key-broker surface must remain minimal")
        require(contract["components"]["securitySchemes"]["mutualTLS"]["type"] == "mutualTLS", "broker must require mutual TLS")
        serialized = yaml.safe_dump(contract).lower()
        require("debug" not in serialized and "errorbody" not in serialized, "broker contract must not expose provider diagnostics")
    except (OSError, KeyError, TypeError, yaml.YAMLError, AssertionError) as error:
        print(f"managed key deployment validation failed: {error}", file=sys.stderr)
        return 1
    print("managed key deployment boundary validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
