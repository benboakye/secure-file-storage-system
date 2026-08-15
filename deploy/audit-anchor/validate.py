"""Validate the repository-safe independent audit-anchor boundary."""

from __future__ import annotations

from pathlib import Path
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
        require(environment.get("SECURESTORE_AUDIT_ANCHOR_PROVIDER") == "remote", "production template must select the remote anchor")
        require(environment.get("SECURESTORE_AUDIT_ANCHOR_ENDPOINT", "").startswith("https://"), "anchor must use HTTPS")
        for variable in (
            "SECURESTORE_AUDIT_ANCHOR_CA_FILE",
            "SECURESTORE_AUDIT_ANCHOR_CLIENT_CERT_FILE",
            "SECURESTORE_AUDIT_ANCHOR_CLIENT_KEY_FILE",
            "SECURESTORE_AUDIT_ANCHOR_RECEIPT_PUBLIC_KEY_FILE",
        ):
            require(environment.get(variable, "").startswith("/run/secrets/"), f"{variable} must reference a mounted trust or identity file")
        require("SECURESTORE_AUDIT_ANCHOR_KEY" not in environment, "production template must not provide a receipt signing secret to SecureStore")
        require("SECURESTORE_AUDIT_ANCHOR_FILE" not in environment, "production template must not select the on-host anchor")

        contract = yaml.safe_load((ROOT / "anchor.openapi.yaml").read_text(encoding="utf-8"))
        require(contract.get("openapi") == "3.1.0", "anchor contract must use OpenAPI 3.1")
        require(set(contract.get("paths", {})) == {"/v1/status", "/v1/checkpoints", "/v1/checkpoints/latest"}, "anchor surface must remain minimal")
        require(contract["components"]["securitySchemes"]["mutualTLS"]["type"] == "mutualTLS", "anchor must require mutual TLS")
        serialized = yaml.safe_dump(contract).lower()
        require("privatekey" not in serialized and "debug" not in serialized, "contract must not expose signing secrets or diagnostics")
    except (OSError, KeyError, TypeError, yaml.YAMLError, AssertionError) as error:
        print(f"audit-anchor deployment validation failed: {error}", file=sys.stderr)
        return 1
    print("independent audit-anchor deployment boundary validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
