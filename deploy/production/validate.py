"""Validate the repository-safe production transport profile."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse
import sys


ROOT = Path(__file__).resolve().parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def environment() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in (ROOT / "transport.env.example").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(bool(separator and key and value), f"invalid environment entry: {raw}")
        values[key] = value
    return values


def main() -> int:
    try:
        values = environment()
        require(values.get("SECURESTORE_DEPLOYMENT_MODE") == "production", "template must select production mode")
        for variable in ("SECURESTORE_TLS_CERT_FILE", "SECURESTORE_TLS_KEY_FILE"):
            require(values.get(variable, "").startswith("/run/secrets/"), f"{variable} must reference a mounted secret")
        for variable in ("SECURESTORE_PUBLIC_APP_URL", "SECURESTORE_ALLOWED_ORIGINS"):
            parsed = urlparse(values.get(variable, ""))
            require(parsed.scheme == "https" and bool(parsed.netloc) and not parsed.path and not parsed.query, f"{variable} must be an exact HTTPS origin")
        require(values.get("SECURESTORE_SECURE_COOKIES") == "true", "secure cookies must be required")
        database = urlparse(values.get("SECURESTORE_DATABASE_URL", ""))
        query = parse_qs(database.query)
        require(database.scheme in {"postgres", "postgresql"} and bool(database.hostname), "PostgreSQL URL is required")
        require(query.get("sslmode") == ["verify-full"], "PostgreSQL must verify CA and host identity")
        require(values.get("SECURESTORE_SCANNER_MODE") == "clamd", "production must select clamd")
        require(values.get("SECURESTORE_KEY_PROVIDER") == "remote", "production must select remote key custody")
        require(values.get("SECURESTORE_AUDIT_ANCHOR_PROVIDER") == "remote", "production must select remote audit anchoring")
        require(values.get("SECURESTORE_REQUIRE_PRIVILEGED_MFA") == "true", "privileged MFA cannot be disabled")
        require(values.get("SECURESTORE_REQUIRE_ADMIN_STEP_UP") == "true", "administrator step-up cannot be disabled")
        for variable in ("SECURESTORE_AUDIT_HMAC_KEY_FILE", "SECURESTORE_MFA_ENCRYPTION_KEY_FILE", "SECURESTORE_METRICS_TOKEN_FILE"):
            require(values.get(variable, "").startswith("/run/secrets/"), f"{variable} must be externally mounted")
        serialized = (ROOT / "transport.env.example").read_text(encoding="utf-8").lower()
        require("sslmode=disable" not in serialized and ".data/" not in serialized, "production template contains a development transport or secret path")
    except (OSError, AssertionError) as error:
        print(f"production transport validation failed: {error}", file=sys.stderr)
        return 1
    print("production HTTPS and startup-boundary validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
