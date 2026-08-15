"""Validate the repository-safe ClamAV deployment boundary.

The checks prevent accidental host publication, unbounded streams, mismatched
database paths, disabled signature updates, and a floating image tag. Actual
ClamD/FreshClam parsing must also be performed with the approved production
image during deployment qualification.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def directives(path: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" ")
        require(bool(separator and value.strip()), f"invalid directive in {path.name}: {raw_line}")
        result.setdefault(key, []).append(value.strip())
    return result


def main() -> int:
    try:
        compose = yaml.safe_load((ROOT / "compose.example.yml").read_text(encoding="utf-8"))
        service = compose["services"]["clamav"]
        require("ports" not in service, "ClamD must not publish a host port")
        require("latest" not in service["image"] and "stable" not in service["image"], "ClamAV image must use an approved feature tag")
        require(service.get("environment", {}).get("FRESHCLAM_CHECKS") == "24", "FreshClam must check hourly")
        require(any("/var/lib/clamav" in volume for volume in service.get("volumes", [])), "signature database must be persistent")
        require("no-new-privileges:true" in service.get("security_opt", []), "container must prevent privilege escalation")

        clamd = directives(ROOT / "clamd.conf")
        freshclam = directives(ROOT / "freshclam.conf")
        require(clamd.get("TCPSocket") == ["3310"], "ClamD must use the private standard port")
        require(clamd.get("DatabaseDirectory") == freshclam.get("DatabaseDirectory") == ["/var/lib/clamav"], "ClamD and FreshClam must share one database directory")
        require(clamd.get("StreamMaxLength") == ["26M"], "stream size must remain bounded to the upload policy")
        require(clamd.get("BytecodeSecurity") == ["TrustSigned"], "unsigned bytecode signatures must not execute")
        require(freshclam.get("Checks") == ["24"], "FreshClam must check hourly")
        require(freshclam.get("NotifyClamd") == ["/etc/clamav/clamd.conf"], "ClamD must be notified after database updates")
        require(not any(re.search(r"(?i)(password|proxy|credential|token)", key) for key in freshclam), "repository config must not contain update credentials")
    except (OSError, KeyError, TypeError, yaml.YAMLError, AssertionError) as error:
        print(f"clamav deployment validation failed: {error}", file=sys.stderr)
        return 1
    print("clamav deployment boundary validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
