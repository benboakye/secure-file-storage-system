"""Validate SecureStore's monitoring package without reading deployment secrets.

This structural validator supplements, but does not replace, `promtool check
config` and `promtool check rules`. Its security assertions prevent accidental
inline credentials, plaintext scraping, sensitive metric dimensions, and loss
of the alert classes required by the monitoring design.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "prometheus.example.yml"
RULES_PATH = ROOT / "rules" / "securestore.rules.yml"
RULE_TESTS_PATH = ROOT / "tests" / "securestore.rules.test.yml"

FORBIDDEN_TERMS = {
    "email",
    "filename",
    "file_id",
    "owner_id",
    "path",
    "session_id",
    "token",
    "upload_id",
    "user_id",
}

REQUIRED_ALERTS = {
    "SecureStoreTargetDown",
    "SecureStoreMetricsTargetMissing",
    "SecureStoreElevatedServerErrors",
    "SecureStoreSustainedRequestLatency",
    "SecureStoreScannerNotProductionReady",
    "SecureStoreScannerSignaturesStale",
    "SecureStoreRepositoryNotDurable",
    "SecureStoreKeyServiceUnavailable",
    "SecureStoreKeyCustodyNotProductionReady",
    "SecureStoreProtectedObjectMissing",
    "SecureStoreAuditEvidenceBacklog",
    "SecureStoreAuditAnchorUnavailable",
    "SecureStoreAuditAnchorNotProductionReady",
    "SecureStoreAuditAnchorInvalidOrLagging",
    "SecureStoreIngestionFailures",
    "SecureStoreProcessingBacklog",
    "SecureStoreCapacityPressure",
    "SecureStoreOrphanObjectsDetected",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as source:
        parsed = yaml.safe_load(source)
    require(isinstance(parsed, dict), f"{path.name} must contain a YAML object")
    return parsed


def validate_config(config: dict) -> None:
    jobs = config.get("scrape_configs", [])
    securestore_jobs = [job for job in jobs if job.get("job_name") == "securestore-api"]
    require(len(securestore_jobs) == 1, "exactly one securestore-api scrape job is required")
    job = securestore_jobs[0]
    require(job.get("scheme") == "https", "production scraping must use HTTPS")
    require(job.get("metrics_path") == "/metrics", "SecureStore metrics path must remain /metrics")

    authorization = job.get("authorization", {})
    require(authorization.get("type") == "Bearer", "scraping must use the dedicated bearer")
    require("credentials" not in authorization, "collector bearer must not be embedded in YAML")
    require(bool(authorization.get("credentials_file")), "collector bearer must be mounted as a file")

    tls = job.get("tls_config", {})
    require(bool(tls.get("ca_file")), "scraping must verify an explicitly trusted CA")
    require(bool(tls.get("server_name")), "scraping must verify the expected server name")
    require(tls.get("insecure_skip_verify") is not True, "TLS verification must not be disabled")

    serialized = yaml.safe_dump(config).lower()
    require("securestore_metrics_bearer_token" not in serialized, "application secret variable must not enter collector YAML")


def validate_rules(document: dict) -> None:
    groups = document.get("groups", [])
    require(groups, "at least one alert group is required")
    rules = [rule for group in groups for rule in group.get("rules", [])]
    alert_names = [rule.get("alert") for rule in rules]
    require(None not in alert_names, "every monitoring rule must be an alert rule")
    require(len(alert_names) == len(set(alert_names)), "alert names must be unique")
    require(REQUIRED_ALERTS == set(alert_names), "alert catalog does not match the approved required set")

    for rule in rules:
        name = rule["alert"]
        expression = str(rule.get("expr", ""))
        require(expression.strip(), f"{name} requires a PromQL expression")
        require(str(rule.get("for", "")).strip(), f"{name} requires a hold duration to reduce flapping")
        require(rule.get("labels", {}).get("severity") in {"warning", "critical"}, f"{name} requires an approved severity")
        require(rule.get("labels", {}).get("service") == "securestore", f"{name} requires the service label")
        require(bool(rule.get("annotations", {}).get("runbook_ref")), f"{name} requires a runbook reference")

        # Extract explicit label matchers from PromQL selectors. Metric names
        # themselves may legitimately contain words such as "protected"; only
        # label keys are checked for forbidden identity/resource dimensions.
        label_keys = {match.lower() for match in re.findall(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:=~|!~|!=|=)", expression)}
        require(not (label_keys & FORBIDDEN_TERMS), f"{name} uses a prohibited sensitive label: {label_keys & FORBIDDEN_TERMS}")


def main() -> int:
    try:
        validate_config(load_yaml(CONFIG_PATH))
        validate_rules(load_yaml(RULES_PATH))
        tests = load_yaml(RULE_TESTS_PATH)
        require(bool(tests.get("tests")), "at least one executable alert-rule test is required")
    except (OSError, yaml.YAMLError, AssertionError) as error:
        print(f"monitoring validation failed: {error}", file=sys.stderr)
        return 1
    print("monitoring configuration and alert policy validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
