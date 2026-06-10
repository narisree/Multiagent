#!/usr/bin/env python3
"""
validate — live KQL validation for Sentinel Analytics Rule translations.

Runs the rule's KQL against a Log Analytics workspace in the user's OWN
authenticated Azure tenant via the az CLI. Query text never leaves the
tenant (data-sovereignty rule: no online validators).

Usage:
  python3 validate.py <rule.json>

Configuration (first match wins):
  1. Env var SENTINEL_VALIDATE_WORKSPACE_ID  — Log Analytics workspace GUID
  2. validate-config.local.json next to this script: {"workspaceId": "<guid>"}
     (untracked — workspace GUIDs are client engagement data)

Behavior:
  - Prerequisites missing (no az, no workspace, not logged in) -> status "skipped".
  - Query accepted by the engine -> status "passed".
  - Kusto syntax/semantic error -> status "failed" with findings.
  - Throttling/timeouts -> status "skipped" (transient, not a verdict).
Always exits 0 — advisory gate, never blocks delivery.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "validate-config.local.json"
ENV_VAR = "SENTINEL_VALIDATE_WORKSPACE_ID"
TIMESPAN = "PT5M"  # minimal scan window — we only care whether the query parses/binds
AZ_TIMEOUT_SECONDS = 60


def get_workspace_id():
    workspace = os.environ.get(ENV_VAR, "").strip()
    if workspace:
        return workspace
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text()).get("workspaceId", "").strip() or None
        except (json.JSONDecodeError, OSError):
            return None
    return None


def check_prerequisites():
    """Return a skip-reason string, or None when live validation can run."""
    if shutil.which("az") is None:
        return "az CLI not found on PATH"
    if get_workspace_id() is None:
        return f"no workspace configured — set {ENV_VAR} or {CONFIG_FILE.name}"
    probe = subprocess.run(["az", "account", "show", "--output", "none"],
                           capture_output=True, timeout=AZ_TIMEOUT_SECONDS)
    if probe.returncode != 0:
        return "not logged in to Azure — run 'az login'"
    return None


def classify_error(stderr: str):
    """Map az/Kusto error text to a finding, or a transient skip reason."""
    text = stderr.strip()
    lowered = text.lower()
    if "throttl" in lowered or "too many requests" in lowered or "429" in lowered:
        return None, f"transient API error (throttling): {text[:200]}"
    if "syntax error" in lowered or "syn0002" in lowered or "query could not be parsed" in lowered:
        return {"code": "E.KQL_LIVE_SYNTAX", "line": 0,
                "message": f"Kusto engine rejected query syntax: {text[:500]}"}, None
    if "failed to resolve" in lowered or "sem0100" in lowered:
        return {"code": "E.KQL_LIVE_SEMANTIC", "line": 0,
                "message": ("Kusto engine could not resolve a table or column — verify the table "
                            "exists and is ingesting in the TARGET workspace (the validation "
                            f"workspace may lack tables the client has): {text[:500]}")}, None
    # Unrecognized error — surface it as semantic-class rather than guessing
    return {"code": "E.KQL_LIVE_SEMANTIC", "line": 0,
            "message": f"Kusto engine error: {text[:500]}"}, None


def run_live(rule_path) -> dict:
    reason = check_prerequisites()
    if reason:
        return {"status": "skipped", "reason": reason, "findings": []}

    try:
        rule = json.loads(Path(rule_path).read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return {"status": "skipped", "reason": f"cannot read rule.json: {exc}", "findings": []}

    kql = rule.get("properties", {}).get("query", "")
    if not kql:
        # ARM deployment template wraps the rule in resources[]
        for res in rule.get("resources", []):
            kql = res.get("properties", {}).get("query", "")
            if kql:
                break
    if not kql:
        return {"status": "skipped", "reason": "no properties.query found in rule.json", "findings": []}

    # take 0: validate parse/bind without returning client data rows
    query = kql + "\n| take 0"
    try:
        result = subprocess.run(
            ["az", "monitor", "log-analytics", "query",
             "--workspace", get_workspace_id(),
             "--analytics-query", query,
             "-t", TIMESPAN,
             "--output", "json"],
            capture_output=True, text=True, timeout=AZ_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"status": "skipped", "reason": "az query timed out (60s)", "findings": []}

    if result.returncode == 0:
        return {"status": "passed", "findings": []}

    finding, transient = classify_error(result.stderr or result.stdout)
    if transient:
        return {"status": "skipped", "reason": transient, "findings": []}
    return {"status": "failed", "findings": [finding]}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(json.dumps({"error": "usage: validate.py <rule.json>"}))
        sys.exit(0)
    print(json.dumps(run_live(args[0]), indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
