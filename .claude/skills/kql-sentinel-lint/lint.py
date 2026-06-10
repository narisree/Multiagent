#!/usr/bin/env python3
"""
kql-sentinel-lint — static analyzer for Sentinel Analytics Rule translations.

Usage:
  python3 lint.py <rule.json> [--verbose]

Exit code 0 in normal operation. Findings emitted as JSON to stdout.
"""

import sys
import json
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Known-good Sentinel values
# ---------------------------------------------------------------------------

VALID_SEVERITIES = {"High", "Medium", "Low", "Informational"}

VALID_TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact", "ImpairProcessControl", "InhibitResponseFunction",
    "PreAttack",
}

VALID_TRIGGER_OPS = {"GreaterThan", "LessThan", "Equal", "NotEqual"}

VALID_ENTITY_TYPES = {
    "Account", "Host", "IP", "URL", "FileHash", "File", "Process",
    "CloudApplication", "DNS", "AzureResource", "IoTDevice", "SecurityGroup",
    "MailMessage", "Mailbox", "MailCluster", "SubmissionMail",
}

ENTITY_IDENTIFIERS = {
    "Account":          {"Name", "NTDomain", "UPNSuffix", "ObjectGuid", "Sid", "AadUserId", "AadTenantId", "PUID", "DisplayName"},
    "Host":             {"HostName", "NetBiosName", "DNSDomain", "FullName", "OSFamily", "OSVersion", "AzureID", "OMSAgentID"},
    "IP":               {"Address"},
    "URL":              {"Url"},
    "FileHash":         {"Algorithm", "Value"},
    "File":             {"Directory", "Name"},
    "Process":          {"ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "DNS":              {"DomainName"},
    "AzureResource":    {"ResourceId"},
    "IoTDevice":        {"IoTHub", "DeviceId", "DeviceName", "DeviceType", "IpAddress", "MacAddress"},
    "SecurityGroup":    {"DistinguishedName", "SID", "ObjectGuid"},
    "MailMessage":      {"Recipient", "Sender", "P1Sender", "NetworkMessageId", "Subject"},
    "Mailbox":          {"MailboxPrimaryAddress", "DisplayName", "Upn"},
}

SENTINEL_TABLES = {
    "SecurityEvent", "WindowsEvent", "Syslog", "CommonSecurityLog",
    "AzureActivity", "SigninLogs", "AADNonInteractiveUserSignInLogs",
    "AuditLogs", "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
    "OfficeActivity", "MicrosoftGraphActivityLogs",
    "DeviceEvents", "DeviceFileEvents", "DeviceNetworkEvents",
    "DeviceProcessEvents", "DeviceRegistryEvents", "DeviceLogonEvents",
    "DeviceImageLoadEvents", "DeviceNetworkInfo", "DeviceInfo",
    "SecurityAlert", "SecurityIncident",
    "ThreatIntelligenceIndicator", "ThreatIntelligencePlatformIndicator",
    "Heartbeat", "Update", "UpdateSummary",
    "VMConnection", "VMProcess", "VMBoundPort", "VMComputer",
    "DnsEvents", "DnsInventory",
    "NetworkSessionEvents", "IMDnsEvents", "IMNetworkSessionEvents",
    "IMFileEvents", "IMProcessEvents", "IMUserManagementEvents",
    "AzureFirewallApplicationRule", "AzureFirewallNetworkRule", "AzureFirewallDnsProxy",
    "AzureNetworkAnalytics_CL",
    "StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs", "StorageTableLogs",
    "AzureDiagnostics", "AzureMetrics",
    "W3CIISLog", "AppServiceHTTPLogs", "AppServiceConsoleLogs",
    "LinuxAuditLog",
    "Event",
    "Perf",
    "Alert",
    # UEBA
    "BehaviorAnalytics", "IdentityInfo", "UserAccessAnalytics", "UserPeerAnalytics",
    # ASIM unifying parsers
    "imAuthentication", "imDns", "imProcessCreate", "imProcessTerminate",
    "imFileEvent", "imRegistryEvent", "imUserManagement",
    "imAuditEvent", "imDhcpEvent", "imNotification", "imNetworkSession",
    # ASIM streaming normalization tables
    "ASimAuthenticationEvent", "ASimDnsActivity", "ASimProcessEvent",
    "ASimFileEvent", "ASimRegistryEvent", "ASimUserManagementActivity",
    "ASimAuditEventActivity", "ASimDhcpEvent", "ASimNotification",
    "ASimNetworkSessionLogs",
}

KQL_KEYWORDS = {
    "where", "project", "extend", "summarize", "by", "join", "union", "let",
    "on", "kind", "inner", "leftouter", "rightouter", "fullouter",
    "innerunique", "leftanti", "rightanti", "leftsemi", "rightsemi",
    "count", "sum", "avg", "min", "max", "dcount", "dcountif", "countif",
    "make_list", "make_set", "arg_max", "arg_min", "percentile",
    "bin", "floor", "ceiling", "round",
    "ago", "now", "datetime", "startofday", "endofday", "startofweek",
    "startofmonth", "startofyear", "todatetime", "totimespan",
    "tolower", "toupper", "trim", "ltrim", "rtrim", "replace_string",
    "replace_regex", "split", "strcat", "strlen", "substring", "indexof",
    "parse", "parse_json", "parse_xml", "parse_urlquery",
    "iff", "iif", "case", "coalesce", "isempty", "isnotempty",
    "isnull", "isnotnull", "tobool", "toint", "tolong", "toreal",
    "tostring", "todynamic",
    "mv-expand", "mv-apply", "bag_unpack", "pack",
    "top", "limit", "take", "distinct", "sort", "order",
    "range", "print", "datatable",
    "matches", "regex", "contains", "startswith", "endswith", "has", "has_any",
    "in", "!in", "between", "!between",
    "serialize", "scan", "evaluate",
}

ISO8601_DURATION = re.compile(r"^P(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$")

LET_NUMERIC = re.compile(r"^\s*let\s+(\w+)\s*=\s*(\d+(?:\.\d+)?)\s*;", re.MULTILINE)


def resolve_let_bindings(kql: str) -> dict:
    """Map let-bound numeric variables to their values, e.g. 'let threshold = 5;' -> {'threshold': 5.0}."""
    return {m.group(1): float(m.group(2)) for m in LET_NUMERIC.finditer(kql)}

ARM_REQUIRED_PROPERTIES = {
    "displayName", "query", "severity",
    "queryFrequency", "queryPeriod",
    "triggerOperator", "triggerThreshold",
}

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, severity, code, line, message):
        self.severity = severity  # E | C | S | F | H | R
        self.code = code
        self.line = line
        self.message = message

    def to_dict(self):
        return {"code": self.code, "line": self.line, "message": self.message}

# ---------------------------------------------------------------------------
# KQL checks
# ---------------------------------------------------------------------------

def check_kql_syntax(kql: str) -> list[Finding]:
    findings = []
    lines = kql.splitlines()

    # Unbalanced parentheses
    depth = 0
    for i, line in enumerate(lines, 1):
        for ch in line:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth < 0:
                findings.append(Finding("E", "E.KQL_SYNTAX", i, f"Unexpected ')' — unbalanced parentheses at line {i}"))
                depth = 0
    if depth != 0:
        findings.append(Finding("E", "E.KQL_SYNTAX", len(lines), f"Unclosed parenthesis — {depth} unmatched '(' in query"))

    # Unbalanced brackets
    depth = 0
    for i, line in enumerate(lines, 1):
        for ch in line:
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
    if depth != 0:
        findings.append(Finding("E", "E.KQL_SYNTAX", 0, f"Unbalanced brackets — {depth} unmatched '[' in query"))

    return findings


def check_table_references(kql: str) -> list[Finding]:
    findings = []
    # Find table names: standalone capitalized words at line start or after union/join
    table_pattern = re.compile(r"(?:^|\|\s*union\s+|join\s+\w+\s+\()([A-Za-z][A-Za-z0-9_]+)(?:\s*\||\s*\(|\s*$)", re.MULTILINE)
    # Also first token of query
    first_table = re.match(r"^\s*([A-Za-z][A-Za-z0-9_]+)", kql)
    candidates = set()
    if first_table:
        candidates.add(first_table.group(1))
    for m in table_pattern.finditer(kql):
        candidates.add(m.group(1))

    for name in candidates:
        if name in KQL_KEYWORDS:
            continue
        if name not in SENTINEL_TABLES:
            findings.append(Finding("E", "E.TABLE_NOT_EXIST", 0,
                f"Table '{name}' not in known Sentinel tables — check spelling (e.g., SecurityEvent not SecurityEvents)"))
    return findings


def check_time_filter(kql: str) -> list[Finding]:
    findings = []
    time_patterns = [
        r"TimeGenerated",
        r"ago\s*\(",
        r"datetime\s*\(",
        r"startofday",
        r"startofmonth",
    ]
    if not any(re.search(p, kql, re.IGNORECASE) for p in time_patterns):
        findings.append(Finding("E", "E.TIME_FILTER_MISSING", 0,
            "No time filter detected (TimeGenerated / ago()) — query will scan entire table history"))
    return findings


def check_join_kind(kql: str) -> list[Finding]:
    findings = []
    # join without explicit kind
    joins = re.findall(r"\bjoin\b(?!\s+kind)", kql, re.IGNORECASE)
    if joins:
        findings.append(Finding("E", "E.JOIN_WRONG_KIND", 0,
            f"Found {len(joins)} join(s) without explicit 'kind=' — default is innerunique which deduplicates; specify kind explicitly"))
    return findings


def check_house_style(kql: str) -> list[Finding]:
    findings = []

    if not re.match(r"^\s*//\s*Source:", kql):
        findings.append(Finding("H", "H.COMMENT_MISSING", 1,
            "KQL should start with '// Source: <SIEM> — <original rule name>' header comment"))

    if not re.search(r"^\s*let\s+\w+\s*=\s*ago\s*\(", kql, re.MULTILINE):
        findings.append(Finding("H", "H.NO_LET_FOR_TIMEWINDOW", 0,
            "Time window should be stored as 'let lookback = ago(1h);' at query top for easy tuning"))

    if not re.search(r"\|\s*project\b", kql):
        findings.append(Finding("H", "H.MISSING_PROJECT", 0,
            "Final output should use '| project' to limit returned columns"))

    threshold_inline = re.search(r"\|\s*where\s+\w+\s*[><=!]+\s*\d{2,}", kql)
    if threshold_inline and not re.search(r"let\s+threshold", kql):
        findings.append(Finding("H", "H.HARDCODED_THRESHOLD", 0,
            "Numeric threshold should be stored in 'let threshold = N' at query top"))

    return findings


def check_semantic(kql: str, properties: dict) -> list[Finding]:
    findings = []

    threshold = properties.get("triggerThreshold", None)
    if threshold == 0:
        let_bindings = resolve_let_bindings(kql)
        for m in re.finditer(r"\|\s*where\s+(\w+)\s*(>=|>)\s*(\w+(?:\.\d+)?)", kql):
            column, op, operand = m.group(1), m.group(2), m.group(3)
            if re.fullmatch(r"\d+(?:\.\d+)?", operand):
                value = float(operand)
                source = operand
            elif operand in let_bindings:
                value = let_bindings[operand]
                source = f"let {operand} = {let_bindings[operand]:g}"
            else:
                continue  # unresolvable identifier — skip, no false positive
            if value >= 1:
                findings.append(Finding("S", "S.THRESHOLD_WRONG", 0,
                    f"triggerThreshold=0 but KQL filters {column} {op} {operand} ({source}) — "
                    "verify alert fires on any match vs. threshold breach"))
                break

    if not re.search(r"tolower\s*\(|toupper\s*\(", kql) and re.search(r"==\s*['\"]", kql):
        findings.append(Finding("S", "S.CASE_SENSITIVITY", 0,
            "String equality comparison found without tolower()/toupper() — may miss case variants"))

    if re.search(r"\bcount\b", kql) and not re.search(r"\bdcount\b", kql):
        # Just a risk note, not certain
        pass  # covered by R.DCOUNT_APPROXIMATION below if dcount is used

    return findings


def check_risks(kql: str) -> list[Finding]:
    findings = []

    if re.search(r"matches\s+regex", kql, re.IGNORECASE):
        findings.append(Finding("R", "R.REGEX_UNTESTED", 0,
            "matches regex pattern translated from source — verify regex correctness in Sentinel editor"))

    if re.search(r"\bdcount\b", kql, re.IGNORECASE):
        findings.append(Finding("R", "R.DCOUNT_APPROXIMATION", 0,
            "dcount() returns approximate distinct count — if exact count matters, use countif(distinct ...)"))

    if re.search(r"parse_json\s*\(", kql, re.IGNORECASE):
        findings.append(Finding("R", "R.DYNAMIC_FIELD", 0,
            "parse_json() result may be null for rows where field is absent — add isnotnull() guard"))

    large_tables = {"SecurityEvent", "Syslog", "CommonSecurityLog", "WindowsEvent"}
    for table in large_tables:
        join_pattern = re.search(rf"join\s+\w*\s*\(\s*{table}", kql)
        if join_pattern:
            findings.append(Finding("R", "R.JOIN_LARGE_TABLE", 0,
                f"join on large table {table} — ensure pre-filter with TimeGenerated/where before the join"))

    return findings


# ---------------------------------------------------------------------------
# ARM template checks
# ---------------------------------------------------------------------------

def check_arm_template(rule: dict) -> list[Finding]:
    findings = []

    props = rule.get("properties", {})
    if not props:
        findings.append(Finding("E", "E.ARM_MISSING_REQUIRED", 0,
            "ARM template has no 'properties' object"))
        return findings

    for field in ARM_REQUIRED_PROPERTIES:
        if field not in props:
            findings.append(Finding("E", "E.ARM_MISSING_REQUIRED", 0,
                f"ARM template missing required field: '{field}'"))

    severity = props.get("severity", "")
    if severity and severity not in VALID_SEVERITIES:
        findings.append(Finding("C", "C.SEVERITY_INVALID", 0,
            f"severity='{severity}' — must be one of: {sorted(VALID_SEVERITIES)}"))

    for tactic in props.get("tactics", []):
        if tactic not in VALID_TACTICS:
            findings.append(Finding("C", "C.TACTICS_INVALID", 0,
                f"tactic='{tactic}' not in Sentinel MITRE taxonomy — check spelling"))

    for duration_field in ("queryFrequency", "queryPeriod", "suppressionDuration"):
        val = props.get(duration_field, "")
        if val and not ISO8601_DURATION.match(val):
            findings.append(Finding("C", "C.QUERY_FREQ_FORMAT", 0,
                f"'{duration_field}={val}' is not a valid ISO 8601 duration (e.g., PT1H, P1D, PT30M)"))

    trigger_op = props.get("triggerOperator", "")
    if trigger_op and trigger_op not in VALID_TRIGGER_OPS:
        findings.append(Finding("C", "C.TRIGGER_OP_INVALID", 0,
            f"triggerOperator='{trigger_op}' — must be one of: {sorted(VALID_TRIGGER_OPS)}"))

    kind = rule.get("kind", "")
    if kind and kind != "Scheduled":
        findings.append(Finding("C", "C.KIND_INVALID", 0,
            f"kind='{kind}' — only 'Scheduled' is supported for custom Analytics Rules"))

    for em in props.get("entityMappings", []):
        entity_type = em.get("entityType", "")
        if entity_type not in VALID_ENTITY_TYPES:
            findings.append(Finding("C", "C.ENTITY_TYPE_INVALID", 0,
                f"entityType='{entity_type}' not in supported entity types"))
            continue
        valid_ids = ENTITY_IDENTIFIERS.get(entity_type, set())
        for fm in em.get("fieldMappings", []):
            identifier = fm.get("identifier", "")
            if identifier not in valid_ids:
                findings.append(Finding("C", "C.ENTITY_IDENTIFIER_INVALID", 0,
                    f"identifier='{identifier}' not valid for entityType='{entity_type}' — valid: {sorted(valid_ids)}"))

    # Warn if entity mappings are absent but query likely produces Account/IP/Host data
    kql = props.get("query", "")
    entity_hints = {
        "Account":  ["AccountName", "UserName", "UserId", "SubjectUserName", "TargetUserName", "UserPrincipalName"],
        "IP":       ["IpAddress", "SourceIP", "DestinationIP", "ClientIP", "RemoteIP"],
        "Host":     ["Computer", "HostName", "DeviceName", "WorkstationName"],
    }
    entity_mappings_present = {em.get("entityType") for em in props.get("entityMappings", [])}
    for entity, fields in entity_hints.items():
        if entity not in entity_mappings_present:
            if any(re.search(rf"\b{f}\b", kql) for f in fields):
                findings.append(Finding("H", "H.ENTITY_MAP_MISSING", 0,
                    f"Query references {entity} fields but entityMappings has no '{entity}' entry — add for incident enrichment"))

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    verbose = "--verbose" in sys.argv
    live = "--live" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if not args:
        print(json.dumps({"error": "usage: lint.py <rule.json> [--verbose] [--live]"}))
        sys.exit(0)

    rule_path = Path(args[0])
    if not rule_path.exists():
        print(json.dumps({"error": f"file not found: {rule_path}"}))
        sys.exit(0)

    try:
        rule = json.loads(rule_path.read_text())
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"E.ARM_INVALID_JSON: {exc}"}))
        sys.exit(0)

    props = rule.get("properties", {})
    kql = props.get("query", "")

    findings: list[Finding] = []

    if kql:
        findings += check_kql_syntax(kql)
        findings += check_table_references(kql)
        findings += check_time_filter(kql)
        findings += check_join_kind(kql)
        findings += check_house_style(kql)
        findings += check_semantic(kql, props)
        findings += check_risks(kql)

    findings += check_arm_template(rule)

    def bucket(severity):
        return [f.to_dict() for f in findings if f.severity == severity]

    output = {
        "errors":               bucket("E"),
        "schema_violations":    bucket("C"),
        "semantic_mismatches":  bucket("S"),
        "field_mapping_errors": bucket("F"),
        "house_style":          bucket("H"),
        "risks":                bucket("R"),
        "summary": {
            "total": len(findings),
            "errors": len(bucket("E")),
            "warnings": len(findings) - len(bucket("E")),
        }
    }

    if live:
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            import validate
            output["live_validation"] = validate.run_live(rule_path)
        except Exception as exc:  # advisory only — never block delivery
            output["live_validation"] = {"status": "skipped",
                                         "reason": f"live validation unavailable: {exc}",
                                         "findings": []}
        live_findings = output["live_validation"].get("findings", [])
        output["errors"].extend(live_findings)
        output["summary"]["total"] += len(live_findings)
        output["summary"]["errors"] += len(live_findings)

    print(json.dumps(output, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
