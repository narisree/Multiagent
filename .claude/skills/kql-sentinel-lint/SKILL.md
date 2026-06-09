---
name: kql-sentinel-lint
description: Quality checker for Sentinel Analytics Rule translations. Runs as Python script when available; falls back to cognitive checklist when execution is blocked.
---

# kql-sentinel-lint

This skill audits a translated Sentinel Analytics Rule for KQL correctness, schema compliance, semantic accuracy, and house-style adherence.

## Invocation

When a translation is generated at `08-generated/<folder>/`:

1. Try: `python3 .claude/skills/kql-sentinel-lint/lint.py 08-generated/<folder>/rule.json`
2. If exit code 0: emit findings JSON. Done.
3. If blocked: fall through to cognitive checklist.

When falling through: "Linter could not run; running cognitive review against the same rubric."

## Cognitive checklist

### Severity 1 — Errors (will fail at runtime or deployment)

- **E.KQL_SYNTAX** — Invalid KQL: unclosed parentheses, missing `|`, unknown operator names.
- **E.TABLE_NOT_EXIST** — Query references a Sentinel table that does not exist (e.g., `SecurityEvents` instead of `SecurityEvent`).
- **E.FIELD_NOT_IN_TABLE** — Query references a field not present in the target table.
- **E.LET_UNDEFINED** — `let` variable used before it is defined.
- **E.SUMMARIZE_NO_BY** — `summarize` without `by` clause where grouping is logically required.
- **E.JOIN_WRONG_KIND** — `join` kind not specified; default `innerunique` may cause unexpected row deduplication.
- **E.TIME_FILTER_MISSING** — No `TimeGenerated` or equivalent time filter; will cause full table scan.
- **E.ARM_INVALID_JSON** — ARM template is malformed JSON.
- **E.ARM_MISSING_REQUIRED** — ARM template missing required field: `displayName`, `query`, `severity`, `queryFrequency`, `queryPeriod`, `triggerOperator`, `triggerThreshold`.

### Severity 2 — Schema violations (Sentinel editor will reject)

- **C.SEVERITY_INVALID** — `severity` not one of: `High`, `Medium`, `Low`, `Informational`.
- **C.TACTICS_INVALID** — `tactics` array contains value not in MITRE ATT&CK taxonomy for Sentinel.
- **C.QUERY_FREQ_FORMAT** — `queryFrequency` / `queryPeriod` not ISO 8601 duration (PT5M, PT1H, P1D).
- **C.TRIGGER_OP_INVALID** — `triggerOperator` not one of: `GreaterThan`, `LessThan`, `Equal`, `NotEqual`.
- **C.ENTITY_TYPE_INVALID** — `entityType` not in Sentinel's supported entity types list.
- **C.ENTITY_IDENTIFIER_INVALID** — `identifier` not valid for the given `entityType`.
- **C.KIND_INVALID** — Rule `kind` not `Scheduled` (only supported kind for custom rules).

### Severity 2.5 — Semantic mismatches (runs, but wrong detection behavior)

- **S.THRESHOLD_WRONG** — `triggerThreshold` set to 0 but original rule required N > threshold events.
- **S.TIME_WINDOW_MISMATCH** — `queryPeriod` does not match the lookback window implied by the original rule.
- **S.LOGIC_INVERTED** — Condition translated with inverted logic (e.g., `== 0` where source intended `> 0`).
- **S.CASE_SENSITIVITY** — String comparison without `tolower()`/`toupper()` where source was case-insensitive.
- **S.SEVERITY_SCALE_WRONG** — Source severity (numeric 0-10) not correctly mapped to Sentinel enum.
- **S.COUNT_VS_DISTINCT** — Source used distinct-count; translation used simple count (or vice versa).

### Severity 2.7 — Field mapping errors (correct KQL, wrong field)

- **F.FIELD_MAP_WRONG** — Source field mapped to incorrect Sentinel equivalent per normalization tables.
- **F.TABLE_WRONG** — Detection data placed in wrong Sentinel table (e.g., Windows auth events in Syslog instead of SecurityEvent).
- **F.CEF_CUSTOM_FIELD** — ArcSight cs*/cn* custom field not resolved to its DeviceCustom* equivalent.
- **F.QRADAR_PAYLOAD** — QRadar PAYLOAD field not mapped to RawData / Message appropriately.

### Severity 3 — House-style deviations (works, not our convention)

- **H.NO_LET_FOR_TIMEWINDOW** — Time window not stored in a `let` variable at the top of the query.
- **H.HARDCODED_THRESHOLD** — Numeric threshold hardcoded in query instead of via `let threshold = N`.
- **H.MISSING_PROJECT** — Final output does not use `project` to limit returned columns.
- **H.COMMENT_MISSING** — No `// Source: <SIEM> — <original rule name>` header comment in KQL.
- **H.ENTITY_MAP_MISSING** — Entity mappings absent when identifiable entities (IP, Account, Host) are present.

### Severity 4 — Risks (no violation, but suspicious)

- **R.JOIN_LARGE_TABLE** — Join on a large table (SecurityEvent, Syslog) without pre-filtering may be slow.
- **R.REGEX_UNTESTED** — `matches regex` pattern translated from source; correctness not verified.
- **R.DCOUNT_APPROXIMATION** — `dcount()` is approximate; if exact count matters, use `count(distinct ...)`.
- **R.DYNAMIC_FIELD** — Access to a dynamic/nested field (e.g., `parse_json()` result) that may be null.
- **R.CROSS_TABLE_LOGIC** — Original rule correlated across multiple log sources; verify all tables are enabled.

## Output format

```
## Lint findings

### Errors (E.*)
### Schema violations (C.*)
### Semantic mismatches (S.*)
### Field mapping errors (F.*)
### House-style deviations (H.*)
### Risks (R.*)
### Looks correct
```

If no findings in a category, omit the heading.
