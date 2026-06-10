# LogRhythm AI Engine Rule Syntax — Parsing Guide

LogRhythm AI Engine (AIE) rules define correlation logic. They export as **XML** or **JSON**. This guide covers how to parse both formats to extract detection logic for KQL translation. **Extract from the rule block structure — do not rely solely on the rule name or description.**

---

## XML Format — Structure Overview

```xml
<AIERuleBlock name="Multiple Failed Logins" enabled="true" riskRating="High">

  <Blocks>
    <!-- Each Block is an event group with a threshold and time window -->
    <Block matchCount="5" withinSeconds="900" matchType="Unique" groupByField="login">

      <!-- Condition groups within the block -->
      <FieldConstraint field="classificationName" comparator="=" value="Authentication Failure"/>
      <FieldConstraint field="login" comparator="!=" value="SYSTEM"/>

      <!-- Log source filter — determines what data source is referenced -->
      <LogSourceCriteria>
        <LogSourceType name="MS Windows Event Logging"/>
      </LogSourceCriteria>

    </Block>
  </Blocks>

  <!-- Time window across blocks (for multi-block correlation) -->
  <ObservationPeriod seconds="1800"/>

</AIERuleBlock>
```

---

## JSON Format — Structure Overview

LogRhythm SIEM API / export tool produces this JSON structure:

```json
{
  "ruleId": 456,
  "name": "Multiple Failed Logins",
  "enabled": true,
  "riskRating": 8,
  "observationPeriodSeconds": 1800,
  "ruleBlocks": [
    {
      "matchCount": 5,
      "withinSeconds": 900,
      "matchType": "Unique",
      "groupByField": "login",
      "conditions": [
        { "field": "classificationName", "comparator": "=",  "value": "Authentication Failure" },
        { "field": "login",              "comparator": "!=", "value": "SYSTEM" }
      ],
      "logSourceFilters": [
        { "logSourceType": "MS Windows Event Logging" }
      ]
    }
  ]
}
```

---

## Element / Key Reference

### Rule-level fields

| XML Attribute / JSON key | Meaning | Maps to |
|---|---|---|
| `name` / `name` | Rule name | Sentinel `displayName` |
| `enabled` / `enabled` | Active? | Sentinel `enabled` |
| `riskRating` / `riskRating` | Severity 1-10 | Sentinel severity via `severity-mappings.md` |
| `<ObservationPeriod seconds>` / `observationPeriodSeconds` | Overall time window for multi-block correlation | Outer `let lookback = ago(Xs)` |

---

### `<Block>` / `ruleBlocks[]` — Event group

| Attribute / JSON key | Meaning | Maps to |
|---|---|---|
| `matchCount` | Minimum number of matching events | `summarize count() >= N` threshold |
| `withinSeconds` | Time window for matchCount | `ago(Xs)` in the lookback variable |
| `matchType` | `Any` = any event, `Unique` = distinct values of groupByField | `count()` vs `dcount()` |
| `groupByField` | Field to group on | `by <field>` in summarize |

**matchType → KQL:**

| matchType | KQL |
|---|---|
| `Any` | `summarize EventCount = count() by ... \| where EventCount >= N` |
| `Unique` | `summarize UniqueCount = dcount(GroupByField) by ... \| where UniqueCount >= N` |

---

### `<FieldConstraint>` / `conditions[]` — Single condition

| Attribute / JSON key | Meaning |
|---|---|
| `field` / `field` | LogRhythm normalized field — see `logrhythm-to-sentinel.md` |
| `comparator` / `comparator` | Comparison operator — see table below |
| `value` / `value` | Literal value, wildcard, or comma-separated list |

**Comparator → KQL operator:**

| LogRhythm comparator | KQL | Notes |
|---|---|---|
| `=` | `==` | Exact match |
| `!=` | `!=` | |
| `<` | `<` | Numeric |
| `>` | `>` | Numeric |
| `<=` | `<=` | |
| `>=` | `>=` | |
| `contains` | `contains` | Substring |
| `does not contain` | `!contains` | |
| `starts with` | `startswith` | |
| `ends with` | `endswith` | |
| `regex` | `matches regex` | |
| `in list` | `in (...)` | Watchlist or inline list |
| `not in list` | `!in (...)` | |
| `is null` | `isnull(field)` | |
| `is not null` | `isnotnull(field)` | |

**Wildcards:** `*` in value → use `startswith`/`endswith`/`contains` as appropriate.

---

### `<LogSourceCriteria>` / `logSourceFilters[]` — Data source

Determines which Sentinel table to use:

| LogRhythm LogSourceType | Sentinel Table |
|---|---|
| MS Windows Event Logging | `SecurityEvent` |
| Linux/Unix syslog | `Syslog` |
| Checkpoint Firewall | `CommonSecurityLog` |
| Palo Alto Networks | `CommonSecurityLog` |
| Microsoft 365 | `OfficeActivity` |
| Azure Active Directory | `SigninLogs` / `AuditLogs` |
| Generic CEF | `CommonSecurityLog` |
| Custom/unknown | `Syslog` (fallback) |

---

## Multi-Block Correlation

When a rule has multiple `<Block>` elements, each block is a separate event group. By default, **all blocks must be satisfied** within the `<ObservationPeriod>` (AND semantics). The grouping field links events across blocks.

```xml
<Blocks>
  <Block matchCount="10" withinSeconds="300" groupByField="originIP">
    <FieldConstraint field="classificationName" comparator="=" value="Network Scan"/>
  </Block>
  <Block matchCount="1" withinSeconds="1800" groupByField="originIP">
    <FieldConstraint field="classificationName" comparator="=" value="Exploit"/>
  </Block>
</Blocks>
<ObservationPeriod seconds="1800"/>
```

**→ KQL correlation pattern:**
```kql
let lookback = ago(30m);
let scanners = CommonSecurityLog
    | where TimeGenerated >= lookback
    | where DeviceEventCategory == "Network Scan"
    | summarize ScanCount = count() by SourceIP, bin(TimeGenerated, 5m)
    | where ScanCount >= 10
    | distinct SourceIP;
CommonSecurityLog
| where TimeGenerated >= lookback
| where DeviceEventCategory == "Exploit"
| where SourceIP in (scanners)
| project TimeGenerated, SourceIP, DestinationIP, Activity, Message
```

---

## Complete Translation Example

**LogRhythm AI Engine JSON:**
```json
{
  "name": "Brute Force Login",
  "riskRating": 8,
  "observationPeriodSeconds": 900,
  "ruleBlocks": [{
    "matchCount": 10,
    "withinSeconds": 900,
    "matchType": "Any",
    "groupByField": "originLogin",
    "conditions": [
      { "field": "classificationName", "comparator": "=",  "value": "Authentication Failure" },
      { "field": "originLogin",        "comparator": "!=", "value": "SYSTEM" }
    ],
    "logSourceFilters": [{ "logSourceType": "MS Windows Event Logging" }]
  }]
}
```

**Extracted detection logic:**
- Filter: Authentication Failure events, login ≠ SYSTEM
- Table: SecurityEvent (Windows Event Logging)
- Aggregation: count per originLogin (mapped → AccountName)
- Threshold: ≥ 10 events within 15 minutes

**KQL output:**
```kql
// Source: LogRhythm — Brute Force Login
let lookback = ago(15m);
let threshold = 10;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4625
| where AccountName != "SYSTEM"
| where AccountName !endswith "$"
| summarize FailureCount = count() by AccountName, IpAddress, Computer
| where FailureCount >= threshold
| project TimeGenerated = now(), AccountName, IpAddress, Computer, FailureCount
```

---

## LogRhythm Normalized Field → Sentinel Field (Quick Reference)

For the complete mapping, see `logrhythm-to-sentinel.md`.

| LogRhythm field | CommonSecurityLog | SecurityEvent |
|---|---|---|
| `originLogin` | `SourceUserName` | `AccountName` |
| `impactedLogin` | `DestinationUserName` | `TargetUserName` |
| `originIP` | `SourceIP` | `IpAddress` |
| `impactedIP` | `DestinationIP` | — |
| `originHostName` | `SourceHostName` | `Computer` |
| `classificationName` | `DeviceEventCategory` | — |
| `commonEventName` | `Activity` | — |
| `processName` | `ProcessName` | `ProcessName` |
| `command` | `ProcessCommandLine` | `CommandLine` |
