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

When a rule has multiple `<Block>` elements, each block is a separate event group. By default, **all blocks must be satisfied** within the `<ObservationPeriod>` (AND semantics, no ordering). The grouping field links events across blocks. Ordered sequences (THEN semantics) are covered after the unordered example.

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

**→ KQL correlation pattern (unordered AND):**
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

## Hard Constructs — Ordered Sequences, Windows, Cross-Block Uniqueness

Classify any rule containing these as **hard** in Step 0.

### Ordered sequence (Block A THEN Block B)

**What it is:** AIE rules where blocks must match IN ORDER. Recognize via a block `order`/`sequence` attribute, a `<BlockRelationship>` element, or rule type "Sequenced" in the export — absence of these means unordered AND (above).
**KQL equivalent:** Partial.
**Recipe:**
- 2 blocks: pattern 13 in `02-knowledge/house-style/kql-patterns.md` (time-window correlation join) — the post-join filter `event2_time - event1_time >= 0` enforces the ordering.
- 3+ blocks: pattern 15 (`scan`), one `step` per block in order, each step binding the grouping field to the previous step:
```kql
// Block1: scan (>=10 in 5m) THEN Block2: exploit THEN Block3: outbound, same originIP
let lookback = ago(30m);
CommonSecurityLog
| where TimeGenerated >= lookback
| where DeviceEventCategory in ("Network Scan", "Exploit", "Command and Control")
| sort by SourceIP asc, TimeGenerated asc
| scan with_match_id=SeqId declare (Stage: int) with
(
    step s1: DeviceEventCategory == "Network Scan";
    step s2: DeviceEventCategory == "Exploit" and SourceIP == s1.SourceIP;
    step s3: DeviceEventCategory == "Command and Control" and SourceIP == s2.SourceIP;
)
| summarize Stages = dcount(DeviceEventCategory), SeqStart = min(TimeGenerated), SeqEnd = max(TimeGenerated)
    by SeqId, SourceIP
| where Stages == 3 and SeqEnd - SeqStart <= 30m   // enforce observation period
```
**Caveats:** A per-block `matchCount` > 1 inside a sequence (e.g., "≥10 scans THEN 1 exploit") cannot be expressed as a single `scan` step — pre-aggregate that block into a `let` (as in the unordered example) and sequence the remaining blocks. Logic Fidelity ≤ 85% until tested.

### Observation period vs per-block windows

**What it is:** The rule has BOTH an `<ObservationPeriod seconds>` (whole-sequence window) and per-block `withinSeconds` (each block's own threshold window).
**KQL equivalent:** Direct — but the two windows map to different places.
**Recipe:**

| Source value | Maps to |
|---|---|
| `observationPeriodSeconds` | ARM `queryPeriod` + outer `let lookback = ago(Xs)` + final `SeqEnd - SeqStart <= X` filter |
| per-block `withinSeconds` == observation period | nothing extra — single lookback covers it |
| per-block `withinSeconds` < observation period | that block's threshold counted per `bin(TimeGenerated, <withinSeconds>)`, or as a join delta constraint (`block2_time - block1_time <= withinSeconds`) |

**Caveats:** `bin()` windows are fixed buckets, LogRhythm windows are sliding — a burst straddling a bin boundary may not trigger. Note in notes.md; if the client requires sliding-window fidelity, flag for a `scan`-based or shorter-bin variant. Never set `queryPeriod` shorter than `observationPeriodSeconds` (lesson L-2026-06-09-002 analog).

### Unique values across blocks

**What it is:** `matchType="Unique"` semantics spanning the whole rule — e.g., "N distinct impacted hosts across both stages within the observation period", not N distinct per block.
**KQL equivalent:** Direct — but placement matters.
**Recipe:** Correlate blocks first (join or `scan`), THEN apply `dcount` over the correlated result:
```kql
// distinct impacted hosts across both correlated stages
<correlated blocks as above>
| summarize UniqueHosts = dcount(DestinationHostName) by SourceIP
| where UniqueHosts >= 5
```
**Caveats:** Running `dcount` per block before the join silently changes semantics (per-stage uniqueness instead of cross-stage) — this is the main translation trap. State in notes.md which interpretation the source rule used; if the export is ambiguous, ask (1 clarifying question allowed for hard inputs).

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
