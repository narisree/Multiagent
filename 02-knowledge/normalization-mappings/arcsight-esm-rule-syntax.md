# ArcSight ESM Rule XML — Syntax Parsing Guide

ArcSight ESM rules are exported as XML. This guide covers how to parse the XML structure to extract detection logic for KQL translation. **Do not rely on the rule description — extract from `<Condition>` and `<Threshold>` elements.**

---

## XML Structure Overview

```xml
<Rule name="Multiple Failed Logins" severity="High" enabled="true">
  <!-- Condition group — what events match -->
  <Filter operator="AND">
    <Condition field="eventId" op="=" value="4625"/>
    <Condition field="targetAccountName" op="!=" value="SYSTEM"/>
    <Filter operator="OR">
      <Condition field="agentSeverity" op="=" value="High"/>
      <Condition field="agentSeverity" op="=" value="Medium"/>
    </Filter>
  </Filter>

  <!-- Threshold — how many events trigger the rule -->
  <Threshold field="targetAccountName" type="EventCount"
             limit="5" timeUnit="Minute" timeWindow="15"/>

  <!-- Correlation across event streams (optional) -->
  <EventJoin>
    <JoinCondition leftField="sourceAddress" rightField="sourceAddress"/>
  </EventJoin>
</Rule>
```

---

## Element Reference

### `<Rule>` — Rule container

| Attribute | Maps to |
|---|---|
| `name` | Sentinel `displayName` |
| `severity` | Sentinel severity (via `severity-mappings.md`) |
| `enabled` | Sentinel `enabled` field |

---

### `<Filter>` — Condition group

| Attribute | Meaning |
|---|---|
| `operator="AND"` | All child `<Condition>` elements must match (KQL: chain `\| where` clauses) |
| `operator="OR"` | Any child element matches (KQL: `\| where A or B`) |
| Nested `<Filter>` | Parenthesized subgroup |

**AND group → KQL:**
```xml
<Filter operator="AND">
  <Condition field="eventId" op="=" value="4625"/>
  <Condition field="status" op="!=" value="Success"/>
</Filter>
```
```kql
| where EventID == 4625
| where Status != "Success"
```

**OR group → KQL:**
```xml
<Filter operator="OR">
  <Condition field="agentSeverity" op="=" value="High"/>
  <Condition field="agentSeverity" op="=" value="Medium"/>
</Filter>
```
```kql
| where LogSeverity in ("High", "Medium")
```

---

### `<Condition>` — Single field comparison

| Attribute | Meaning |
|---|---|
| `field` | ArcSight CEF field name → map via `arcsight-to-sentinel.md` |
| `op` | Comparison operator — see operator table below |
| `value` | Literal value, wildcard, or comma-separated list |

**Operator mapping:**

| ArcSight `op` | KQL equivalent | Notes |
|---|---|---|
| `=` | `==` | Exact match |
| `!=` | `!=` | |
| `<` | `<` | Numeric |
| `>` | `>` | Numeric |
| `<=` | `<=` | |
| `>=` | `>=` | |
| `Contains` | `contains` | Case-insensitive substring |
| `ContainsIgnoreCase` | `contains` | Same as Contains in KQL |
| `StartsWith` | `startswith` | |
| `EndsWith` | `endswith` | |
| `MatchesRegex` | `matches regex` | Escape backslashes in KQL |
| `InList` | `in (...)` | Value is comma-separated list |
| `NotInList` | `!in (...)` | |
| `INCIDR` | `ipv4_is_in_range(field, "CIDR")` | CIDR notation |
| `IsNull` | `isnull(field)` | |
| `IsNotNull` | `isnotnull(field)` | |

**Wildcard values:** ArcSight `*` wildcards in values → translate to `startswith`, `endswith`, or `contains` as appropriate.

**Example:**
```xml
<Condition field="destinationHostName" op="=" value="CRITICAL-*"/>
```
```kql
| where DestinationHostName startswith "CRITICAL-"
```

---

### `<Threshold>` — Aggregation gate

| Attribute | Meaning |
|---|---|
| `field` | The grouping field (count events per this field) |
| `type` | `EventCount` or `DistinctCount` |
| `limit` | Threshold value (trigger when count exceeds this) |
| `timeUnit` | `Second`, `Minute`, `Hour`, `Day` |
| `timeWindow` | Number of timeUnits for the lookback window |

**EventCount → KQL:**
```xml
<Threshold field="targetAccountName" type="EventCount" limit="5" timeUnit="Minute" timeWindow="15"/>
```
```kql
let lookback = ago(15m);
let threshold = 5;
// ... filter conditions ...
| summarize FailureCount = count() by TargetUserName
| where FailureCount > threshold
```

**DistinctCount → KQL:**
```xml
<Threshold field="destinationAddress" type="DistinctCount" limit="10" timeUnit="Minute" timeWindow="5"/>
```
```kql
let lookback = ago(5m);
let threshold = 10;
// ... filter conditions ...
| summarize UniqueDestinations = dcount(DestinationIP) by SourceIP
| where UniqueDestinations > threshold
```

**timeUnit → KQL duration:**

| ArcSight timeUnit | KQL `ago()` |
|---|---|
| `Second` | `ago(Ns)` |
| `Minute` | `ago(Nm)` |
| `Hour` | `ago(Nh)` |
| `Day` | `ago(Nd)` |

---

### `<EventJoin>` and `<JoinCondition>` — Correlation

Correlates two event streams. Each `<JoinCondition>` specifies a field that must match between the left and right events.

```xml
<EventJoin timeWindow="30" timeUnit="Minute">
  <JoinCondition leftField="sourceAddress" rightField="sourceAddress"/>
</EventJoin>
```

**→ KQL correlation pattern:**
```kql
let lookback = ago(30m);
let leftEvents = TableA
    | where TimeGenerated >= lookback
    | where <left filter conditions>
    | project TimeGenerated, SourceIP;
TableB
| where TimeGenerated >= lookback
| where <right filter conditions>
| join kind=inner (leftEvents) on SourceIP
| project TimeGenerated, SourceIP, <other fields>
```

---

## Complete Translation Example

**ArcSight ESM XML:**
```xml
<Rule name="Brute Force Login" severity="High" enabled="true">
  <Filter operator="AND">
    <Condition field="eventId" op="=" value="4625"/>
    <Condition field="targetAccountName" op="!=" value="SYSTEM"/>
    <Condition field="targetAccountName" op="!=" value="ANONYMOUS LOGON"/>
  </Filter>
  <Threshold field="targetAccountName" type="EventCount"
             limit="10" timeUnit="Minute" timeWindow="10"/>
</Rule>
```

**Extracted detection logic:**
- Event filter: EventID = 4625 AND account not SYSTEM/ANONYMOUS
- Aggregation: count per account
- Threshold: > 10 events within 10 minutes

**KQL output:**
```kql
// Source: ArcSight — Brute Force Login
let lookback = ago(10m);
let threshold = 10;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4625
| where AccountName !in ("SYSTEM", "ANONYMOUS LOGON")
| where AccountName !endswith "$"
| summarize FailureCount = count() by AccountName, IpAddress, Computer
| where FailureCount > threshold
| project TimeGenerated = now(), AccountName, IpAddress, Computer, FailureCount
```

---

## ArcSight CEF Field → XML Field Name Mapping

ArcSight XML rules use internal ESM field names, not CEF keys. Common mappings:

| ESM XML field | CEF key | CommonSecurityLog field |
|---|---|---|
| `eventId` | (internal) | `DeviceEventClassID` or `EventID` via SecurityEvent |
| `sourceAddress` | `src` | `SourceIP` |
| `destinationAddress` | `dst` | `DestinationIP` |
| `sourceUserName` | `suser` | `SourceUserName` |
| `targetAccountName` | `duser` | `DestinationUserName` / `AccountName` |
| `deviceHostName` | `dvchost` | `DeviceName` |
| `sourceHostName` | `shost` | `SourceHostName` |
| `destinationHostName` | `dhost` | `DestinationHostName` |
| `agentSeverity` | `severity` | `LogSeverity` |
| `requestUrl` | `request` | `RequestURL` |
| `applicationProtocol` | `app` | `ApplicationProtocol` |
| `transportProtocol` | `proto` | `Protocol` |
| `bytesIn` | `in` | `ReceivedBytes` |
| `bytesOut` | `out` | `SentBytes` |

For a complete field mapping, see `arcsight-to-sentinel.md`.
