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

---

## Nested Filter → KQL Options

Source: Azure/Azure-Sentinel Tools/RuleMigration/Rule Logic Mappings.md

When an ArcSight `<Filter>` contains nested sub-filters with complex AND/OR/NOT logic, four KQL translation approaches are available (in order of preference):

**Option 1 — Direct filter (preferred):** Flatten the logic into a single `| where` chain.
```kql
SecurityEvent
| where EventID == 4728
| where isnotempty(SubjectDomainName) or isnotempty(TargetDomainName)
| where SubjectUserName !~ "AutoMatedService"
```

**Option 2 — KQL function:** Save shared filter logic as a reusable KQL function in the workspace, then call it.
```kql
// Saved function: ExcludeValidUsers
let ExcludeValidUsers = (T: (SubjectUserName: string)) {
    T | where SubjectUserName !in ("svc-backup", "AutoMatedService")
};
SecurityEvent
| where EventID == 4728
| invoke ExcludeValidUsers()
```

**Option 3 — Parameterized function:** Create a function with typed parameters when the exclusion list changes per-rule.

**Option 4 — Join (least preferred):** Use `join kind=leftanti` only when the exclusion set is too large for inline `!in`. Avoid for simple cases — joins add cost.

**Note:** Avoid `=~` / `!~` (case-insensitive) when `==` / `!=` is sufficient — case-sensitive operators use index lookups and are faster.

---

## Hard Constructs

ESM constructs without a 1:1 KQL equivalent. Recipe format: what it is → KQL equivalent (Direct / Partial / None) → recipe → caveats. Classify any rule containing these as **hard** in Step 0.

### Active list READ (`InActiveList` condition)

**What it is:** `<Condition field="sourceAddress" op="InActiveList" value="Blocklist-IPs"/>` — membership test against a shared, mutable list.
**KQL equivalent:** Direct — Sentinel Watchlist.
**Recipe:**
```kql
let BlocklistIPs = _GetWatchlist('Blocklist-IPs') | project SearchKey;
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where SourceIP in (BlocklistIPs)
```
**Caveats:** Confirm the watchlist exists in the client workspace (or deliver a creation step in notes.md). Multi-column active lists: `_GetWatchlist` returns all columns — join on the keyed column instead of `project SearchKey`.

### Active list WRITE (rule action "Add to Active List")

**What it is:** A rule `<Action>` that inserts the matched entity into an active list, feeding other rules' `InActiveList` tests.
**KQL equivalent:** None — decomposition required.
**Recipe:** Pattern 17 in `02-knowledge/house-style/kql-patterns.md`: (1) Analytics Rule for the detection, (2) Watchlist as the state store, (3) automation rule + Logic App playbook performing the watchlist write. Agent delivers rule.json + playbook spec in notes.md; playbook deployment is the user's manual step.
**Caveats:** Active list entries have TTL; Watchlists do not auto-expire — pruning playbook or accepted staleness, stated in notes.md. Logic Fidelity ≤ 80% until the full chain is deployed.

### Session lists

**What it is:** TTL'd start/end state tracking (e.g., "VPN session open" between logon and logoff events), queried by other rules mid-session.
**KQL equivalent:** Partial — by session lifetime.
**Recipe:**
- Session fully observable within the rule's lookback window: model it inline — pattern 16 (session reconstruction) or pattern 13 (start/end pairing join). Set `queryPeriod` ≥ the session list's TTL.
- Session state must persist beyond a reasonable `queryPeriod` (e.g., multi-day VPN sessions consulted by other rules): decompose per pattern 17, with the playbook writing session open/close entries to a watchlist.
**Caveats:** Prefer the inline form — the watchlist form adds write latency and a second deployment artifact. If multiple ESM rules consult the same session list, the watchlist form is mandatory (shared state).

### Rule variables (calculated fields)

**What it is:** ESM "local variables" computed on the rule (string concatenation, arithmetic, field extraction) and referenced in conditions or actions.
**KQL equivalent:** Direct — `| extend`.
**Recipe:** Translate each variable to an `extend` before the conditions that use it. Common ESM function counterparts:

| ESM variable function | KQL |
|---|---|
| Concatenate | `strcat(a, b)` |
| Substring | `substring(s, start, len)` |
| ToLowerCase / ToUpperCase | `tolower(s)` / `toupper(s)` |
| Arithmetic (+, -, *, /) | same operators via `extend` |
| Regex extract | `extract(@"pattern", 1, field)` |
| Timestamp difference | `datetime_diff('minute', t1, t2)` |

**Caveats:** Variables referencing active list lookups combine this recipe with the active-list recipes above. An ESM function with no row in this table = flag as inference, Field Mapping −10.

### MatchesFilter (reference to a saved Filter resource)

**What it is:** `<Condition op="MatchesFilter" value="Corporate-Networks"/>` — the rule delegates part of its logic to a separately exported Filter resource.
**KQL equivalent:** Partial — inline the referenced filter.
**Recipe:** Locate the referenced filter's XML in the export package and inline its conditions, using the Nested Filter → KQL Options above: Option 1 (flatten) for a filter used by one rule; Option 2 (workspace KQL function) when the same filter is referenced by many rules in the batch — translate it once, `invoke` it everywhere.
**Caveats:** Referenced filter not included in the export = blocking question → `07-questions/open-questions.md`; do NOT approximate from the filter's name. Cap Logic Fidelity at 70% if forced to deliver without it.
