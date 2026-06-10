# QRadar → Sentinel Field Mapping

QRadar rules use AQL (Ariel Query Language) and an internal event model. Logs are forwarded to Sentinel via:
- **Syslog** (raw), ingesting to `Syslog` table
- **CEF forwarding**, ingesting to `CommonSecurityLog`
- **Custom parsers** → custom `_CL` tables

---

## QRadar JSON Rule Export — Structure

When QRadar rules are exported as JSON, the AQL query is in **`aqlQuery`** (preferred) or **`buildingBlocks[].logic`**. Always parse from there — not from the rule name or description.

```json
{
  "id": 12345,
  "name": "Multiple Failed Logins",
  "type": "EventRule",
  "enabled": true,
  "groups": ["Authentication"],
  "priority": 7,
  "aqlQuery": "SELECT username, sourceip, count(*) AS cnt FROM events WHERE qid = 5100008 GROUP BY username, sourceip HAVING cnt > 5 LAST 10 MINUTES",
  "buildingBlocks": [
    { "id": 1, "name": "Auth failures BB", "logic": "SELECT ... FROM events WHERE ..." }
  ],
  "responseActions": []
}
```

**Extraction targets:**

| JSON key | Maps to |
|---|---|
| `aqlQuery` | PRIMARY: AQL query string — extract filter, GROUP BY, HAVING, LAST N |
| `buildingBlocks[].logic` | FALLBACK: building block AQL (use when `aqlQuery` is absent) |
| `priority` (1-10) | Sentinel severity via `severity-mappings.md` |
| `groups[]` | MITRE tactic inference (e.g., `"Authentication"` → `CredentialAccess`) |
| `enabled` | Sentinel `enabled` field |
| `name` | Sentinel `displayName` |

**AQL LAST clause → ISO 8601:**

| AQL | KQL / ISO 8601 |
|---|---|
| `LAST 10 MINUTES` | `ago(10m)` / `PT10M` |
| `LAST 1 HOURS` | `ago(1h)` / `PT1H` |
| `LAST 24 HOURS` | `ago(24h)` / `PT24H` |
| `LAST 7 DAYS` | `ago(7d)` / `P7D` |

See `input-formats.md` for the full dual-input format spec.

---

## QRadar Event Model → Sentinel Fields

### Core identity fields

| QRadar Field | Sentinel Table | Sentinel Field | Notes |
|---|---|---|---|
| sourceip | CommonSecurityLog / Syslog | SourceIP / extract from SyslogMessage | |
| destinationip | CommonSecurityLog | DestinationIP | |
| sourceport | CommonSecurityLog | SourcePort | |
| destinationport | CommonSecurityLog | DestinationPort | |
| username | CommonSecurityLog / Syslog | SourceUserName / extract | |
| domainname | CommonSecurityLog | SourceNTDomain | |
| hostname | Syslog / CommonSecurityLog | Computer / SourceHostName | |

### Event identification

| QRadar Field | Sentinel Field | Notes |
|---|---|---|
| QIDNAME (event name) | Activity | From QID map |
| qid | DeviceEventClassID | QRadar event ID |
| logsourcename | DeviceVendor + DeviceProduct | Combine vendor/product |
| logsourcetypename | DeviceProduct | |
| logsourceid | (no direct map) | Infer from DeviceProduct/Vendor |
| category / categoryname | DeviceEventCategory | High-level category |
| subcategoryname | Activity (secondary) | |
| eventcount | (summarize count) | Use in aggregation |
| magnitude | (no direct map) | Infer from LogSeverity |

### Network fields

| QRadar Field | Sentinel Field | Notes |
|---|---|---|
| protocolname | Protocol | TCP/UDP/ICMP |
| direction | CommunicationDirection | INBOUND/OUTBOUND |
| BytesSent | SentBytes | |
| BytesReceived | ReceivedBytes | |
| PacketsSent | SentPackets | |
| PacketsReceived | ReceivedPackets | |
| sourcegeographic | (no direct map) | |
| destinationgeographic | (no direct map) | |

### Time fields

| QRadar Field | Sentinel Field | Notes |
|---|---|---|
| starttime | StartTime | Epoch milliseconds → datetime |
| endtime | EndTime | |
| devicetime | TimeGenerated | Approximate; use TimeGenerated |
| storetime | TimeGenerated | Sentinel ingest time |

### Payload / raw data

| QRadar Field | Sentinel Field | Notes |
|---|---|---|
| payload | RawData (Syslog: SyslogMessage) | Full raw log |
| utf8payload | Message | Decoded payload |

---

## QRadar AQL → KQL translation patterns

### Basic filter
```aql
-- QRadar AQL
SELECT * FROM events WHERE sourceip = '1.2.3.4'
```
```kql
-- KQL equivalent
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where SourceIP == "1.2.3.4"
```

### Aggregation / threshold
```aql
-- QRadar AQL: failed logins > 5
SELECT username, sourceip, COUNT(*) as count
FROM events WHERE qid = 5100008
GROUP BY username, sourceip
HAVING count > 5
```
```kql
-- KQL equivalent
let lookback = ago(1h);
let threshold = 5;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4625
| summarize FailureCount = count() by AccountName, IpAddress
| where FailureCount > threshold
| project TimeGenerated = now(), AccountName, IpAddress, FailureCount
```

### Rule with offense (correlation)
QRadar offenses map to Sentinel incidents. The rule that triggers the offense becomes the Analytics Rule.

### CONTAINS / MATCHES
```aql
payload ICONTAINS 'malware'
```
```kql
| where SyslogMessage contains "malware"    // or
| where tolower(SyslogMessage) has "malware"
```

### INCIDR
```aql
sourceip INCIDR '10.0.0.0/8'
```
```kql
| where ipv4_is_in_range(SourceIP, "10.0.0.0/8")
```

### MATCHES (regex)
```aql
payload MATCHES '.*\\.exe$'
```
```kql
| where Message matches regex @"\.exe$"
```

---

## QRadar Severity → Sentinel Severity

See `severity-mappings.md`. QRadar uses 1-10 (magnitude) and Low/Medium/High.

---

## QRadar Category → MITRE Tactic

| QRadar Category | MITRE Tactic |
|---|---|
| Authentication | CredentialAccess |
| Access | InitialAccess |
| Exploit | Execution |
| Malware | Execution, Impact |
| Reconnaissance | Reconnaissance, Discovery |
| Suspicious Activity | DefenseEvasion |
| DDoS | Impact |
| Botnet | CommandAndControl |
| Application Activity | Collection |
| Audit | (varies) |

---

## Syslog-forwarded QRadar events

When QRadar forwards via Syslog:
```kql
Syslog
| where TimeGenerated >= ago(1h)
| where Facility == "local0"                         // or the configured facility
| where SyslogMessage contains "QRadar"              // if tagged
| parse SyslogMessage with * "src=" SourceIP " " * "dst=" DestinationIP " " *
```

Use `parse` or `extract()` to pull structured fields out of SyslogMessage.

---

## QRadar Reference Sets → Sentinel Watchlists

```aql
-- QRadar: Reference Set membership
sourceip IN (SELECT value FROM reference_set WHERE set_name = 'Blocklist-IPs')
```
```kql
-- KQL equivalent using Sentinel Watchlist
let BlocklistIPs = _GetWatchlist('Blocklist-IPs') | project SearchKey;
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where SourceIP in (BlocklistIPs)
```

---

## QRadar Date/Time Tests → KQL

Source: Azure/Azure-Sentinel Tools/RuleMigration/Rule Logic Mappings.md

QRadar rules can filter by day-of-month, day-of-week, and time-of-day. KQL equivalents:

### Day of month
```aql
-- QRadar: event occurs on day < 4 of month
```
```kql
| where dayofmonth(TimeGenerated) < 4
```

### Day of week
```aql
-- QRadar: event occurs Wednesday–Friday
```
```kql
| where dayofweek(TimeGenerated) between (3d .. 5d)
// dayofweek() returns a timespan: 0d=Sun, 1d=Mon, 2d=Tue, 3d=Wed, 4d=Thu, 5d=Fri, 6d=Sat
```

### Time of day
```aql
-- QRadar: event occurs at 23:55
```
```kql
| where format_datetime(TimeGenerated, 'HH:mm') == "23:55"
// TimeGenerated is UTC — convert to local time first if needed: datetime_utc_to_local()
```

---

## QRadar Negative Function → KQL

Source: Azure/Azure-Sentinel Tools/RuleMigration/Rule Logic Mappings.md

QRadar "none of these rules match" (negative function) — fire when condition A is true but condition B is NOT true from the same source within the time window.

```aql
-- QRadar: Test2 matches but Test6 does NOT match (same SourceIP + Protocol)
```
```kql
let spanoftime = 10m;
let conditionA = (
    CommonSecurityLog
    | where Protocol !in ("UDP", "ICMP")
    | where TimeGenerated > ago(spanoftime)
);
let conditionB = (
    CommonSecurityLog
    | where SourceIP == DestinationIP
);
conditionA
| join kind=rightanti conditionB on $left.SourceIP == $right.SourceIP
    and $left.Protocol == $right.Protocol
```

**`rightanti` join:** returns rows from right table with NO matching row in left table. Use when detecting absence of a correlating event.

---

## Hard Constructs

Stateful or compositional QRadar constructs without a 1:1 KQL equivalent. Recipe format: what it is → KQL equivalent (Direct / Partial / None) → recipe → caveats. Classify any rule containing these as **hard** in Step 0.

### Building-block chains

**What it is:** A rule whose tests reference other building blocks ("when BB:AuthFailures matches AND BB:ExternalSource matches"). In the JSON export, the rule's `aqlQuery` may be absent and the logic spread across `buildingBlocks[].logic`, with BBs referencing other BBs by name/id.
**KQL equivalent:** Partial — compose via `let` blocks.
**Recipe:** Resolve references recursively at parse time, then inline each building block as a named `let` tabular expression:
```kql
// BB:AuthFailures + BB:ExternalSource composed into one rule
let lookback = ago(10m);
let bbAuthFailures = SecurityEvent
    | where TimeGenerated >= lookback
    | where EventID == 4625;
let bbExternalSource = bbAuthFailures
    | where not(ipv4_is_private(IpAddress));
bbExternalSource
| summarize FailureCount = count() by AccountName, IpAddress
| where FailureCount > 5
| project AccountName, IpAddress, FailureCount
```
**Caveats:** Chains deeper than 2 levels, or BBs referenced by multiple rules, are a signal to translate the shared BB once as a workspace KQL function instead of inlining N times. Circular BB references or a BB whose `logic` is missing from the export = blocking question → `07-questions/open-questions.md`. Logic Fidelity −10 when any referenced BB had to be inferred.

### Reference set WRITE (response action)

**What it is:** `responseActions[]` containing an add-to-reference-set action (e.g., `{"type": "addToReferenceSet", "set": "Blocklist-IPs", "value": "sourceip"}`). The rule both detects AND updates shared state.
**KQL equivalent:** None — decomposition required.
**Recipe:** Pattern 17 in `02-knowledge/house-style/kql-patterns.md`: (1) Analytics Rule for the detection (reference-set READ stays `_GetWatchlist`, see section above), (2) Sentinel Watchlist as the state store, (3) automation rule + Logic App playbook performing the watchlist write. Agent delivers rule.json + playbook spec in notes.md; playbook deployment is the user's manual step.
**Caveats:** QRadar reference sets support per-element TTL (`time_to_live`); Watchlists do not auto-expire — note staleness risk and the need for a pruning playbook. Logic Fidelity ≤ 80% until the full chain is deployed.

### AQL custom properties

**What it is:** Custom event properties (regex- or JSON-extracted fields defined in QRadar, e.g., `"CustomUsername"`) appearing as ordinary columns in AQL.
**KQL equivalent:** Partial — re-create the extraction inline.
**Recipe:** Obtain the property's extraction definition from the QRadar export (or ask). Then:
```kql
| extend CustomUsername = extract(@"user=(\S+)", 1, SyslogMessage)
```
If the client's Sentinel ingestion has a custom parser/DCR producing a `_CL` table, map to that column instead and confirm the table name with the user.
**Caveats:** Always inference — drop Field Mapping confidence ≥10 points per Step 3 rule 4 and add the property to `07-questions/open-questions.md` if the extraction regex was not in the export.

### Offense chaining

**What it is:** Rules testing offense attributes ("when an offense is created", "when the offense magnitude exceeds N") — second-order logic over QRadar's correlation output, not over events.
**KQL equivalent:** Partial — two options by intent.
**Recipe:**
- If the chain only aggregates the same detection (dedup/grouping): use the Analytics Rule's `incidentConfiguration.groupingConfiguration` (matchingMethod `AllEntities` or `Selected`) instead of a second rule.
- If the chain tests "offense from rule X exists, then…": write a second-stage Analytics Rule over `SecurityAlert`:
```kql
let lookback = ago(1h);
SecurityAlert
| where TimeGenerated >= lookback
| where AlertName == "<first-stage rule displayName>"
| summarize AlertCount = count() by CompromisedEntity
| where AlertCount > 3
```
**Caveats:** `SecurityAlert` rows appear minutes after the first-stage rule fires — set the second-stage `queryPeriod` generously (≥ 2× first-stage frequency). Offense magnitude has no Sentinel equivalent (closest: alert severity) — flag as inference.
