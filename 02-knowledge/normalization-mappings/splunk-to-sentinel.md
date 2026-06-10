# Splunk → Sentinel Field Mapping

Splunk uses SPL (Search Processing Language). Logs land in Sentinel via:
- **HEC/Syslog forwarding** → `CommonSecurityLog` or `Syslog`
- **Splunk Add-on forwarding** → various tables depending on source
- **Direct log source** → same table as original source (e.g., Windows events → `SecurityEvent`)

---

## Splunk JSON Export — Structure (savedsearches)

Splunk saves searches/alerts are exported as JSON. The SPL query is in **`content.search`**. Always parse from there first.

```json
{
  "name": "Multiple Failed Logins",
  "content": {
    "search": "index=wineventlog EventCode=4625 | stats count as failures by Account_Name, src | where failures > 5",
    "cron_schedule": "*/15 * * * *",
    "dispatch.earliest_time": "-15m",
    "dispatch.latest_time": "now",
    "alert_threshold": "0",
    "alert_comparator": "greater than",
    "alert.severity": "3",
    "description": "Detects brute force login attempts"
  }
}
```

**Extraction targets:**

| JSON key | Maps to |
|---|---|
| `content.search` | PRIMARY: SPL query string — extract `index`, `where`, `stats`, `eval`, `rex` |
| `content.cron_schedule` | `queryFrequency` — convert cron to ISO 8601 (see table below) |
| `content.dispatch.earliest_time` | `queryPeriod` — convert Splunk relative time to ISO 8601 |
| `content.alert.severity` | Sentinel severity via `severity-mappings.md` |
| `content.description` | SECONDARY only — consult for MITRE inference if SPL gives no hints |
| `name` | Sentinel `displayName` |

**Cron → ISO 8601 frequency:**

| Cron | ISO 8601 |
|---|---|
| `*/5 * * * *` | `PT5M` |
| `*/15 * * * *` | `PT15M` |
| `0 * * * *` | `PT1H` |
| `0 */4 * * *` | `PT4H` |
| `0 0 * * *` | `P1D` |

**Splunk relative time → KQL `ago()`:**

| Splunk | KQL |
|---|---|
| `-5m` | `ago(5m)` |
| `-15m` | `ago(15m)` |
| `-1h` | `ago(1h)` |
| `-24h` | `ago(24h)` |
| `-7d` | `ago(7d)` |

See `input-formats.md` for the full dual-input format spec.

---

## SPL Operator → KQL Operator

| SPL | KQL | Notes |
|---|---|---|
| `search index=X` | `TableName \| where ...` | KQL uses table names, not indexes |
| `where` | `\| where` | Identical semantics |
| `stats count by field` | `\| summarize count() by field` | |
| `stats count(field) as alias by ...` | `\| summarize alias = count() by ...` | |
| `stats dc(field) as alias` | `\| summarize alias = dcount(field)` | dc = distinct count |
| `stats sum(field) as alias` | `\| summarize alias = sum(field)` | |
| `stats avg(field) as alias` | `\| summarize alias = avg(field)` | |
| `stats min(field) as alias` | `\| summarize alias = min(field)` | |
| `stats max(field) as alias` | `\| summarize alias = max(field)` | |
| `stats values(field) as alias` | `\| summarize alias = make_set(field)` | |
| `stats list(field) as alias` | `\| summarize alias = make_list(field)` | |
| `stats first(field) as alias` | `\| summarize alias = arg_max(TimeGenerated, field)` | first = latest |
| `stats last(field) as alias` | `\| summarize alias = arg_min(TimeGenerated, field)` | last = earliest |
| `eval field = if(cond, a, b)` | `\| extend field = iff(cond, a, b)` | |
| `eval field = case(...)` | `\| extend field = case(...)` | |
| `eval field = coalesce(a,b)` | `\| extend field = coalesce(a,b)` | |
| `rex field=X "(?P<name>pattern)"` | `\| extend name = extract("pattern", 1, X)` | Named group → numbered |
| `spath` | `\| extend x = parse_json(field)` | JSON parsing |
| `mvexpand field` | `\| mv-expand field` | |
| `dedup field` | `\| distinct field` | |
| `sort -field` | `\| sort by field desc` | |
| `head N` | `\| top N by ...` or `\| limit N` | |
| `tail N` | `\| sort by TimeGenerated asc \| limit N` | |
| `table field1, field2` | `\| project field1, field2` | |
| `fields - field` | `\| project-away field` | |
| `rename field as alias` | `\| project-rename alias=field` | |
| `bin _time span=1h` | `\| bin TimeGenerated = 1h` or `summarize ... by bin(TimeGenerated,1h)` | |
| `timechart` | `\| summarize count() by bin(TimeGenerated, 1h)` | |
| `join type=inner` | `\| join kind=inner` | |
| `join type=left` | `\| join kind=leftouter` | |
| `lookup` | `\| lookup` or `\| join kind=leftouter` | |
| `inputlookup` | `_GetWatchlist('name')` or `datatable(...)` | |
| `transaction` | see Hard Constructs below | No direct equivalent |
| `eventstats` | `\| join kind=inner (T \| summarize ...)` | see Hard Constructs below |

---

## SPL Field Names → Sentinel Fields

### Windows/Authentication (Splunk Windows Add-on → SecurityEvent)

| Splunk Field | Sentinel Field | Notes |
|---|---|---|
| EventCode | EventID | |
| ComputerName | Computer | |
| Account_Name | AccountName | |
| Account_Domain | AccountDomain | |
| src_user | SubjectUserName | |
| dest_user | TargetUserName | |
| src | IpAddress | Source IP for auth |
| dest | Computer | Destination for lateral mvmt |
| Logon_Type | LogonType | |
| Status | Status | |
| Sub_Status | SubStatus | |
| Object_Name | ObjectName | |
| Process_Name | ProcessName | |
| Process_ID | ProcessId | |
| Privilege_List | PrivilegeList | |

### Network (Splunk Stream / network data)

| Splunk Field | Sentinel Field | Notes |
|---|---|---|
| src_ip | SourceIP (CSL) or LocalIP (DeviceNetworkEvents) | |
| dest_ip | DestinationIP (CSL) or RemoteIP | |
| src_port | SourcePort | |
| dest_port | DestinationPort | |
| transport | Protocol | |
| bytes_in | ReceivedBytes | |
| bytes_out | SentBytes | |
| url | RequestURL | |
| http_method | RequestMethod | |
| user_agent | RequestClientApplication | |
| status_code | EventResultDetails | |
| action | DeviceAction | |
| app | ApplicationProtocol | |

### Generic / CIM

| Splunk CIM Field | Sentinel Field | Notes |
|---|---|---|
| user | AccountName / SourceUserName | Context-dependent |
| src | SourceIP | |
| dest | DestinationIP | |
| signature | Activity | Event name |
| signature_id | DeviceEventClassID | |
| vendor_product | DeviceVendor + " " + DeviceProduct | |
| severity | LogSeverity | See severity-mappings.md |
| category | DeviceEventCategory | |
| message | Message | |
| _time | TimeGenerated | |
| _raw | SyslogMessage / RawData | |

---

## SPL → KQL Translation Examples

### Brute force detection
```spl
index=wineventlog EventCode=4625
| stats count as failures by Account_Name, src
| where failures > 5
```
```kql
let lookback = ago(1h);
let threshold = 5;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4625
| summarize failures = count() by AccountName, IpAddress
| where failures > threshold
| project TimeGenerated = now(), AccountName, IpAddress, failures
```

### Threat intel lookup
```spl
index=network
[inputlookup malicious_ips.csv | fields ip | rename ip as src_ip]
```
```kql
let lookback = ago(1h);
let malIPs = _GetWatchlist('malicious-ips') | project SearchKey;
CommonSecurityLog
| where TimeGenerated >= lookback
| where SourceIP in (malIPs) or DestinationIP in (malIPs)
```

### Regex extraction
```spl
| rex field=_raw "user=(?P<username>[^\s]+)"
```
```kql
| extend username = extract(@"user=(\S+)", 1, RawData)
```

### Time series / outlier
```spl
| timechart span=1h count by user
| anomalydetection
```
```kql
| make-series EventCount = count() on TimeGenerated step 1h by AccountName
| extend Anomalies = series_decompose_anomalies(EventCount)
```

---

## Splunk index → Sentinel table mapping

| Splunk Index | Data | Sentinel Table |
|---|---|---|
| wineventlog | Windows Security Events | SecurityEvent |
| syslog | Linux syslog | Syslog |
| cef | CEF/ArcSight data | CommonSecurityLog |
| o365 | Office 365 | OfficeActivity |
| azure | Azure logs | AzureActivity |
| aad | Azure AD | SigninLogs, AuditLogs |
| network | Network logs | CommonSecurityLog, NetworkSessionEvents |
| endpoint | Endpoint events | DeviceEvents, DeviceProcessEvents, etc. |
| dns | DNS logs | DnsEvents |
| proxy | Web proxy | CommonSecurityLog |

---

## Hard Constructs

SPL constructs without a 1:1 KQL equivalent. Recipe format: what it is → KQL equivalent (Direct / Partial / None) → recipe → caveats. Classify any rule containing these as **hard** in Step 0.

### `tstats` + CIM data models

**What it is:** `| tstats count from datamodel=Authentication where ... by Authentication.user` — accelerated searches over CIM data models instead of raw indexes.
**KQL equivalent:** Partial — the data model maps to a Sentinel table or ASIM parser; `tstats` acceleration itself is a performance feature, not logic.
**Recipe:** Map the data model, then translate the `where`/`by` clauses normally; CIM field names resolve via the Generic/CIM table above.

| Splunk CIM data model | Sentinel table / ASIM parser |
|---|---|
| `Authentication` | `imAuthentication` (preferred) / `SecurityEvent` / `SigninLogs` |
| `Network_Traffic` | `imNetworkSession` / `CommonSecurityLog` |
| `Network_Resolution` (DNS) | `imDns` / `DnsEvents` |
| `Endpoint.Processes` | `imProcessCreate` / `DeviceProcessEvents` |
| `Endpoint.Registry` | `imRegistryEvent` / `DeviceRegistryEvents` |
| `Endpoint.Filesystem` | `imFileEvent` / `DeviceFileEvents` |
| `Web` | `CommonSecurityLog` (proxy) / `W3CIISLog` |
| `Email` | `OfficeActivity` — flag if Defender for Office tables unavailable |
| `Change` (audit) | `imAuditEvent` / `AuditLogs` / `AzureActivity` |

**Caveats:** `summariesonly=t` only restricts Splunk to accelerated data — drop it, no KQL counterpart needed. ASIM parsers are the analogous normalization layer; prefer them so the rule stays source-agnostic. Confirm the ASIM parser is deployed in the client workspace (Table/Schema confidence −10 if unconfirmed).

### `transaction`

**What it is:** Groups events into "transactions" by field(s) with `maxspan`/`maxpause`/`startswith`/`endswith`.
**KQL equivalent:** None directly — three variants by what the rule actually uses:
**Recipe:**
- Used only for count/duration per group (`| transaction user maxspan=4h | where duration > X`): → pattern 16 (`02-knowledge/house-style/kql-patterns.md`) — `summarize min/max(TimeGenerated) by <field>, bin(TimeGenerated, maxspan)` + `extend Duration`.
- `startswith=X endswith=Y` pairing: → pattern 13 (time-window correlation join).
- True ordered reconstruction (intermediate event order matters): → pattern 15 (`scan`).
**Caveats:** `maxpause` (max gap between consecutive events) has no clean equivalent — approximate with `maxspan` binning and state the gap in notes.md. Logic Fidelity ≤ 85% for any `transaction` translation until tested.

### `streamstats` / `eventstats`

**What it is:** `streamstats` = running aggregates over ordered events; `eventstats` = group aggregate attached to every row without collapsing.
**KQL equivalent:** Partial.
**Recipe:** Pattern 18 (`02-knowledge/house-style/kql-patterns.md`): `streamstats` → `sort by <group> asc, TimeGenerated asc | serialize | extend ... row_cumsum()/prev()`; `eventstats` → compute the aggregate in a `let` subquery and `join kind=inner` back on the group keys.
**Caveats:** KQL has no implicit event order — the `sort | serialize` is mandatory or `prev()`/`row_cumsum()` results are undefined. `streamstats time_window=X` → add `bin(TimeGenerated, X)` to the restart condition.

### Macros

**What it is:** `` `macro_name(arg)` `` — text substitution defined in macros.conf; the SPL is not self-contained.
**KQL equivalent:** None without the definition.
**Recipe:** Request the macros.conf definition. Substitute arguments textually into the macro body, then translate the expanded SPL normally. If the same macro appears across many rules, translate it once as a workspace KQL function (`let` lambda — same approach as ArcSight Nested Filter Option 2 in `arcsight-esm-rule-syntax.md`).
**Caveats:** Definition unavailable = blocking question → `07-questions/open-questions.md`; cap Logic Fidelity at 70% and state which clause is unresolved. Never guess macro contents from the name.

### Subsearches

**What it is:** `[ search index=x ... | fields ip ]` or `[ inputlookup list.csv ]` embedded in the outer search — evaluated first, result substituted as a filter.
**KQL equivalent:** Direct — `let` subquery.
**Recipe:**
```kql
let sub = (CommonSecurityLog
    | where TimeGenerated >= ago(1h)
    | where <inner conditions>
    | project SourceIP);
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where SourceIP in (sub)
```
`inputlookup` → `_GetWatchlist` (see operator table above).
**Caveats:** Splunk silently truncates subsearches at 10,000 rows / 60 seconds; KQL has no such limit, so the translation may match MORE than the source did in production. Note in notes.md — this is fidelity to intent, not to the runtime quirk.

### Alert throttling

**What it is:** `alert.suppress = 1`, `alert.suppress.period = 4h`, `alert.suppress.fields = user` in savedsearches.conf — suppresses re-alerting, optionally per field value.
**KQL equivalent:** Partial.
**Recipe:**

| Splunk setting | Sentinel field |
|---|---|
| `alert.suppress = 1` | `suppressionEnabled: true` |
| `alert.suppress.period = 4h` | `suppressionDuration: "PT4H"` (ISO 8601) |
| `alert.suppress.fields = user` | No exact equivalent — nearest: `incidentConfiguration.groupingConfiguration` with `matchingMethod: "Selected"` + `groupByEntities` |

**Caveats:** Sentinel suppression is GLOBAL (the whole rule stops firing for the duration); Splunk per-field throttling only suppresses repeats for the same field value. Entity-based incident grouping approximates per-field behavior at the incident layer, not the alert layer. State this semantic difference in notes.md; Sentinel Metadata confidence −5.
