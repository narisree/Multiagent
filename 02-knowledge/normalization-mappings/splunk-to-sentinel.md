# Splunk → Sentinel Field Mapping

Splunk uses SPL (Search Processing Language). Logs land in Sentinel via:
- **HEC/Syslog forwarding** → `CommonSecurityLog` or `Syslog`
- **Splunk Add-on forwarding** → various tables depending on source
- **Direct log source** → same table as original source (e.g., Windows events → `SecurityEvent`)

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
| `transaction` | `\| scan` or correlate with bin+summarize | No direct equivalent |
| `eventstats` | `\| join kind=inner (T \| summarize ...)` | Window aggregation |

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
