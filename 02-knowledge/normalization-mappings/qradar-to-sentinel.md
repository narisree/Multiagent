# QRadar → Sentinel Field Mapping

QRadar rules use AQL (Ariel Query Language) and an internal event model. Logs are forwarded to Sentinel via:
- **Syslog** (raw), ingesting to `Syslog` table
- **CEF forwarding**, ingesting to `CommonSecurityLog`
- **Custom parsers** → custom `_CL` tables

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
