# LogRhythm → Sentinel Field Mapping

LogRhythm uses its own schema with normalized fields across log sources. Logs are forwarded via Syslog (CEF or JSON format) into Sentinel's `CommonSecurityLog` or `Syslog` table.

---

## LogRhythm Normalized Fields → Sentinel

### Identity and host

| LogRhythm Field | Sentinel Table | Sentinel Field | Notes |
|---|---|---|---|
| originHostName | CommonSecurityLog / Syslog | SourceHostName / Computer | Source host |
| impactedHostName | CommonSecurityLog | DestinationHostName | Target host |
| originLogin | CommonSecurityLog | SourceUserName | Originating user |
| impactedLogin | CommonSecurityLog | DestinationUserName | Target user |
| login | SecurityEvent | AccountName | Windows auth events |
| account | SecurityEvent | TargetUserName | Target account |
| domainOrigin | SecurityEvent | SubjectDomainName | |
| domainImpacted | SecurityEvent | TargetDomainName | |
| userAgent | CommonSecurityLog | RequestClientApplication | Browser/agent |

### Network

| LogRhythm Field | Sentinel Field | Notes |
|---|---|---|
| originIP | SourceIP | Source IP address |
| impactedIP | DestinationIP | Destination IP |
| originPort | SourcePort | |
| impactedPort | DestinationPort | |
| protocolName | Protocol | TCP/UDP/ICMP |
| bytesIn | ReceivedBytes | |
| bytesOut | SentBytes | |
| natIP | SourceTranslatedAddress | NAT'd source IP |
| natPort | SourceTranslatedPort | |

### Event metadata

| LogRhythm Field | Sentinel Field | Notes |
|---|---|---|
| vendorMsgID | DeviceEventClassID | Vendor event ID |
| classificationName | DeviceEventCategory | LR classification |
| commonEventName | Activity | Normalized event name |
| logSourceName | DeviceVendor | Log source name |
| logSourceType | DeviceProduct | Log source type |
| subject | Message (partial) | Event subject/title |
| action | DeviceAction | Action taken |
| result | DeviceEventOutcome | Result of action |
| reason | Reason | |
| severity | LogSeverity | LR severity 1-10; see severity-mappings.md |
| riskRating | (no direct map) | LR risk rating; map to Sentinel severity |

### Process and file

| LogRhythm Field | Sentinel Field | Notes |
|---|---|---|
| processName | ProcessName | Process name |
| processId | ProcessId | PID |
| command | ProcessCommandLine | Full command line |
| parentProcessName | ParentProcessName | Parent process |
| objectName | ObjectName | File/registry object |
| objectType | ObjectType | |
| hash | FileHash | |
| serialNumber | DeviceExternalID | |

### URL and application

| LogRhythm Field | Sentinel Field | Notes |
|---|---|---|
| url | RequestURL | |
| requestMethod | RequestMethod | |
| responseCode | EventResultDetails | HTTP response code |
| application | ApplicationProtocol | |
| interfaceName | DeviceInboundInterface | |

### Time

| LogRhythm Field | Sentinel Field | Notes |
|---|---|---|
| logDate | TimeGenerated | Sentinel ingest time |
| originatedDate | StartTime | Source event time |
| itemDate | TimeGenerated | |

---

## LogRhythm Classification → MITRE Tactic

| LR Classification | MITRE Tactic |
|---|---|
| Authentication Failure | CredentialAccess |
| Brute Force | CredentialAccess |
| Privilege Escalation | PrivilegeEscalation |
| Account Created | Persistence |
| Account Enabled | Persistence |
| Account Modified | Persistence |
| Malware | Execution, Impact |
| Network Scan | Discovery |
| Port Scan | Reconnaissance |
| Lateral Movement | LateralMovement |
| Data Loss | Exfiltration |
| Data Destruction | Impact |
| Policy Violation | (varies) |
| Suspicious Activity | DefenseEvasion |
| Audit Cleared | DefenseEvasion |
| Firewall Deny | (varies) |
| IDS Alert | (varies by sub-type) |

---

## LogRhythm Severity Scale → Sentinel

| LR Severity | Sentinel Severity |
|---|---|
| 10 | High |
| 8-9 | High |
| 5-7 | Medium |
| 3-4 | Low |
| 1-2 | Informational |

See `severity-mappings.md` for the canonical table.

---

## LogRhythm AI Engine Rule Syntax

LogRhythm rules are expressed as AI Engine (AIE) rule blocks, not a traditional query language. Always extract detection logic from the rule block structure — not the rule description.

**Full parsing guide:** `logrhythm-ai-engine-syntax.md`

Key extraction points:
- `matchCount` + `withinSeconds` → threshold + lookback window
- `matchType` (`Any` vs `Unique`) → `count()` vs `dcount()`
- `conditions[].field/comparator/value` → KQL `where` filter clauses
- `logSourceFilters[].logSourceType` → Sentinel table selection
- `riskRating` → Sentinel severity via `severity-mappings.md`

For multi-block rules (sequence detection), see the correlation patterns in `logrhythm-ai-engine-syntax.md`.

---

## LogRhythm KQL patterns

### Basic rule (failed auth > threshold)
```
-- LogRhythm
Classification: Authentication Failure
Threshold: > 5 within 60 minutes
```
```kql
let lookback = ago(1h);
let threshold = 5;
CommonSecurityLog
| where TimeGenerated >= lookback
| where DeviceEventCategory == "Authentication Failure"
| summarize FailCount = count() by SourceUserName, SourceIP, SourceHostName
| where FailCount > threshold
| project TimeGenerated = now(), SourceUserName, SourceIP, SourceHostName, FailCount
```

### LR compound rule (AND conditions)
```
-- LogRhythm compound rule
Classification = "Malware" AND
impactedHostName = "CRITICAL-SERVER*"
```
```kql
let lookback = ago(1h);
CommonSecurityLog
| where TimeGenerated >= lookback
| where DeviceEventCategory == "Malware"
| where DestinationHostName startswith "CRITICAL-SERVER"
| project TimeGenerated, DestinationHostName, SourceIP, Activity, Message
```

### LR correlation (sequence detection)
```
-- LR rule: Port scan then exploitation attempt
Rule A: Network Scan (10 events / 5 min)
then
Rule B: Exploit (within 30 min)
from same source
```
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
