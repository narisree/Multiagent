# KQL Pattern Library — Validated Skeletons by Detection Type

---

## 1. Brute Force / Failed Authentication (Windows)

**Source table:** SecurityEvent  
**Key EventIDs:** 4625 (failed), 4624 (success)

```kql
// Source: <SIEM> — <original rule name>
// Detects: Multiple failed logon attempts followed by success (brute force)
let lookback = ago(1h);
let threshold = 10;
let failedLogons = SecurityEvent
    | where TimeGenerated >= lookback
    | where EventID == 4625
    | where AccountType == "User"
    | summarize FailureCount = count(), FirstFailure = min(TimeGenerated)
        by AccountName, AccountDomain, IpAddress, WorkstationName;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4624
| where LogonType in (3, 10)
| join kind=inner (failedLogons | where FailureCount > threshold)
    on AccountName, AccountDomain
| project TimeGenerated, AccountName, AccountDomain, IpAddress,
    WorkstationName, FailureCount, FirstFailure, Computer
```

---

## 2. Brute Force (CEF / ArcSight)

**Source table:** CommonSecurityLog

```kql
// Source: <SIEM> — <original rule name>
let lookback = ago(1h);
let threshold = 10;
CommonSecurityLog
| where TimeGenerated >= lookback
| where DeviceEventCategory has_any ("Authentication", "authentication failure", "logon failure")
| where DeviceEventOutcome != "Success"
| summarize FailureCount = count(), SourceIPs = make_set(SourceIP)
    by SourceUserName, DestinationHostName
| where FailureCount > threshold
| project TimeGenerated = now(), SourceUserName, DestinationHostName,
    FailureCount, SourceIPs
```

---

## 3. Password Spray (many accounts, few attempts each)

```kql
// Source: <SIEM> — <original rule name>
// Detects: Same source IP attempting many different accounts (low per-account count)
let lookback = ago(1h);
let minAccounts = 10;
let maxAttemptsPerAccount = 3;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4625
| summarize AttemptCount = count(), UniqueAccounts = dcount(AccountName)
    by IpAddress
| where UniqueAccounts >= minAccounts
| project TimeGenerated = now(), IpAddress, AttemptCount, UniqueAccounts
```

---

## 4. Privilege Escalation — Admin Group Membership

```kql
// Source: <SIEM> — <original rule name>
// Detects: User added to privileged groups
let lookback = ago(1h);
let sensitiveGroups = dynamic([
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators"
]);
SecurityEvent
| where TimeGenerated >= lookback
| where EventID in (4728, 4732, 4756)   // added to global/local/universal group
| where TargetUserName in~ (sensitiveGroups)
| project TimeGenerated, AccountName, AccountDomain,
    TargetUserName, SubjectUserName, Computer, EventID
```

---

## 5. Lateral Movement — Pass-the-Hash

```kql
// Source: <SIEM> — <original rule name>
// Detects: NTLM network logon without interactive session (PtH indicator)
let lookback = ago(1h);
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where WorkstationName != Computer
| where AccountName !endswith "$"             // exclude machine accounts
| where IpAddress != "127.0.0.1" and IpAddress != "-"
| project TimeGenerated, AccountName, AccountDomain,
    IpAddress, WorkstationName, Computer, LogonType
```

---

## 6. Process Execution — Suspicious Command Line

```kql
// Source: <SIEM> — <original rule name>
let lookback = ago(1h);
let suspiciousPatterns = dynamic([
    "powershell.*-enc", "cmd.*\/c.*echo", "certutil.*-decode",
    "bitsadmin.*transfer", "wmic.*process.*call", "mshta.*http"
]);
DeviceProcessEvents
| where TimeGenerated >= lookback
| where ProcessCommandLine matches regex @"(?i)(powershell.*-e[nc]+ |certutil.*-decode|bitsadmin.*/transfer|wmic.*process.*call.*create|mshta.*http)"
| project TimeGenerated, DeviceName, AccountName, AccountDomain,
    ProcessCommandLine, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 7. Network Anomaly — Beaconing Detection

```kql
// Source: <SIEM> — <original rule name>
// Detects: Regular connection intervals suggesting C2 beaconing
let lookback = ago(24h);
let minConnections = 10;
DeviceNetworkEvents
| where TimeGenerated >= lookback
| where ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| summarize ConnectionCount = count(),
    IntervalStdev = stdev(datetime_diff("minute", TimeGenerated, prev(TimeGenerated, 1)))
    by DeviceName, RemoteIP, RemotePort
| where ConnectionCount >= minConnections
| where IntervalStdev < 2                // low variance = regular interval
| project TimeGenerated = now(), DeviceName, RemoteIP, RemotePort,
    ConnectionCount, IntervalStdev
```

---

## 8. Data Exfiltration — Large Upload

```kql
// Source: <SIEM> — <original rule name>
let lookback = ago(1h);
let thresholdBytes = 100000000;   // 100 MB
CommonSecurityLog
| where TimeGenerated >= lookback
| where CommunicationDirection == 1 or DeviceEventCategory has "upload"
| summarize TotalBytes = sum(SentBytes) by SourceIP, DestinationIP, SourceUserName
| where TotalBytes > thresholdBytes
| project TimeGenerated = now(), SourceIP, DestinationIP, SourceUserName,
    TotalBytes, TotalMB = TotalBytes / 1048576
```

---

## 9. Threat Intel — IP Lookup

```kql
// Source: <SIEM> — <original rule name>
let lookback = ago(1h);
let maliciousIPs = ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(14d)
    | where isnotempty(NetworkIP) and Active == true and Confidence >= 70
    | project NetworkIP, ThreatType, Description;
CommonSecurityLog
| where TimeGenerated >= lookback
| join kind=inner (maliciousIPs) on $left.SourceIP == $right.NetworkIP
| project TimeGenerated, SourceIP, DestinationIP, SourceUserName,
    DeviceVendor, Activity, ThreatType, Description
```

---

## 10. Defense Evasion — Security Log Cleared

```kql
// Source: <SIEM> — <original rule name>
let lookback = ago(1h);
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 1102        // Security log cleared
    or EventID == 4688 and ProcessCommandLine has "wevtutil" and ProcessCommandLine has "cl"
| project TimeGenerated, Computer, AccountName, AccountDomain,
    EventID, Activity, ProcessCommandLine
```

---

## 11. Scheduled Task Creation

```kql
// Source: <SIEM> — <original rule name>
let lookback = ago(1h);
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4698   // Scheduled task created
| extend TaskDetails = parse_xml(TaskContentXml)
| project TimeGenerated, Computer, AccountName, AccountDomain,
    TaskName, TaskContentXml
```

---

## 12. Azure AD — Impossible Travel / Suspicious Sign-in

```kql
// Source: <SIEM> — <original rule name>
let lookback = ago(1h);
SigninLogs
| where TimeGenerated >= lookback
| where ResultType == 0   // Successful sign-in
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City   = tostring(LocationDetails.city)
| summarize Countries = make_set(Country), Cities = make_set(City),
    IPCount = dcount(IPAddress), SigninCount = count()
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1    // signed in from multiple countries in 1 hour
| project TimeGenerated, UserPrincipalName, Countries, Cities, IPCount, SigninCount
```

---

## 13. Time-Window Correlation (Add then Remove pattern)

Source: Azure/Azure-Sentinel Tools/RuleMigration/Rule Logic Mappings.md

**Use when:** Rule fires on event B occurring within a time window after event A, from the same entity (user/IP/host). The classic ArcSight `<EventJoin>` and QRadar "time window" pattern.

```kql
// Source: <SIEM> — <original rule name>
// Detects: Event A followed by Event B from same entity within lookback window
let waittime = 10m;   // must see event2 after event1 by at least this long
let lookback = 1d;    // maximum gap between event1 and event2
let event1 = (
    SecurityEvent
    | where TimeGenerated > ago(waittime + lookback)
    | where EventID == 4728   // replace with actual event1 filter
    | project event1_time = TimeGenerated, event1_ID = EventID,
        event1_Activity = Activity, event1_Host = Computer,
        TargetUserName, AccountUsedToAdd = SubjectUserName
);
let event2 = (
    SecurityEvent
    | where TimeGenerated > ago(waittime)
    | where EventID == 4729   // replace with actual event2 filter
    | project event2_time = TimeGenerated, event2_ID = EventID,
        event2_Activity = Activity, event2_Host = Computer,
        TargetUserName, AccountUsedToRemove = SubjectUserName
);
event1
| join kind=inner event2 on TargetUserName
| where event2_time - event1_time < lookback
| where tolong(event2_time - event1_time) >= 0
| project delta_time = event2_time - event1_time,
    event1_time, event2_time, event1_ID, event2_ID,
    event1_Activity, event2_Activity, TargetUserName,
    AccountUsedToAdd, AccountUsedToRemove,
    event1_Host, event2_Host
```

**Key notes:**
- `event1` lookback = `waittime + lookback` to catch pairs where event2 just arrived
- `event2` lookback = `waittime` (only recent events)
- Post-join filter `event2_time - event1_time >= 0` ensures correct ordering
- `delta_time` column useful for incident review

---

## 14. Negative Correlation (None-of-these-rules match)

Source: Azure/Azure-Sentinel Tools/RuleMigration/Rule Logic Mappings.md

**Use when:** QRadar "negative function" — fire when rule A matches but rule B does NOT match from the same source. Maps to `join kind=rightanti`.

```kql
// Source: QRadar — <original rule name>
// Detects: Events matching condition A with NO corresponding event matching condition B
let spanoftime = 10m;
let conditionA = (
    CommonSecurityLog
    | where TimeGenerated > ago(spanoftime)
    | where <condition A filter>
    | project TimeGenerated, SourceIP, Protocol
);
let conditionB = (
    CommonSecurityLog
    | where TimeGenerated > ago(spanoftime)
    | where <condition B filter>   // events that EXCLUDE the alert
    | project SourceIP, Protocol
);
conditionA
| join kind=rightanti conditionB on SourceIP, Protocol
| project TimeGenerated, SourceIP, Protocol
```

**`rightanti` semantics:** returns rows from the right table that have NO match in the left table. Used to model "B happened but A did not."

---

## Performance Notes (from Microsoft Rule Migration Guide)

Source: Azure/Azure-Sentinel Tools/RuleMigration/Rule Logic Mappings.md

Apply these to every query:

1. **Smaller table on the left in joins.** KQL broadcasts the left table; keeping it small reduces memory.
2. **`hint.strategy=broadcast`** for the smaller table when it has ≤ ~100K records:
   ```kql
   bigTable | join hint.strategy=broadcast (smallTable) on Key
   ```
3. **Prefer `==` over `=~`** (case-sensitive is faster). Only use `=~`/`!~` when case-insensitivity is genuinely needed.
4. **Prefer `has` over `contains`** for whole-word token matching — `has` uses inverted index; `contains` does full string scan.
5. **Never use `search`** when the table name is known — `search` scans all tables.
6. **Order `| where` clauses** from most-selective to least-selective — earliest filters reduce rows for downstream operators.
7. **Use `in` over multiple `or`** for list membership — identical performance, better readability.
