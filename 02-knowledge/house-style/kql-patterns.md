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
