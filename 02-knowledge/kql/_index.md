# KQL Knowledge Index

## Files

| File | Contents |
|---|---|
| `operators-reference.md` | All tabular operators: where, project, summarize, join, union, parse, mv-expand, etc. |
| `functions-reference.md` | Scalar/aggregation functions: string, datetime, numeric, IP, dynamic, conditional |
| `time-operators.md` | Time syntax, ago(), bin(), datetime, ISO 8601 durations, make-series |

## Quick reference: most-used patterns in translations

```kql
// Standard rule skeleton
let lookback = ago(1h);
let threshold = 5;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4625
| summarize FailureCount = count() by AccountName, Computer, bin(TimeGenerated, 1h)
| where FailureCount > threshold
| project TimeGenerated, AccountName, Computer, FailureCount
```

```kql
// Cross-table correlation (join)
let lookback = ago(1h);
let failedLogins = SecurityEvent
    | where TimeGenerated >= lookback
    | where EventID == 4625
    | summarize FailCount = count() by AccountName;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4624
| join kind=inner (failedLogins) on AccountName
| where FailCount > 5
| project TimeGenerated, AccountName, Computer, FailCount
```

```kql
// Threat intel lookup
let lookback = ago(1h);
let maliciousIPs = ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(14d)
    | where isnotempty(NetworkIP) and Active == true
    | project NetworkIP;
CommonSecurityLog
| where TimeGenerated >= lookback
| where SourceIP in (maliciousIPs) or DestinationIP in (maliciousIPs)
| project TimeGenerated, SourceIP, DestinationIP, DeviceVendor, Activity
```
