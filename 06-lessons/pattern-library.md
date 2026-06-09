# Pattern Library — Input Shape → KQL Snippet

Append after every successful translation.

---

## Format

```
### <source-siem> — <detection-type> — <input-shape signature>

**Example input:** <one line description>
**KQL snippet:**
[snippet]
**When to use:** <one sentence>
**Source output:** 08-generated/<folder>/
**Lesson refs:** L-XXXX-XX-XX-NNN, ...
```

---

## Bootstrap entries (from house style)

### SecurityEvent — Brute Force — failed logon count > threshold

**Example input:** ArcSight rule: "10+ failed logins from same IP within 60 minutes"
**KQL snippet:**
```kql
let lookback = ago(1h);
let threshold = 10;
SecurityEvent
| where TimeGenerated >= lookback
| where EventID == 4625
| summarize FailureCount = count() by AccountName, IpAddress
| where FailureCount > threshold
| project TimeGenerated = now(), AccountName, IpAddress, FailureCount
```
**When to use:** Any SIEM rule that counts failed authentications against a threshold.
**Source output:** (bootstrap — not from a specific translation)
**Lesson refs:** L-2026-06-09-004, L-2026-06-09-008

---

### CommonSecurityLog — Network Threat Intel Lookup — IP in blocklist

**Example input:** QRadar rule: "Connection from IP in reference set 'Malicious-IPs'"
**KQL snippet:**
```kql
let lookback = ago(1h);
let malIPs = _GetWatchlist('Malicious-IPs') | project SearchKey;
CommonSecurityLog
| where TimeGenerated >= lookback
| where SourceIP in (malIPs) or DestinationIP in (malIPs)
| project TimeGenerated, SourceIP, DestinationIP, Activity, DeviceVendor
```
**When to use:** Any source SIEM rule referencing a reference set / blocklist / watchlist.
**Source output:** (bootstrap)
**Lesson refs:** L-2026-06-09-007
