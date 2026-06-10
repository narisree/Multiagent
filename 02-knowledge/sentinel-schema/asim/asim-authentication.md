# ASIM Authentication Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimAuthentication.yaml` (v0.1.3, 2023-01-30)

Sentinel tables: `imAuthentication`, `ASimAuthenticationEvent`

Normalizes logon, logoff, and privilege elevation events from any source.

---

## Schema-Specific Fields

| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | `Logon`, `Logoff`, `Elevate` |
| EventSchema | string | Mandatory | `Authentication` |
| EventResultDetails | string | Recommended | `No such user or password`, `No such user`, `Incorrect password`, `Incorrect key`, `Account expired`, `Password expired`, `User locked`, `User disabled`, `Logon violates policy`, `Session expired`, `Other` |
| EventSubType | string | Optional | `System`, `Interactive`, `Service`, `RemoteInteractive`, `RemoteService`, `Remote`, `AssumeRole` |
| LogonMethod | string | Optional | Authentication technique used (e.g., `Username & Password`) |
| LogonProtocol | string | Optional | Protocol used (e.g., `NTLM`, `Kerberos`, `OAuth`) |

## Included Entities

- **Dvc** — device entity fields (DvcHostname, DvcIpAddr, DvcId, DvcOs, etc.)
- **Actor** — initiating user (ActorUsername, ActorUserId, ActorUserType, ActorSessionId)
- **Acting Application** — app performing the auth (ActingAppName, ActingAppId, ActingAppType)
- **Target Application** — app being authenticated to (TargetAppName, TargetAppId, TargetAppType, TargetUrl)
- **Target User** — account being authenticated (TargetUsername, TargetUserId, TargetUserType)
- **Source System** — origin system (SrcIpAddr, SrcHostname, SrcDomain, SrcPortNumber)
- **Target System** — destination system (DstIpAddr, DstHostname, DstDomain, DstPortNumber)

## Aliases

| Alias | Maps To |
|---|---|
| User | TargetUsername |
| IpAddr | SrcIpAddr |
| LogonTarget | TargetAppName, TargetUrl, TargetHostname |
| Application | TargetAppName |

## Common KQL usage

```kql
// ASIM authentication events - normalized across all sources
imAuthentication
| where TimeGenerated >= ago(1h)
| where EventType == "Logon" and EventResult == "Failure"
| summarize FailCount = count() by TargetUsername, SrcIpAddr
| where FailCount > 10
```
