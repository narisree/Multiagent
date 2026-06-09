# Sentinel Tables Reference

Key fields for each major table. Use this to determine which table to query and which fields are available.

---

## SecurityEvent — Windows Security Events (MMA/AMA agent)

**Connector:** Windows Security Events via MMA / Windows Security Events via AMA
**Key fields:**

| Field | Type | Description |
|---|---|---|
| TimeGenerated | datetime | Event timestamp |
| EventID | int | Windows Event ID |
| Computer | string | Source computer |
| Account | string | DOMAIN\UserName |
| AccountName | string | Username only |
| AccountDomain | string | Domain only |
| SubjectUserName | string | User who initiated action |
| SubjectDomainName | string | Domain of initiating user |
| TargetUserName | string | Target user |
| TargetDomainName | string | Target domain |
| LogonType | int | Logon type (2=interactive, 3=network, 10=remote) |
| LogonTypeName | string | Human-readable logon type |
| IpAddress | string | Source IP (-/127.0.0.1 for local) |
| IpPort | string | Source port |
| WorkstationName | string | Originating workstation |
| ProcessName | string | Process that generated event |
| ProcessId | int | Process ID |
| Activity | string | Human-readable event description |
| Status | string | Event status |
| SubStatus | string | Substatus code |
| FailureReason | string | Logon failure reason |
| ObjectName | string | Target object |
| ObjectType | string | Object type |
| ShareName | string | Network share |
| ShareLocalPath | string | Local path of share |
| TaskName | string | Scheduled task name (ID 4698) |
| PrivilegeList | string | Privileges used |
| KeyLength | int | Key length for Kerberos |

**Common EventIDs:**
| ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credential logon (runas) |
| 4656 | Object access attempted |
| 4663 | Object access performed |
| 4672 | Special privilege logon |
| 4688 | Process created |
| 4698 | Scheduled task created |
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset |
| 4728 | Member added to global group |
| 4732 | Member added to local group |
| 4738 | User account changed |
| 4740 | Account locked out |
| 4756 | Member added to universal group |
| 4776 | NTLM credential validation |
| 5140 | Network share accessed |
| 5145 | Network share object access checked |
| 7045 | Service installed |

---

## WindowsEvent — Windows Events (AMA, XML format)

**Key fields:** TimeGenerated, Computer, Channel, EventID, EventData (dynamic/XML)

```kql
WindowsEvent
| where EventID == 4625
| extend AccountName = tostring(EventData.SubjectUserName)
         , LogonType  = toint(EventData.LogonType)
         , IpAddress  = tostring(EventData.IpAddress)
```

---

## Syslog — Linux Syslog

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| Computer | Hostname |
| SyslogMessage | Full log message |
| Facility | Syslog facility (auth, daemon, kern, etc.) |
| FacilityName | Human-readable facility |
| SeverityLevel | emergency/alert/critical/error/warning/notice/info/debug |
| SeverityNumber | 0-7 |
| ProcessID | PID |
| ProcessName | Process name |
| HostName | Source host |

---

## CommonSecurityLog — CEF / ArcSight / SIEM connectors

**Connector:** Common Event Format (CEF) via AMA or Syslog

| Field | CEF Field | Description |
|---|---|---|
| TimeGenerated | rt (receipt time) | Sentinel ingest time |
| DeviceVendor | deviceVendor | e.g., "ArcSight" |
| DeviceProduct | deviceProduct | Product name |
| DeviceVersion | deviceVersion | Product version |
| DeviceEventClassID | deviceEventClassId | Event class / rule ID |
| Activity | name | Event name |
| LogSeverity | severity | String severity 0-10 or Low/Medium/High |
| SourceIP | src | Source IP address |
| SourcePort | spt | Source port |
| SourceUserName | suser | Source username |
| SourceHostName | shost | Source hostname |
| DestinationIP | dst | Destination IP |
| DestinationPort | dpt | Destination port |
| DestinationUserName | duser | Destination username |
| DestinationHostName | dhost | Destination hostname |
| RequestURL | request | Full request URL |
| RequestMethod | requestMethod | HTTP method |
| ApplicationProtocol | app | Application protocol |
| Protocol | proto | Network protocol |
| DeviceAction | act | Action taken (allow/block/drop) |
| DeviceEventOutcome | outcome | Result of action |
| Message | msg | Human-readable message |
| FileName | fname | File name |
| FileSize | fsize | File size |
| FileCreateTime | fileCreateTime | File creation time |
| FileModificationTime | fileModificationTime | File mod time |
| FileHash | fileHash | File hash |
| ProcessName | sproc | Source process |
| DestinationProcessName | dproc | Destination process |
| DeviceCustomString1-6 | cs1-cs6 | Custom string fields |
| DeviceCustomString1Label-6Label | cs1Label-cs6Label | Labels for custom strings |
| DeviceCustomNumber1-3 | cn1-cn3 | Custom number fields |
| DeviceCustomNumber1Label-3Label | cn1Label-cn3Label | Labels for custom numbers |
| DeviceCustomDate1-2 | deviceCustomDate1-2 | Custom date fields |
| AdditionalExtensions | additional CEF extensions | Any unmapped CEF fields |

---

## SigninLogs — Azure AD Interactive Sign-ins

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| UserDisplayName | Full name |
| UserPrincipalName | UPN (email format) |
| UserId | AAD Object ID |
| AppDisplayName | Application name |
| AppId | Application ID |
| ClientAppUsed | Browser/client app |
| IPAddress | Sign-in IP |
| Location | City/Country |
| LocationDetails | dynamic: city, state, countryOrRegion |
| DeviceDetail | dynamic: deviceId, displayName, operatingSystem |
| Status | dynamic: errorCode, failureReason |
| ResultType | 0=success, other=error code |
| ResultDescription | Human-readable result |
| RiskDetail | Risk reason |
| RiskLevelAggregated | none/low/medium/high |
| RiskLevelDuringSignIn | none/low/medium/high |
| RiskState | none/confirmedSafe/remediated/dismissed/atRisk/confirmedCompromised |
| ConditionalAccessStatus | success/failure/notApplied/unknownFutureValue |
| AuthenticationRequirement | singleFactorAuthentication/multiFactorAuthentication |
| MfaDetail | dynamic: authMethod, authDetail |
| CorrelationId | Request correlation ID |
| TenantId | AAD tenant |
| NetworkLocationDetails | dynamic: networkNames, networkType |

---

## AuditLogs — Azure AD Audit

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| OperationName | Operation performed |
| Result | success/failure |
| ResultDescription | Details |
| Category | UserManagement/GroupManagement/ApplicationManagement/etc. |
| InitiatedBy | dynamic: user, app |
| TargetResources | dynamic array: targets of the operation |
| LoggedByService | AAD service that logged |

---

## AzureActivity — Azure Resource Manager logs

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| Caller | UPN or SPN who called |
| CallerIpAddress | Source IP |
| OperationName | ARM operation |
| OperationNameValue | Normalized operation |
| ResourceGroup | Resource group |
| ResourceProviderValue | e.g., "MICROSOFT.COMPUTE" |
| Resource | Resource name |
| ResourceId | Full ARM resource ID |
| ActivityStatusValue | Succeeded/Failed/Accepted/Started |
| Level | Critical/Error/Warning/Informational/Verbose |
| Properties | dynamic: detailed properties |
| Authorization | dynamic: action, scope, role |
| HTTPRequest | dynamic: clientRequestId, method, URI |
| SubscriptionId | Azure subscription |
| TenantId | AAD tenant |

---

## OfficeActivity — Microsoft 365

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| Operation | Action performed |
| Workload | Exchange/SharePoint/Teams/OneDrive/etc. |
| UserId | UPN |
| ClientIP | Source IP |
| RecordType | Numeric record type |
| OrganizationId | Tenant ID |
| OfficeObjectId | Object ID |
| OfficeWorkload | Service |
| ResultStatus | Succeeded/Failed |
| UserAgent | Client user agent |

---

## Defender for Endpoint (DeviceXxx tables)

### DeviceProcessEvents

| Field | Description |
|---|---|
| TimeGenerated / Timestamp | Event time |
| DeviceName | Machine name |
| DeviceId | MDE device ID |
| AccountName | Running user |
| AccountDomain | User domain |
| AccountSid | User SID |
| ProcessId | PID |
| ProcessCommandLine | Full command line |
| FileName | Process executable |
| FolderPath | Full path |
| SHA256 | Process hash |
| SHA1 | SHA1 hash |
| MD5 | MD5 hash |
| ParentProcessId | Parent PID |
| ParentProcessName | Parent name |
| ParentProcessCommandLine | Parent command line |
| InitiatingProcessAccountName | Account that started parent |
| LogonId | Logon session |

### DeviceNetworkEvents

| Field | Description |
|---|---|
| DeviceName | Machine name |
| ActionType | ConnectionSuccess/ConnectionFailed/etc. |
| LocalIP | Source IP |
| LocalPort | Source port |
| RemoteIP | Destination IP |
| RemotePort | Destination port |
| RemoteUrl | URL (if applicable) |
| Protocol | TCP/UDP |
| InitiatingProcessFileName | Process that made connection |
| InitiatingProcessCommandLine | Full command line |

### DeviceFileEvents

| Field | Description |
|---|---|
| DeviceName | Machine name |
| ActionType | FileCreated/FileModified/FileDeleted/FileRenamed |
| FileName | File name |
| FolderPath | Full path |
| SHA256 | File hash |
| FileSize | File size |
| InitiatingProcessFileName | Process that modified file |

### DeviceLogonEvents

| Field | Description |
|---|---|
| DeviceName | Machine name |
| ActionType | LogonSuccess/LogonFailed |
| AccountName | Account |
| AccountDomain | Domain |
| LogonType | Interactive/Network/RemoteInteractive/etc. |
| RemoteIP | Source IP for network logons |
| RemoteDeviceName | Remote machine |
| IsLocalAdmin | bool |

---

## ThreatIntelligenceIndicator

| Field | Description |
|---|---|
| TimeGenerated | Ingest time |
| Active | bool — is indicator still active |
| ExpirationDateTime | When indicator expires |
| IndicatorId | Unique ID |
| NetworkIP | IP indicator |
| NetworkDestinationIP | Destination IP |
| NetworkSourceIP | Source IP |
| Url | URL indicator |
| FileHashType | MD5/SHA1/SHA256 |
| FileHashValue | Hash value |
| DomainName | Domain indicator |
| EmailSenderAddress | Email indicator |
| ThreatType | Malware/C2/Phishing/etc. |
| Confidence | 0-100 |
| TlpLevel | white/green/amber/red |
| Tags | array of strings |
| Description | Indicator description |

---

## ASIM Normalized Tables (Schema-agnostic)

| Table | Use case |
|---|---|
| `NetworkSessionEvents` | Network flows, normalized from multiple connectors |
| `IMDnsEvents` | DNS queries, normalized |
| `IMFileEvents` | File events, normalized |
| `IMProcessEvents` | Process events, normalized |
| `IMNetworkSessionEvents` | Network sessions (legacy name) |
| `IMUserManagementEvents` | User management, normalized |
