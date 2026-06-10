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

For full field schemas see `02-knowledge/sentinel-schema/asim/`.

| Table | ASIM Schema | Use case |
|---|---|---|
| `imAuthentication` / `ASimAuthenticationEvent` | Authentication | Logon/logoff events, normalized across all sources |
| `imDns` / `ASimDnsActivity` | Dns | DNS queries and responses |
| `imFileEvent` / `ASimFileEvent` | FileEvent | File operations (create, modify, delete, rename) |
| `imProcessCreate` / `imProcessTerminate` / `ASimProcessEvent` | ProcessEvent | Process creation and termination |
| `imRegistryEvent` / `ASimRegistryEvent` | RegistryEvent | Windows registry key/value operations |
| `imUserManagement` / `ASimUserManagementActivity` | UserManagement | User and group lifecycle events |
| `imAuditEvent` / `ASimAuditEventActivity` | AuditEvent | Configuration and administrative changes |
| `imDhcpEvent` / `ASimDhcpEvent` | DHCPEvent | DHCP lease events |
| `imNotification` / `ASimNotification` | Notification | Security alerts and notifications |
| `imNetworkSession` / `ASimNetworkSessionLogs` | NetworkSession | Network flows (replaces NetworkSessionEvents) |

---

## Azure AD Additional Sign-in Tables

### AADNonInteractiveUserSignInLogs
Non-interactive sign-ins (service access on behalf of user, token refresh).

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| UserDisplayName | Full name |
| UserPrincipalName | UPN |
| UserId | AAD Object ID |
| AppDisplayName | App that was accessed |
| AppId | App ID |
| ResourceDisplayName | Resource accessed |
| ResourceId | Resource ID |
| IPAddress | Source IP |
| Location | Location |
| ResultType | 0=success, other=error code |
| ResultDescription | Human-readable result |
| CorrelationId | Request correlation ID |
| ConditionalAccessStatus | success/failure/notApplied |
| AuthenticationRequirement | singleFactorAuthentication/multiFactorAuthentication |

### AADServicePrincipalSignInLogs
Service principal (app) sign-in events.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| ServicePrincipalName | SPN display name |
| ServicePrincipalId | SPN Object ID |
| AppId | Application ID |
| ResourceDisplayName | Resource accessed |
| ResourceId | Resource ID |
| IPAddress | Source IP |
| Location | Location |
| ResultType | 0=success, other=error code |
| ResultDescription | Human-readable result |
| CorrelationId | Request correlation ID |

### AADManagedIdentitySignInLogs
Managed identity sign-in events.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| ManagedIdentityName | MI display name |
| ManagedIdentityId | MI Object ID |
| ResourceDisplayName | Resource accessed |
| ResourceId | Resource ID |
| IPAddress | Source IP |
| ResultType | 0=success, other=error code |
| CorrelationId | Correlation ID |

---

## Microsoft Graph Activity

### MicrosoftGraphActivityLogs
Graph API calls (directory operations, app registrations, etc.).

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| UserId | Calling user or SPN |
| AppId | Application making the call |
| RequestId | Unique request ID |
| RequestMethod | GET/POST/PATCH/DELETE |
| RequestUri | Full URI of Graph API call |
| ResponseStatusCode | HTTP status code |
| Roles | Roles used in the request |
| Scopes | OAuth scopes |
| ServicePrincipalId | SPN if app-only |
| IPAddress | Source IP |

---

## Defender for Endpoint — Additional Tables

### DeviceEvents
Catch-all for MDE events not covered by more specific tables (network share access, clipboard events, WMI events, etc.).

| Field | Description |
|---|---|
| TimeGenerated / Timestamp | Event time |
| DeviceName | Machine name |
| DeviceId | MDE device ID |
| ActionType | Event type (e.g., AsrLowIntegritySigBlockedAudited, PowerShellCommand, etc.) |
| FileName | File associated with event |
| FolderPath | Full path |
| SHA256 | File hash |
| ProcessCommandLine | Command line |
| InitiatingProcessFileName | Process that triggered event |
| InitiatingProcessCommandLine | Initiating process command line |
| AccountName | User |
| AccountDomain | Domain |
| RemoteIP | Remote IP (for network events) |
| RemoteUrl | Remote URL |
| AdditionalFields | JSON with event-specific data |

### DeviceRegistryEvents
Windows registry operations from MDE.

| Field | Description |
|---|---|
| DeviceName | Machine name |
| ActionType | RegistryValueSet/RegistryKeyCreated/RegistryKeyDeleted/RegistryValueDeleted |
| RegistryKey | Full registry key path |
| RegistryValueName | Value name |
| RegistryValueData | Value data |
| RegistryValueType | REG_SZ/REG_DWORD/etc. |
| PreviousRegistryKey | Previous key (for renames) |
| PreviousRegistryValueName | Previous value name |
| PreviousRegistryValueData | Previous value data |
| InitiatingProcessFileName | Process performing registry change |
| InitiatingProcessCommandLine | Process command line |
| AccountName | User |

### DeviceImageLoadEvents
DLL and driver loading events from MDE.

| Field | Description |
|---|---|
| DeviceName | Machine name |
| ActionType | ImageLoaded |
| FileName | DLL/driver filename |
| FolderPath | Full path |
| SHA256 | Hash |
| IsSigned | bool — image is signed |
| Signer | Certificate signer |
| SignerHash | Signing certificate hash |
| IsValidCertificate | bool — certificate valid |
| InitiatingProcessFileName | Process loading the image |
| InitiatingProcessCommandLine | Process command line |
| AccountName | User |

### DeviceNetworkInfo
Network adapter state snapshots from MDE.

| Field | Description |
|---|---|
| DeviceName | Machine name |
| Timestamp | Snapshot time |
| NetworkAdapterName | Adapter name |
| MacAddress | MAC address |
| NetworkAdapterType | Ethernet/WiFi/etc. |
| NetworkAdapterStatus | Up/Down |
| TunnelType | VPN tunnel type if applicable |
| IPAddresses | Dynamic array of IP objects (IPAddress, SubnetPrefix, AddressType) |
| DefaultGateways | Array of gateway IPs |
| DnsAddresses | Array of DNS server IPs |
| DhcpEnabled | bool |
| DhcpServer | DHCP server IP |

### DeviceInfo
Device inventory snapshots from MDE.

| Field | Description |
|---|---|
| DeviceName | Machine name |
| Timestamp | Snapshot time |
| DeviceId | MDE device ID |
| OSPlatform | Windows/macOS/Linux |
| OSVersion | OS version string |
| OSArchitecture | x64/x86/ARM |
| PublicIP | Public IP |
| IsAzureADJoined | bool |
| IsHybridAzureADJoined | bool |
| LoggedOnUsers | Array of logged-on user objects |
| MachineGroup | MDE device group |
| SensorHealthState | Active/InactiveGently/InactiveMisconfigured |
| OnboardingStatus | Onboarded/CanBeOnboarded/etc. |
| AadDeviceId | Azure AD device ID |

---

## Sentinel Metadata Tables

### SecurityAlert
Alerts generated by Sentinel analytics rules and connected security products.

| Field | Description |
|---|---|
| TimeGenerated | Alert creation time |
| AlertName | Alert rule name |
| AlertSeverity | High/Medium/Low/Informational |
| AlertType | Alert type identifier |
| CompromisedEntity | Primary affected entity |
| ProviderName | Source product/connector |
| ProductName | Generating product |
| Description | Alert description |
| Entities | JSON array of mapped entities |
| ExtendedLinks | Links to additional context |
| ExtendedProperties | Key-value pairs of additional data |
| Tactics | MITRE tactics array |
| Techniques | MITRE techniques array |
| Status | New/InProgress/Resolved |
| ProcessingEndTime | When alert was processed |
| RemediationSteps | Remediation recommendations |
| ConfidenceLevel | High/Medium/Low/Unknown |
| ConfidenceScore | 0-1 float |
| IsIncident | bool |
| IncidentLinkToWorkplace | Incident portal URL |
| VendorOriginalId | Source system alert ID |

### SecurityIncident
Sentinel incidents (grouped alerts).

| Field | Description |
|---|---|
| TimeGenerated | Incident creation time |
| IncidentName | Unique incident identifier |
| Title | Incident title |
| Description | Incident description |
| Severity | High/Medium/Low/Informational |
| Status | New/Active/Closed |
| Owner | Assigned analyst (JSON) |
| Classification | BenignPositive/FalsePositive/TruePositive/Undetermined |
| ClassificationComment | Analyst comment |
| ClassificationReason | Specific reason |
| CreatedTime | When incident was created |
| FirstActivityTime | Earliest activity time |
| LastActivityTime | Latest activity time |
| LastModifiedTime | Last update time |
| ClosedTime | When closed |
| AlertIds | Array of associated alert IDs |
| Labels | Array of label objects |
| ProviderIncidentId | External system ID |
| IncidentNumber | Numeric incident ID |
| RelatedAnalyticRuleIds | Analytics rules that fired |

---

## UEBA Tables

### BehaviorAnalytics
UEBA analysis results — anomaly scores and entity enrichment.

| Field | Description |
|---|---|
| TimeGenerated | Analysis time |
| UsersInsights | Dynamic — user risk insights |
| DevicesInsights | Dynamic — device risk insights |
| ActivityType | Type of activity analyzed |
| InvestigationPriority | Investigation priority score |
| SourceRecordId | Original event record ID |
| UserName | Username |
| UserPrincipalName | UPN |
| UserId | AAD Object ID |
| DeviceName | Device name |
| SourceIPAddress | Source IP |
| SourceIPLocation | IP geolocation |
| SourceDevice | Source device |
| ActivityInsights | Dynamic — insights about the activity |
| ActionType | Action being analyzed |

### IdentityInfo
Entity identity data from UEBA (updated periodically).

| Field | Description |
|---|---|
| AccountUPN | User Principal Name |
| AccountName | Username |
| AccountDomain | Domain |
| AccountObjectId | AAD Object ID |
| AccountSID | User SID |
| AccountDisplayName | Full name |
| AccountNTName | DOMAIN\user format |
| EmailAddress | Email |
| GivenName | First name |
| Surname | Last name |
| Department | Department |
| JobTitle | Job title |
| Manager | Manager UPN |
| IsAccountEnabled | bool |
| Tags | Array of risk tags |
| ThreatIntelligence | Array of TI matches |
| AssignedRoles | Azure AD roles assigned |
| GroupMembership | Group memberships |
| RiskLevel | none/low/medium/high |
| RiskState | none/atRisk/confirmedCompromised/confirmedSafe/etc. |
| BlastRadius | Impact radius score |

### UserAccessAnalytics
Peer group and access baseline data from UEBA.

| Field | Description |
|---|---|
| TimeGenerated | Analysis time |
| UserName | Username |
| UserPrincipalName | UPN |
| SourceIPAddress | Source IP |
| SourceIPLocation | IP location |
| AccessedResource | Resource accessed |
| AccessedApp | Application accessed |
| ActivityType | Activity type |
| InvestigationPriority | Score |

### UserPeerAnalytics
Peer group comparisons from UEBA.

| Field | Description |
|---|---|
| TimeGenerated | Analysis time |
| UserName | Username |
| UserPrincipalName | UPN |
| PeerGroupName | Peer group identifier |
| PeerGroupUserCount | Number of peers |
| SourceIPAddress | Source IP |
| ActivityType | Activity being compared |
| InvestigationPriority | Score |

---

## Azure Platform Tables

### AzureDiagnostics
Catch-all for Azure resource diagnostic logs. Filter by ResourceType.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| ResourceType | Azure resource type (e.g., VAULTS, NETWORKSECURITYGROUPS) |
| Resource | Resource name |
| ResourceGroup | Resource group |
| SubscriptionId | Azure subscription |
| OperationName | Operation performed |
| ResultType | Success/Failed/etc. |
| ResultSignature | HTTP status or sub-result |
| ResultDescription | Details |
| Category | Log category |
| CallerIpAddress | Source IP |
| Level | Critical/Error/Warning/Informational |
| Properties | Dynamic JSON — resource-specific data |

**Key ResourceType values for security:**
- `VAULTS` — Key Vault access
- `NETWORKSECURITYGROUPS` — NSG flow logs
- `APPLICATIONGATEWAYS` — App Gateway
- `VIRTUALNETWORKS` — VNet logs

```kql
// Key Vault access
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet" or OperationName == "KeyGet"
| project TimeGenerated, Resource, CallerIpAddress, OperationName, ResultType, identity_claim_upn_s
```

### AzureFirewallApplicationRule
Azure Firewall application rule logs.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| SourceIP | Source IP address |
| SourcePort | Source port |
| TargetUrl | Target URL |
| Fqdn | Destination FQDN |
| Protocol | HTTP/HTTPS/etc. |
| Action | Allow/Deny |
| PolicyName | Firewall policy name |
| RuleName | Matched rule name |
| RuleCollectionGroup | Rule collection group |
| RuleCollection | Rule collection name |
| TranslatedIp | NAT translated IP |
| TranslatedPort | NAT translated port |

### AzureFirewallNetworkRule
Azure Firewall network rule logs.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| SourceIP | Source IP |
| SourcePort | Source port |
| DestinationIP | Destination IP |
| DestinationPort | Destination port |
| Protocol | TCP/UDP/ICMP |
| Action | Allow/Deny |
| PolicyName | Firewall policy |
| RuleName | Matched rule |
| RuleCollection | Rule collection |

### StorageBlobLogs
Azure Storage blob access logs.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| CallerIpAddress | Source IP |
| AuthenticationType | Anonymous/SAS/AccountKey/OAuth |
| Category | StorageRead/StorageWrite/StorageDelete |
| OperationName | GetBlob/PutBlob/DeleteBlob/etc. |
| ResourceId | Storage account resource ID |
| AccountName | Storage account name |
| DurationMs | Operation duration |
| ResponseBodySize | Bytes returned |
| RequestBodySize | Bytes uploaded |
| StatusCode | HTTP status |
| StatusText | HTTP status text |
| Uri | Full request URI |
| UserAgentHeader | Client user agent |
| ObjectKey | Blob path |

---

## Network and DNS Tables

### DnsEvents (Legacy DNS connector)
DNS events from Windows DNS server or DNS connectors.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| Computer | DNS server |
| ClientIP | Client that made the query |
| Name | Domain queried |
| QueryType | Record type (A, AAAA, MX, etc.) |
| IPAddresses | IP addresses returned |
| SubType | Response/Query |
| ResultCode | DNS result code |
| QueryTypeName | Record type name |
| ReplyCode | Numeric reply code |
| ReplyCodeName | NOERROR/NXDOMAIN/SERVFAIL/etc. |
| EventId | Windows DNS event ID |

### W3CIISLog
IIS web server logs via W3C Extended Log Format.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| sIp | Server IP |
| csMethod | HTTP method (GET/POST/etc.) |
| csUriStem | URL path |
| csUriQuery | Query string |
| sPort | Server port |
| csUsername | Authenticated username |
| cIp | Client IP |
| csUserAgent | User agent |
| csReferer | Referring URL |
| scStatus | HTTP status code |
| scSubStatus | IIS sub-status |
| scWin32Status | Win32 status |
| scBytes | Bytes sent |
| csBytes | Bytes received |
| TimeTaken | Request duration in milliseconds |
| sComputerName | IIS server name |
| sSiteName | IIS site name |

---

## Infrastructure Tables

### Heartbeat
Log Analytics agent heartbeat — confirms agent connectivity.

| Field | Description |
|---|---|
| TimeGenerated | Heartbeat timestamp |
| Computer | Agent hostname |
| ComputerIP | Agent IP |
| OSType | Windows/Linux |
| OSName | OS name |
| OSMajorVersion | Major version |
| OSMinorVersion | Minor version |
| Version | Agent version |
| Solutions | Solutions collecting from this agent |
| Category | Direct/SDKWorkspace/etc. |
| ManagementGroupName | SCOM management group |
| RemoteIPCountry | Country of IP |
| RemoteIPLongitude | IP longitude |
| RemoteIPLatitude | IP latitude |

### Update
Windows Update history from Update Management.

| Field | Description |
|---|---|
| TimeGenerated | Assessment time |
| Computer | Machine name |
| Product | Update product name |
| Classification | Security Updates/Critical Updates/etc. |
| UpdateState | Needed/NotNeeded/Installed/Failed |
| KBID | Knowledge Base article ID |
| PublishedDate | Update release date |
| Title | Update title |
| RebootBehavior | CanRequestReboot/NeverReboots/etc. |
| MSRCSeverity | Critical/Important/Moderate/Low |
| MandatoryReboot | bool |

### LinuxAuditLog
Linux auditd logs via OMS agent.

| Field | Description |
|---|---|
| TimeGenerated | Timestamp |
| Computer | Linux host |
| AuditID | Audit event ID |
| ExecutablePath | Executable path |
| AuditdMessage | Full auditd message |
| Type | Audit record type (SYSCALL/EXECVE/PATH/etc.) |
| node | Audit node name |
| ProcessId | PID |
| ParentProcessId | Parent PID |
| AccountName | User |
| UserID | UID |
| GroupID | GID |
| CommandLine | Command executed |
| AUID | Audit UID |
| SUID | Set UID |
| SGID | Set GID |
| Key | Audit rule key |
| Syscall | System call number |
| Success | yes/no |
