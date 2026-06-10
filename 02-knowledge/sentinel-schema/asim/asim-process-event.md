# ASIM Process Event Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimProcessEvent.yaml` (v0.1.5, 2023-03-06)

Sentinel tables: `imProcessCreate`, `imProcessTerminate`, `ASimProcessEvent`

Normalizes process creation and termination events from Windows, Linux, and endpoint agents.

---

## Schema-Specific Fields

| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | `ProcessCreated`, `ProcessTerminated` |
| EventSchema | string | Mandatory | `ProcessEvent` |

## Included Entities

### Target Process (the created/terminated process)
| Field | Type | Class | Description |
|---|---|---|---|
| TargetProcessName | string | Mandatory | Process executable name |
| TargetProcessCommandLine | string | Recommended | Full command line |
| TargetProcessId | string | Mandatory | Process ID |
| TargetProcessGuid | string | Optional | Process GUID (Sysmon) |
| TargetProcessFilePath | string | Optional | Full path of executable |
| TargetProcessFileDirectory | string | Optional | Directory of executable |
| TargetProcessMD5 | string | Optional | MD5 hash of executable |
| TargetProcessSHA1 | string | Optional | SHA1 hash |
| TargetProcessSHA256 | string | Optional | SHA256 hash |
| TargetProcessSHA512 | string | Optional | SHA512 hash |
| TargetProcessIMPHASH | string | Optional | Import hash (PE) |
| TargetProcessIntegrityLevel | string | Optional | `Low`, `Medium`, `High`, `System` |
| TargetProcessTokenElevation | string | Optional | `Default`, `Full`, `Limited`, `None` |
| TargetProcessSessionId | integer | Optional | Logon session ID |
| TargetProcessCreationTime | datetime | Optional | Process start time |

### Acting Process (the parent/spawning process)
| Field | Type | Class | Description |
|---|---|---|---|
| ActingProcessName | string | Recommended | Parent process name |
| ActingProcessCommandLine | string | Optional | Parent command line |
| ActingProcessId | string | Recommended | Parent PID |
| ActingProcessGuid | string | Optional | Parent process GUID |
| ActingProcessFilePath | string | Optional | Parent executable path |
| ActingProcessMD5 | string | Optional | Parent MD5 |
| ActingProcessSHA256 | string | Optional | Parent SHA256 |
| ActingProcessCreationTime | datetime | Optional | Parent process start time |

### Parent Process (grandparent)
| Field | Type | Class | Description |
|---|---|---|---|
| ParentProcessName | string | Optional | Grandparent process name |
| ParentProcessId | string | Optional | Grandparent PID |
| ParentProcessCreationTime | datetime | Optional | Grandparent start time |

### Actor (user running the process)
| Field | Type | Class | Description |
|---|---|---|---|
| ActorUsername | string | Mandatory | Username |
| ActorUsernameType | string | Conditional | `Windows`, `UPN`, `DN`, `Simple` |
| ActorUserId | string | Recommended | User SID or equivalent |
| ActorUserIdType | string | Conditional | `SID`, `UID`, `AADID`, etc. |
| ActorUserType | string | Optional | `Regular`, `Machine`, `Admin`, etc. |
| ActorSessionId | string | Optional | Logon session ID |

### Target User (for RunAs / impersonation)
| Field | Type | Class | Description |
|---|---|---|---|
| TargetUsername | string | Recommended | Impersonated user |
| TargetUserId | string | Recommended | Impersonated user ID |
| TargetUserSessionId | string | Optional | Target user session ID |

### Device
| Field | Type | Class | Description |
|---|---|---|---|
| DvcHostname | string | Recommended | Device hostname |
| DvcIpAddr | string | Recommended | Device IP |
| DvcId | string | Optional | Device ID (e.g., MDE device ID) |
| DvcOs | string | Optional | Device OS |

## Aliases

| Alias | Maps To |
|---|---|
| User | ActorUsername |
| Process | TargetProcessName |
| CommandLine | TargetProcessCommandLine |
| Hash | TargetProcessMD5, TargetProcessSHA1, TargetProcessSHA256, TargetProcessSHA512, TargetProcessIMPHASH |

## Common KQL usage

```kql
// ASIM process events - suspicious PowerShell execution
imProcessCreate
| where TimeGenerated >= ago(1h)
| where TargetProcessName has "powershell"
| where TargetProcessCommandLine matches regex @"(?i)-e[nc]+ [A-Za-z0-9+/]{20}"
| project TimeGenerated, DvcHostname, ActorUsername,
    TargetProcessCommandLine, ActingProcessName
```
