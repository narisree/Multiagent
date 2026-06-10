# ASIM Registry Event Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimRegistryEvent.yaml` (v0.1.0, 2023-09-12)

Sentinel tables: `imRegistryEvent`, `ASimRegistryEvent`

Normalizes Windows registry key and value operations.

---

## Schema-Specific Fields

### Event classification
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | `RegistryKeyCreated`, `RegistryKeyDeleted`, `RegistryKeyRenamed`, `RegistryValueDeleted`, `RegistryValueSet` |
| EventSchema | string | Mandatory | `RegistryEvent` |

### Registry key/value fields
| Field | Type | Class | Description |
|---|---|---|---|
| RegistryKey | string | Mandatory | Registry key, normalized to standard root key naming (e.g., `HKEY_LOCAL_MACHINE\...`) |
| RegistryValue | string | Recommended | Registry value name (analogous to a filename) |
| RegistryValueType | string | Recommended | Value type normalized to standard form (e.g., `Reg_Dword`, `Reg_Sz`) |
| RegistryValueData | string | Recommended | Data stored in the registry value |

### Previous state (for modifications)
| Field | Type | Class | Description |
|---|---|---|---|
| RegistryPreviousKey | string | Recommended | Original registry key before modification |
| RegistryPreviousValue | string | Recommended | Original value name before modification |
| RegistryPreviousValueType | string | Recommended | Original value type before modification |
| RegistryPreviousValueData | string | Recommended | Original data before modification |

## Included Entities
- **Dvc** — device where registry event occurred
- **Actor** — user performing the operation (ActorUsername, ActorUserId)
- **Acting Process** — process performing the operation (ActingProcessName, ActingProcessId, ActingProcessCommandLine)
- **Parent Process** — parent of acting process

## Aliases
| Alias | Maps To |
|---|---|
| User | ActorUsername |
| Process | ActingProcessName |

## Common KQL usage
```kql
// ASIM registry events - detect persistence via Run key
imRegistryEvent
| where TimeGenerated >= ago(1h)
| where EventType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    "\\Run\\", "\\RunOnce\\",
    "\\Services\\", "\\AppInit_DLLs",
    "\\Image File Execution Options\\")
| project TimeGenerated, DvcHostname, ActorUsername,
    RegistryKey, RegistryValue, RegistryValueData, ActingProcessName
```
