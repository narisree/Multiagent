# ASIM Audit Event Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimAuditEvent.yaml` (v0.1.0, 2022-12-14)

Sentinel tables: `imAuditEvent`, `ASimAuditEventActivity`

Normalizes configuration changes, policy changes, and administrative actions.

---

## Schema-Specific Fields

| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | `Set`, `Read`, `Create`, `Delete`, `Execute`, `Install`, `Clear`, `Enable`, `Disable`, `Other` |
| EventSchema | string | Mandatory | `AuditEvent` |
| Operation | string | Mandatory | The specific operation as reported by the source device |
| Object | string | Recommended | Name of the object on which the operation was performed |
| ObjectId | string | Recommended | ID of the object on which the operation was performed |
| ObjectType | string | Related | `Configuration Atom`, `Policy Rule`, `Cloud Resource`, `Other` |
| OriginalObjectType | string | Optional | Object type as reported by source before normalization |
| OldValue | string | Optional | Value before the operation |
| NewValue | string | Recommended | Value after the operation |
| ValueType | string | Optional | `Other` |
| ThreatField | string | Conditional | `SrcIpAddr`, `DstIpAddr` |
| ThreatIpAddr | string | Optional | IP address with associated threat |

## Included Entities

- **Dvc** — device where audit event was generated
- **Actor** — user who performed the action (ActorUsername, ActorUserId, ActorUserType)
- **Acting Application** — application used (ActingAppName, ActingAppId, ActingAppType)
- **Source System** — originating system (SrcIpAddr, SrcHostname)
- **Target Application** — application being audited (TargetAppName, TargetAppId)

## Aliases

| Alias | Maps To |
|---|---|
| User | ActorUsername |
| Application | TargetAppName |
| Process | ActingProcessName |
| IpAddr | SrcIpAddr |
| Value | NewValue |

## Common KQL usage

```kql
// ASIM audit events - detect privileged role assignments
imAuditEvent
| where TimeGenerated >= ago(1h)
| where EventType == "Set" or EventType == "Create"
| where ObjectType == "Policy Rule"
| where Object has_any ("admin", "owner", "contributor", "global")
| project TimeGenerated, ActorUsername, Operation, Object, NewValue, DvcHostname
```
