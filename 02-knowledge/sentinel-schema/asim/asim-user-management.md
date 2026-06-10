# ASIM User Management Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimUserManagement.yaml` (v0.1.1, 2023-09-12)

Sentinel tables: `imUserManagement`, `ASimUserManagementActivity`

Normalizes user and group lifecycle events (creation, deletion, modification, group membership).

---

## Schema-Specific Fields

| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | `UserCreated`, `UserDeleted`, `UserModified`, `UserLocked`, `UserUnlocked`, `UserDisabled`, `UserEnabled`, `PasswordChanged`, `PasswordReset`, `GroupCreated`, `GroupDeleted`, `GroupModified`, `UserAddedToGroup`, `UserRemovedFromGroup`, `GroupEnumerated`, `UserRead`, `GroupRead` |
| EventSchema | string | Mandatory | `UserManagement` |
| EventResultDetails | string | Recommended | `NotAuthorized`, `Other` |
| EventSubType | string | Optional | `Password`, `Hash` |
| PreviousPropertyValue | string | Optional | Previous value of the property modified |
| NewPropertyValue | string | Optional | New value of the property modified |

## Included Entities
- **Dvc** — device generating the event
- **Actor** — user performing the management action (ActorUsername, ActorUserId, ActorUserType)
- **Acting Application** — application used (ActingAppName, ActingAppType)
- **Source System** — originating system (SrcIpAddr, SrcHostname)
- **Target User** — user being managed (TargetUsername, TargetUserId, TargetUserType)
- **Target Group** — group being managed (TargetGroupName, TargetGroupId, TargetGroupType)

## Aliases
| Alias | Maps To |
|---|---|
| UpdatedPropertyName | EventSubType |
| Hostname | DvcHostname |

## Common KQL usage
```kql
// ASIM user management - new local admin account created
imUserManagement
| where TimeGenerated >= ago(1h)
| where EventType == "UserCreated" or EventType == "UserAddedToGroup"
| where TargetGroupName has_any ("Administrators", "Domain Admins", "Enterprise Admins")
| project TimeGenerated, DvcHostname, ActorUsername,
    EventType, TargetUsername, TargetGroupName
```
