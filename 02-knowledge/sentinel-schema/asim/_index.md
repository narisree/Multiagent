# ASIM Schema Index

Source: Azure/Azure-Sentinel `ASIM/schemas/` — formal YAML schema definitions

ASIM (Advanced Security Information Model) normalizes security events from any source into a common schema, enabling source-agnostic detection rules.

---

## Schema Files

| File | Schema | Sentinel Table(s) | Event Types |
|---|---|---|---|
| `common-event-fields.md` | Common fields + enumerations | All ASIM tables | Inherited by every schema |
| `asim-authentication.md` | Authentication | `imAuthentication`, `ASimAuthenticationEvent` | Logon, Logoff, Elevate |
| `asim-audit-event.md` | AuditEvent | `imAuditEvent`, `ASimAuditEventActivity` | Set, Read, Create, Delete, Execute, Install, Clear, Enable, Disable |
| `asim-dhcp-event.md` | DHCPEvent | `imDhcpEvent`, `ASimDhcpEvent` | Assign, Renew, Release, DNS Update |
| `asim-dns.md` | Dns | `imDns`, `ASimDnsActivity` | DNS queries and responses |
| `asim-file-event.md` | FileEvent | `imFileEvent`, `ASimFileEvent` | FileCreated, FileModified, FileDeleted, FileRenamed, FileCopied, FileMoved |
| `asim-notification.md` | Notification | `imNotification`, `ASimNotification` | Alert, Other |
| `asim-process-event.md` | ProcessEvent | `imProcessCreate`, `imProcessTerminate`, `ASimProcessEvent` | ProcessCreated, ProcessTerminated |
| `asim-registry-event.md` | RegistryEvent | `imRegistryEvent`, `ASimRegistryEvent` | RegistryKeyCreated, RegistryKeyDeleted, RegistryValueSet, etc. |
| `asim-user-management.md` | UserManagement | `imUserManagement`, `ASimUserManagementActivity` | UserCreated, UserDeleted, GroupModified, UserAddedToGroup, etc. |

---

## ASIM Key Concepts

### Parser naming convention
- `im<Schema>` — unifying parser (queries all sources)
- `vim<Schema><Source>` — source-specific parser (e.g., `vimAuthenticationAAD`)
- `ASim<Schema>Event` — normalized table (when streaming normalization is used)

### Universal use in detection rules
```kql
// Use ASIM parsers instead of native tables for source-agnostic rules
imAuthentication   // instead of SecurityEvent | where EventID == 4624/4625
imDns              // instead of DnsEvents or Syslog with bind logs
imProcessCreate    // instead of DeviceProcessEvents or SecurityEvent EventID 4688
imFileEvent        // instead of DeviceFileEvents
```

### When to use ASIM vs native tables
- **Use ASIM parsers** when writing new detections — they work across all connected data sources
- **Use native tables** when source-specific fields are needed (e.g., Windows EventID, CEF cs1 custom fields)
- **In translations** — if source rule references normalized concepts (username, IP), prefer ASIM; if it references source-specific IDs, use native table

---

## Common Event Fields (all ASIM schemas)

All ASIM schemas inherit these fields — see `common-event-fields.md`:

| Field | Type | Class |
|---|---|---|
| TimeGenerated | datetime | Mandatory |
| EventResult | string | Mandatory — `Success`, `Failure`, `Partial`, `NA` |
| EventSeverity | string | Recommended — `Informational`, `Low`, `Medium`, `High` |
| EventType | string | Mandatory — schema-specific |
| EventProduct | string | Mandatory — generating product |
| EventVendor | string | Mandatory — generating vendor |
| AdditionalFields | dynamic | Recommended — unmapped fields |
