# Sentinel Schema Knowledge Index

| File | Contents |
|---|---|
| `analytics-rule-schema.md` | Full ARM template schema, required/optional fields, incident grouping options |
| `tables-reference.md` | ~50 native Sentinel tables with key fields (Security, AAD, MDE, UEBA, Azure, Network, Infra) |
| `entity-mappings.md` | All entity types, valid identifiers, and per-table mapping patterns |
| `mitre-tactics.md` | Valid tactic strings, common techniques, and legacy SIEM category → tactic mapping |

## ASIM — Advanced Security Information Model

Source-agnostic normalized schemas from the Azure/Azure-Sentinel repo (`ASIM/schemas/`). Use ASIM parsers in new detections instead of native tables wherever possible.

| File | Schema | Tables |
|---|---|---|
| `asim/_index.md` | Index + key concepts | — |
| `asim/common-event-fields.md` | Common fields inherited by all schemas | all ASIM tables |
| `asim/asim-authentication.md` | Authentication | `imAuthentication`, `ASimAuthenticationEvent` |
| `asim/asim-audit-event.md` | AuditEvent | `imAuditEvent`, `ASimAuditEventActivity` |
| `asim/asim-dhcp-event.md` | DHCPEvent | `imDhcpEvent`, `ASimDhcpEvent` |
| `asim/asim-dns.md` | Dns | `imDns`, `ASimDnsActivity` |
| `asim/asim-file-event.md` | FileEvent | `imFileEvent`, `ASimFileEvent` |
| `asim/asim-notification.md` | Notification | `imNotification`, `ASimNotification` |
| `asim/asim-process-event.md` | ProcessEvent | `imProcessCreate`, `ASimProcessEvent` |
| `asim/asim-registry-event.md` | RegistryEvent | `imRegistryEvent`, `ASimRegistryEvent` |
| `asim/asim-user-management.md` | UserManagement | `imUserManagement`, `ASimUserManagementActivity` |
