# ASIM DHCP Event Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimDHCPEvent.yaml` (v0.1.0, 2023-09-12)

Sentinel tables: `imDhcpEvent`, `ASimDhcpEvent`

Normalizes DHCP lease assignment, renewal, and release events.

---

## Schema-Specific Fields

| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | `Assign`, `Renew`, `Release`, `DNS Update` |
| EventSchema | string | Mandatory | `Dhcp` |
| RequestedIpAddr | string | Optional | IP address requested by the DHCP client |
| DhcpLeaseDuration | integer | Optional | Lease duration in seconds |
| DhcpSessionId | string | Optional | Session identifier from reporting device |
| DhcpSessionDuration | integer | Optional | DHCP session completion time in milliseconds |
| DhcpSrcDHCId | string | Optional | DHCP client ID per RFC4701 |
| DhcpCircuitId | string | Recommended | DHCP circuit ID per RFC3046 |
| DhcpSubscriberId | string | Optional | DHCP subscriber ID per RFC3993 |
| DhcpVendorClassId | string | Optional | DHCP Vendor Class ID per RFC3925 |
| DhcpVendorClass | string | Optional | DHCP Vendor Class per RFC3925 |
| DhcpUserClassId | string | Optional | DHCP User Class ID per RFC3004 |
| DhcpUserClass | string | Optional | DHCP User Class per RFC3004 |

## Included Entities
- **Dvc** — DHCP server
- **Src User** — client user if known (SrcUsername, SrcUserId)
- **Src System** — DHCP client (SrcIpAddr, SrcHostname, SrcMacAddr)

## Aliases
| Alias | Maps To |
|---|---|
| User | SrcUsername |
| IpAddr | SrcIpAddr |
| Hostname | SrcHostname |
| SessionId | DhcpSessionId |
| Duration | DhcpSessionDuration |

## Common KQL usage
```kql
// ASIM DHCP - detect IP address assigned to new/unknown MAC
imDhcpEvent
| where TimeGenerated >= ago(1h)
| where EventType == "Assign"
| project TimeGenerated, SrcMacAddr, SrcIpAddr, SrcHostname, DhcpLeaseDuration
```
