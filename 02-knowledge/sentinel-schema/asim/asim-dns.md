# ASIM DNS Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimDns.yaml` (v0.1.7)

Sentinel tables: `imDns`, `ASimDnsActivity`

Normalizes DNS query and response events from any DNS server or security tool.

---

## Schema-Specific Fields

### Event identification
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | DNS op code (e.g., `Query`, `Update`) |
| EventSubType | string | Mandatory | `request` or `response` (most sources only log responses) |
| EventResultDetails | string | Mandatory | DNS response code (e.g., `NOERROR`, `NXDOMAIN`, `SERVFAIL`) |
| EventSchema | string | Mandatory | `Dns` |

### DNS Query fields
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| DnsQuery | string | Mandatory | The domain being resolved |
| DnsQueryType | integer | Optional | DNS Resource Record Type code (e.g., 1=A, 28=AAAA, 16=TXT) |
| DnsQueryTypeName | string | Recommended | DNS RR Type name (e.g., `A`, `AAAA`, `MX`, `TXT`, `CNAME`) |
| DnsQueryClass | integer | Optional | DNS class ID (1 = IN = Internet) |
| DnsQueryClassName | string | Optional | DNS class name (typically `IN`) |

### DNS Response fields
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| DnsResponseName | string | Optional | Content of DNS response record |
| DnsResponseCode | integer | Optional | Numeric DNS response code |
| DnsResponseIpCountry | string | Optional | Country of response IP |
| DnsResponseIpRegion | string | Optional | Region/state of response IP |
| DnsResponseIpCity | string | Optional | City of response IP |
| DnsResponseIpLatitude | float | Optional | Latitude of response IP |
| DnsResponseIpLongitude | float | Optional | Longitude of response IP |

### Network/transport fields
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| NetworkProtocol | string | Optional | `TCP` or `UDP` (typically UDP) |
| NetworkProtocolVersion | string | Optional | IP version |
| DnsNetworkDuration | integer | Optional | Request completion time in milliseconds |
| TransactionIdHex | string | Recommended | DNS query unique ID in hexadecimal |
| DnsSessionId | string | Optional | DNS session identifier |

### DNS Flags
| Field | Type | Class | Description |
|---|---|---|---|
| DnsFlags | string | Optional | Raw flags as reported by device |
| DnsFlagsAuthenticated | bool | Optional | DNSSEC AD flag — verified data |
| DnsFlagsAuthoritative | bool | Optional | AA flag — authoritative response |
| DnsFlagsCheckingDisabled | bool | Optional | DNSSEC CD flag |
| DnsFlagsRecursionAvailable | bool | Optional | RA flag — server supports recursion |
| DnsFlagsRecursionDesired | bool | Optional | RD flag — client requested recursion |
| DnsFlagsTruncated | bool | Optional | TC flag — response exceeded max size |
| DnsFlagsZ | bool | Optional | Deprecated DNS Z flag |

### Categorization
| Field | Type | Class | Description |
|---|---|---|---|
| UrlCategory | string | Optional | Category of the requested domain (e.g., `Malware`, `Gambling`) |

### Threat fields
| Field | Type | Class | Values |
|---|---|---|---|
| ThreatField | string | Conditional | `SrcIpAddr`, `DstIpAddr`, `Domain`, `DnsResponseName` |
| ThreatIpAddr | string | Optional | IP address where threat was identified |

## Included Entities

- **Dvc** — DNS server device
- **Src User** — user that generated the request (SrcUsername, SrcUserId)
- **Src Process** — process that generated the request (SrcProcessName, SrcProcessId)
- **Src System** — source system (SrcIpAddr, SrcHostname, SrcDomain)
- **Dst System** — destination DNS server (DstIpAddr, DstHostname)

## Aliases

| Alias | Maps To |
|---|---|
| User | SrcUsername |
| Process | SrcProcessName |
| IpAddr | SrcIpAddr |
| Hostname | SrcHostname |
| Domain | DnsQuery |
| DnsResponseCodeName | EventResultDetails |
| Duration | DnsNetworkDuration |
| SessionId | DnsSessionId |
| DomainCategory | UrlCategory |

## Common KQL usage

```kql
// ASIM DNS - detect NXDOMAIN spike (possible DGA)
imDns
| where TimeGenerated >= ago(1h)
| where EventResultDetails == "NXDOMAIN"
| summarize NxCount = count(), Queries = make_set(DnsQuery) by SrcIpAddr
| where NxCount > 50
| project TimeGenerated = now(), SrcIpAddr, NxCount, Queries
```
