# ASIM Common Event Fields

Source: Azure/Azure-Sentinel `ASIM/schemas/common/ASimEventFields.yaml`

These fields are inherited by ALL ASIM normalized schemas. Every ASIM table includes these fields.

---

## Common Event Fields

| Field | Type | Class | Values / Notes |
|---|---|---|---|
| TimeGenerated | datetime | Mandatory | Timestamp when record was generated |
| Type | string | Mandatory | Table name (populated by Log Analytics) |
| AdditionalFields | dynamic | Recommended | Supplementary event data not mapped to other fields |
| Src | string | Recommended | Unique identifier of source/acting device (may alias SrcHostname, SrcIpAddr, etc.) |
| Dst | string | Recommended | Unique identifier of target/destination device |
| EventMessage | string | Optional | General message or description from source |
| EventCount | int | Optional | Number of events in aggregated record (1 if not aggregated) |
| EventStartTime | datetime | Mandatory | Start time of event; use TimeGenerated if unavailable |
| EventEndTime | datetime | Mandatory | End time of event; use TimeGenerated if unavailable |
| EventType | string | Mandatory | Operation type — schema-specific enumeration |
| EventSubType | string | Optional | Subdivision of EventType — schema-specific enumeration |
| EventResult | string | Mandatory | `Success`, `Failure`, `Partial`, `NA` |
| EventResultDetails | string | Recommended | Reason for EventResult — schema-specific enumeration |
| EventOriginalUid | string | Optional | Unique record ID from source system |
| EventOriginalType | string | Optional | Source system's native event type/ID |
| EventOriginalSubType | string | Optional | Source system's native event subtype |
| EventOriginalResultDetails | string | Optional | Source system's result details before normalization |
| EventSeverity | string | Recommended | `Informational`, `Low`, `Medium`, `High` |
| EventOriginalSeverity | string | Optional | Source system's severity before normalization |
| EventProduct | string | Mandatory | Product generating the event (e.g., `Sysmon`, `M365 Defender for Endpoint`) |
| EventProductVersion | string | Optional | Product version number |
| EventVendor | string | Mandatory | Vendor of the product (e.g., `Microsoft`) |
| EventSchema | string | Mandatory | ASIM schema name (e.g., `Authentication`, `Dns`) |
| EventSchemaVersion | string | Mandatory | Schema version (e.g., `0.1.3`) |
| EventOwner | string | Optional | Generating department or subsidiary |
| EventReportUrl | string | Optional | URL linking to supplementary resource for the event |

---

## ASIM Enumerated Types (from ASimEnumerations.yaml)

### UserIdType
`SID`, `UID`, `AADID`, `OktaId`, `AWSId`, `PUID`, `Other`

### UsernameType
`UPN`, `Windows`, `DN`, `Simple`

### UserType
`Regular`, `Machine`, `Admin`, `Guest`, `System`, `Service`, `Application`, `Other`

### AppType
`Process`, `Service`, `Resource`, `URL`, `SaaS application`, `Operating System`, `Container`, `CSP`, `Other`

### DvcIdType
`MDEid`, `AzureResourceId`, `MD4IoTid`, `VMConnectionId`, `AwsVpcId`, `Other`

### DeviceType
`Computer`, `Mobile Device`, `IOT Device`, `Other`

### DomainType
`Windows`, `FQDN`

### FilePathType
`Windows Local`, `Windows Share`, `Unix`, `URL`
