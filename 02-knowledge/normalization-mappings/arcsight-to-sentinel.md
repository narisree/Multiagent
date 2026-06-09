# ArcSight → Sentinel Field Mapping

ArcSight uses CEF (Common Event Format). The Sentinel connector ingests CEF via Syslog into the **CommonSecurityLog** table.

---

## CEF Header Fields

| CEF Header | CommonSecurityLog Field | Notes |
|---|---|---|
| deviceVendor | DeviceVendor | e.g., "ArcSight" |
| deviceProduct | DeviceProduct | Product name |
| deviceVersion | DeviceVersion | |
| deviceEventClassId | DeviceEventClassID | Rule/event class ID |
| name | Activity | Human-readable event name |
| severity | LogSeverity | String 0-10 or word; see severity-mappings.md |

---

## CEF Extension Fields → CommonSecurityLog

| CEF Field | CommonSecurityLog Field | Data Type |
|---|---|---|
| src | SourceIP | string |
| spt | SourcePort | int |
| suser | SourceUserName | string |
| shost | SourceHostName | string |
| smac | SourceMACAddress | string |
| sntdom | SourceNTDomain | string |
| dst | DestinationIP | string |
| dpt | DestinationPort | int |
| duser | DestinationUserName | string |
| dhost | DestinationHostName | string |
| dmac | DestinationMACAddress | string |
| dntdom | DestinationNTDomain | string |
| request | RequestURL | string |
| requestMethod | RequestMethod | string (GET/POST/etc.) |
| requestClientApplication | RequestClientApplication | string |
| app | ApplicationProtocol | string |
| proto | Protocol | string |
| act | DeviceAction | string (allow/deny/block/drop) |
| outcome | DeviceEventOutcome | string |
| msg | Message | string |
| reason | Reason | string |
| cn1 / cn1Label | DeviceCustomNumber1 / DeviceCustomNumber1Label | long |
| cn2 / cn2Label | DeviceCustomNumber2 / DeviceCustomNumber2Label | long |
| cn3 / cn3Label | DeviceCustomNumber3 / DeviceCustomNumber3Label | long |
| cs1 / cs1Label | DeviceCustomString1 / DeviceCustomString1Label | string |
| cs2 / cs2Label | DeviceCustomString2 / DeviceCustomString2Label | string |
| cs3 / cs3Label | DeviceCustomString3 / DeviceCustomString3Label | string |
| cs4 / cs4Label | DeviceCustomString4 / DeviceCustomString4Label | string |
| cs5 / cs5Label | DeviceCustomString5 / DeviceCustomString5Label | string |
| cs6 / cs6Label | DeviceCustomString6 / DeviceCustomString6Label | string |
| deviceCustomDate1 / deviceCustomDate1Label | DeviceCustomDate1 / DeviceCustomDate1Label | datetime |
| deviceCustomDate2 / deviceCustomDate2Label | DeviceCustomDate2 / DeviceCustomDate2Label | datetime |
| fname | FileName | string |
| fsize | FileSize | long |
| fhash | FileHash | string |
| ftype | FileType | string |
| fcreateTime | FileCreateTime | datetime |
| fmodifyTime | FileModificationTime | datetime |
| sproc | ProcessName | string (source process) |
| dpid | DestinationProcessId | int |
| dproc | DestinationProcessName | string |
| spid | SourceProcessId | int (note: maps to ProcessId in CSL) |
| cat | DeviceEventCategory | string |
| rt | ReceiptTime | datetime (maps to TimeGenerated if not overridden) |
| start | StartTime | datetime |
| end | EndTime | datetime |
| externalId | ExtID | string |
| deviceInboundInterface | DeviceInboundInterface | string |
| deviceOutboundInterface | DeviceOutboundInterface | string |
| deviceTranslatedAddress | DeviceTranslatedAddress | string |
| destinationTranslatedAddress | DestinationTranslatedAddress | string |
| sourceTranslatedAddress | SourceTranslatedAddress | string |
| destinationTranslatedPort | DestinationTranslatedPort | int |
| sourceTranslatedPort | SourceTranslatedPort | int |
| bytesIn | ReceivedBytes | long |
| bytesOut | SentBytes | long |
| in | ReceivedPackets | long |
| out | SentPackets | long |
| cnt | EventCount | int |
| deviceDirection | CommunicationDirection | int (0=inbound, 1=outbound) |
| flexDate1 / flexDate1Label | FlexDate1 / FlexDate1Label | datetime |
| flexNumber1 / flexNumber1Label | FlexNumber1 / FlexNumber1Label | long |
| flexNumber2 / flexNumber2Label | FlexNumber2 / FlexNumber2Label | long |
| flexString1 / flexString1Label | FlexString1 / FlexString1Label | string |
| flexString2 / flexString2Label | FlexString2 / FlexString2Label | string |

---

## ArcSight ESM-specific fields

| ArcSight ESM Field | Sentinel Approach |
|---|---|
| Manager Severity | Map via LogSeverity; see severity-mappings.md |
| Base Event ID | DeviceEventClassID |
| Event Category (ArcSight taxonomy) | DeviceEventCategory |
| Target User Name | DestinationUserName |
| Source Zone / Target Zone | AdditionalExtensions or DeviceCustomStringN |
| Attacker Address | SourceIP |
| Target Address | DestinationIP |
| Correlation Rule Name | Activity |
| ArcSight Rule ID | DeviceEventClassID |

---

## Custom field resolution strategy

ArcSight uses cs1–cs6 and cn1–cn3 for custom fields. Resolution approach:
1. Check the label fields (cs1Label, cs1Label, etc.) to identify content.
2. Map by semantic content, not field name. e.g., if cs1Label = "hash" → use SHA256/FileHash.
3. Emit a comment in KQL: `// cs1 (label: ProcessName) mapped to ProcessName`

```kql
// Example: cs1Label = "CommandLine"
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| extend CommandLine = DeviceCustomString1  // cs1 where cs1Label == "CommandLine"
```

---

## ArcSight Connector Filtering

Filter to specific products in KQL:
```kql
CommonSecurityLog
| where DeviceVendor == "ArcSight"
| where DeviceProduct == "ESM"
```

Or by vendor for a device type:
```kql
CommonSecurityLog
| where DeviceVendor in ("Palo Alto Networks", "Fortinet", "Check Point")
```

---

## Timestamp handling

ArcSight sends `rt` (receipt time) and `start`/`end` for event windows.
- `TimeGenerated` = Sentinel ingest time (usually close to rt)
- `ReceiptTime` = the `rt` CEF field (device receipt time)
- `StartTime` / `EndTime` = event window from source

For detection queries, use `TimeGenerated` for time filtering. Reference `ReceiptTime` only when event time matters for logic.
