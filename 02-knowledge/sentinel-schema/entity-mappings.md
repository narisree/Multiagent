# Sentinel Entity Mappings Reference

Source: learn.microsoft.com/en-us/azure/sentinel/map-data-fields-to-entities

Entity mappings connect KQL query columns to Sentinel entity types, enabling incident enrichment and entity correlation.

---

## Entity Types and Valid Identifiers

### Account
Maps to user/service account entities.
```json
{
  "entityType": "Account",
  "fieldMappings": [
    { "identifier": "Name",       "columnName": "AccountName" },
    { "identifier": "NTDomain",   "columnName": "AccountDomain" },
    { "identifier": "UPNSuffix",  "columnName": "UPNSuffix" },
    { "identifier": "Sid",        "columnName": "AccountSid" },
    { "identifier": "AadUserId",  "columnName": "UserId" },
    { "identifier": "ObjectGuid", "columnName": "AccountObjectId" },
    { "identifier": "DisplayName","columnName": "UserDisplayName" }
  ]
}
```
**Required:** At least one identifier. `Name` + `NTDomain` preferred for Windows accounts. `UPNSuffix` + `Name` for AAD accounts.

### Host
Maps to computer/device entities.
```json
{
  "entityType": "Host",
  "fieldMappings": [
    { "identifier": "HostName",    "columnName": "Computer" },
    { "identifier": "NetBiosName", "columnName": "Computer" },
    { "identifier": "DNSDomain",   "columnName": "DNSDomain" },
    { "identifier": "FullName",    "columnName": "FQDN" },
    { "identifier": "OSFamily",    "columnName": "OSFamily" },
    { "identifier": "OSVersion",   "columnName": "OSVersion" },
    { "identifier": "AzureID",     "columnName": "AzureResourceId" }
  ]
}
```

### IP
Maps to IP address entities.
```json
{
  "entityType": "IP",
  "fieldMappings": [
    { "identifier": "Address", "columnName": "IpAddress" }
  ]
}
```
**Note:** One entity mapping per IP (source and destination need separate mappings).

### URL
```json
{
  "entityType": "URL",
  "fieldMappings": [
    { "identifier": "Url", "columnName": "RequestURL" }
  ]
}
```

### FileHash
```json
{
  "entityType": "FileHash",
  "fieldMappings": [
    { "identifier": "Algorithm", "columnName": "HashAlgorithm" },
    { "identifier": "Value",     "columnName": "SHA256" }
  ]
}
```
**Algorithm values:** `MD5`, `SHA1`, `SHA256`, `SHA256AC`, `Unknown`

### File
```json
{
  "entityType": "File",
  "fieldMappings": [
    { "identifier": "Name",      "columnName": "FileName" },
    { "identifier": "Directory", "columnName": "FolderPath" }
  ]
}
```

### Process
```json
{
  "entityType": "Process",
  "fieldMappings": [
    { "identifier": "ProcessId",         "columnName": "ProcessId" },
    { "identifier": "CommandLine",       "columnName": "ProcessCommandLine" },
    { "identifier": "ElevationToken",    "columnName": "ElevationToken" },
    { "identifier": "CreationTimeUtc",   "columnName": "ProcessCreationTime" }
  ]
}
```

### CloudApplication
```json
{
  "entityType": "CloudApplication",
  "fieldMappings": [
    { "identifier": "AppId",         "columnName": "AppId" },
    { "identifier": "Name",          "columnName": "AppDisplayName" },
    { "identifier": "InstanceName",  "columnName": "ResourceDisplayName" }
  ]
}
```

### DNS
```json
{
  "entityType": "DNS",
  "fieldMappings": [
    { "identifier": "DomainName", "columnName": "QueryName" }
  ]
}
```

### AzureResource
```json
{
  "entityType": "AzureResource",
  "fieldMappings": [
    { "identifier": "ResourceId", "columnName": "ResourceId" }
  ]
}
```

---

## Common entity mapping patterns by table

### SecurityEvent — failed logon
```json
"entityMappings": [
  { "entityType": "Account", "fieldMappings": [
    {"identifier": "Name",     "columnName": "AccountName"},
    {"identifier": "NTDomain", "columnName": "AccountDomain"}
  ]},
  { "entityType": "Host", "fieldMappings": [
    {"identifier": "HostName", "columnName": "Computer"}
  ]},
  { "entityType": "IP", "fieldMappings": [
    {"identifier": "Address", "columnName": "IpAddress"}
  ]}
]
```

### SigninLogs — AAD sign-in
```json
"entityMappings": [
  { "entityType": "Account", "fieldMappings": [
    {"identifier": "Name",      "columnName": "UserPrincipalName"},
    {"identifier": "AadUserId", "columnName": "UserId"}
  ]},
  { "entityType": "IP", "fieldMappings": [
    {"identifier": "Address", "columnName": "IPAddress"}
  ]}
]
```

### CommonSecurityLog — network/CEF
```json
"entityMappings": [
  { "entityType": "IP", "fieldMappings": [
    {"identifier": "Address", "columnName": "SourceIP"}
  ]},
  { "entityType": "IP", "fieldMappings": [
    {"identifier": "Address", "columnName": "DestinationIP"}
  ]},
  { "entityType": "Account", "fieldMappings": [
    {"identifier": "Name", "columnName": "SourceUserName"}
  ]}
]
```

### DeviceProcessEvents — process execution
```json
"entityMappings": [
  { "entityType": "Host", "fieldMappings": [
    {"identifier": "HostName", "columnName": "DeviceName"}
  ]},
  { "entityType": "Account", "fieldMappings": [
    {"identifier": "Name",     "columnName": "AccountName"},
    {"identifier": "NTDomain", "columnName": "AccountDomain"}
  ]},
  { "entityType": "Process", "fieldMappings": [
    {"identifier": "CommandLine", "columnName": "ProcessCommandLine"},
    {"identifier": "ProcessId",   "columnName": "ProcessId"}
  ]},
  { "entityType": "FileHash", "fieldMappings": [
    {"identifier": "Algorithm", "columnName": "HashAlgorithm"},
    {"identifier": "Value",     "columnName": "SHA256"}
  ]}
]
```

---

## Rules

- Maximum 5 entity mappings per rule.
- Each entity mapping can have up to 3 fieldMappings.
- For the same entityType appearing twice (e.g., source IP and dest IP), create two separate entityMappings entries.
- At least one identifier per entityMapping is required; multiple identifiers improve matching quality.
