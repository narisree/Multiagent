# ASIM File Event Schema

Source: Azure/Azure-Sentinel `ASIM/schemas/ASimFileEvent.yaml` (v0.2.3, 2023-09-12)

Sentinel tables: `imFileEvent`, `ASimFileEvent`

Normalizes file creation, modification, deletion, rename, copy, and move events.

---

## Schema-Specific Fields

### Event classification
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| EventType | string | Mandatory | `FileAccessed`, `FileCreated`, `FileModified`, `FileDeleted`, `FileRenamed`, `FileCopied`, `FileMoved`, `FolderCreated`, `FolderDeleted`, `FolderMoved`, `FolderModified`, `FolderCopied`, `FileCreatedOrModified` |
| EventSubType | string | Optional | `Upload`, `Extended`, `Recycle`, `Preview`, `Download`, `Versions`, `Site`, `Checkin`, `Checkout`, `FolderModified` |
| EventSchema | string | Mandatory | `FileEvent` |

### Target file (the file being operated on)
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| TargetFilePath | string | Mandatory | Full normalized path of the target file |
| TargetFilePathType | string | Conditional | `Windows Local`, `Windows Share`, `Unix`, `URL` |
| TargetFileName | string | Recommended | Filename with extension, no path |
| TargetFileDirectory | string | Optional | Folder path without filename |
| TargetFileExtension | string | Optional | File extension |
| TargetFileMimeType | string | Optional | IANA MIME type |
| TargetFileSize | long | Optional | File size in bytes |
| TargetFileCreationTime | datetime | Optional | File creation timestamp |
| TargetFileMD5 | string | Optional | MD5 hash |
| TargetFileSHA1 | string | Optional | SHA1 hash |
| TargetFileSHA256 | string | Optional | SHA256 hash |
| TargetFileSHA512 | string | Optional | SHA512 hash |

### Source file (for copy/move/rename operations)
| Field | Type | Class | Values / Notes |
|---|---|---|---|
| SrcFilePath | string | Mandatory | Source file full path |
| SrcFilePathType | string | Conditional | `Windows Local`, `Windows Share`, `Unix`, `URL` |
| SrcFileName | string | Recommended | Source filename |
| SrcFileDirectory | string | Optional | Source folder |
| SrcFileExtension | string | Optional | Source extension |
| SrcFileMimeType | string | Optional | Source MIME type |
| SrcFileSize | long | Optional | Source file size in bytes |
| SrcFileCreationTime | datetime | Optional | Source file creation time |
| SrcFileMD5 | string | Optional | Source MD5 |
| SrcFileSHA1 | string | Optional | Source SHA1 |
| SrcFileSHA256 | string | Optional | Source SHA256 |
| SrcFileSHA512 | string | Optional | Source SHA512 |

### Network context
| Field | Type | Class | Description |
|---|---|---|---|
| HttpUserAgent | string | Optional | User agent for HTTP/HTTPS file operations |
| NetworkApplicationProtocol | string | Optional | `HTTP`, `HTTPS`, `SMB`, `FTP`, `SSH` |

### Threat fields
| Field | Type | Class | Values |
|---|---|---|---|
| ThreatField | string | Conditional | `SrcFilePath`, `DstFilePath` |
| ThreatFilePath | string | Optional | Path where threat was identified |

## Included Entities
- **Dvc** — device where event occurred
- **Actor** — user performing the file operation (ActorUsername, ActorUserId)
- **Acting Application** — application doing the operation (ActingAppName, ActingAppType)
- **Source System** — originating system (SrcIpAddr, SrcHostname)
- **Target URL** — if file is on web storage (TargetUrl)

## Aliases
| Alias | Maps To |
|---|---|
| User | ActorUsername |
| Application | TargetAppName |
| Url | TargetUrl |
| Process | ActingProcessName |
| IpAddr | SrcIpAddr |
| FileName | TargetFileName |
| FilePath | TargetFilePath |
| Hash | Best available TargetFile hash |
| HashType | Hash algorithm type |

## Common KQL usage
```kql
// ASIM file events - detect ransomware bulk file modifications
imFileEvent
| where TimeGenerated >= ago(5m)
| where EventType == "FileModified" or EventType == "FileRenamed"
| where TargetFileExtension in~ (".locked", ".encrypted", ".enc", ".crypt")
| summarize FileCount = count(), Files = make_set(TargetFileName) by DvcHostname, ActorUsername
| where FileCount > 20
```
