# MITRE ATT&CK — Valid Values for Sentinel Analytics Rules

Source: learn.microsoft.com/en-us/azure/sentinel/understand-threat-intelligence

---

## Valid Tactics (Sentinel string values)

These are the exact strings accepted by Sentinel in the `tactics` array:

| Sentinel String | MITRE ID | Description |
|---|---|---|
| `"Reconnaissance"` | TA0043 | Gathering information |
| `"ResourceDevelopment"` | TA0042 | Establishing resources |
| `"InitialAccess"` | TA0001 | Getting into the network |
| `"Execution"` | TA0002 | Running malicious code |
| `"Persistence"` | TA0003 | Maintaining foothold |
| `"PrivilegeEscalation"` | TA0004 | Gaining higher permissions |
| `"DefenseEvasion"` | TA0005 | Avoiding detection |
| `"CredentialAccess"` | TA0006 | Stealing credentials |
| `"Discovery"` | TA0007 | Figuring out the environment |
| `"LateralMovement"` | TA0008 | Moving through the environment |
| `"Collection"` | TA0009 | Gathering data of interest |
| `"CommandAndControl"` | TA0011 | Communicating with compromised systems |
| `"Exfiltration"` | TA0010 | Stealing data |
| `"Impact"` | TA0040 | Manipulate, interrupt, or destroy |
| `"ImpairProcessControl"` | TA0106 | ICS-specific: manipulate control processes |
| `"InhibitResponseFunction"` | TA0107 | ICS-specific: prevent response |
| `"PreAttack"` | (legacy) | Combines Reconnaissance + ResourceDevelopment |

---

## Common Techniques by Tactic

### CredentialAccess
| Technique | Description |
|---|---|
| T1110 | Brute Force |
| T1110.001 | Password Guessing |
| T1110.003 | Password Spraying |
| T1110.004 | Credential Stuffing |
| T1003 | OS Credential Dumping |
| T1003.001 | LSASS Memory |
| T1555 | Credentials from Password Stores |
| T1552 | Unsecured Credentials |
| T1558 | Steal or Forge Kerberos Tickets |
| T1558.003 | Kerberoasting |

### InitialAccess
| Technique | Description |
|---|---|
| T1078 | Valid Accounts |
| T1078.004 | Cloud Accounts |
| T1190 | Exploit Public-Facing Application |
| T1566 | Phishing |
| T1566.001 | Spearphishing Attachment |
| T1566.002 | Spearphishing Link |
| T1133 | External Remote Services |
| T1195 | Supply Chain Compromise |

### Execution
| Technique | Description |
|---|---|
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell |
| T1059.005 | Visual Basic |
| T1059.007 | JavaScript |
| T1204 | User Execution |
| T1047 | Windows Management Instrumentation |
| T1569 | System Services |
| T1053 | Scheduled Task/Job |
| T1053.005 | Scheduled Task |

### Persistence
| Technique | Description |
|---|---|
| T1098 | Account Manipulation |
| T1136 | Create Account |
| T1136.001 | Local Account |
| T1136.003 | Cloud Account |
| T1547 | Boot or Logon Autostart Execution |
| T1547.001 | Registry Run Keys |
| T1053.005 | Scheduled Task |
| T1543 | Create or Modify System Process |
| T1543.003 | Windows Service |

### DefenseEvasion
| Technique | Description |
|---|---|
| T1078 | Valid Accounts |
| T1562 | Impair Defenses |
| T1562.001 | Disable or Modify Tools |
| T1070 | Indicator Removal |
| T1070.001 | Clear Windows Event Logs |
| T1036 | Masquerading |
| T1027 | Obfuscated Files or Information |
| T1218 | Signed Binary Proxy Execution |

### LateralMovement
| Technique | Description |
|---|---|
| T1021 | Remote Services |
| T1021.001 | RDP |
| T1021.002 | SMB/Windows Admin Shares |
| T1021.006 | Windows Remote Management |
| T1550 | Use Alternate Authentication Material |
| T1550.002 | Pass the Hash |
| T1550.003 | Pass the Ticket |
| T1570 | Lateral Tool Transfer |

### Exfiltration
| Technique | Description |
|---|---|
| T1041 | Exfiltration Over C2 Channel |
| T1048 | Exfiltration Over Alternative Protocol |
| T1567 | Exfiltration Over Web Service |
| T1020 | Automated Exfiltration |
| T1030 | Data Transfer Size Limits |

### Impact
| Technique | Description |
|---|---|
| T1486 | Data Encrypted for Impact (Ransomware) |
| T1490 | Inhibit System Recovery |
| T1489 | Service Stop |
| T1499 | Endpoint Denial of Service |
| T1485 | Data Destruction |
| T1531 | Account Access Removal |

---

## Mapping legacy SIEM categories to tactics

| Legacy Category | MITRE Tactic |
|---|---|
| Authentication failure / brute force | CredentialAccess |
| Privilege escalation | PrivilegeEscalation |
| New admin account / account changes | Persistence |
| Lateral movement / pass-the-hash | LateralMovement |
| Malware execution | Execution |
| Data exfiltration | Exfiltration |
| C2 / beaconing | CommandAndControl |
| Reconnaissance / port scan | Discovery |
| Ransomware / encryption | Impact |
| Defense evasion / log clearing | DefenseEvasion |
| Phishing / initial compromise | InitialAccess |
| Scheduled task creation | Persistence, Execution |
