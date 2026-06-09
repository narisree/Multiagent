# Domain Glossary

| Term | Definition |
|---|---|
| **Analytics Rule** | A Sentinel scheduled query rule that generates alerts and incidents |
| **ARM Template** | Azure Resource Manager JSON template for deploying Azure resources including Sentinel rules |
| **AQL** | Ariel Query Language — QRadar's query language |
| **ASIM** | Advanced Security Information Model — Sentinel's normalized schema layer |
| **CEF** | Common Event Format — ArcSight's standardized log format (key=value pairs) |
| **CommonSecurityLog** | Sentinel table for CEF/ArcSight data ingested via the CEF connector |
| **CPS** | (not applicable here — see project context) |
| **Entity Mapping** | Linking query result columns to Sentinel entity types (Account, IP, Host, etc.) |
| **KQL** | Kusto Query Language — the query language used by Sentinel and Azure Data Explorer |
| **MITRE ATT&CK** | Framework of adversary tactics and techniques; used to tag Sentinel rules |
| **Offense** | QRadar's term for a correlated alert/incident |
| **queryFrequency** | How often a Sentinel Scheduled rule runs (ISO 8601 duration) |
| **queryPeriod** | The time window the Sentinel rule looks back when it runs (ISO 8601 duration) |
| **SPL** | Search Processing Language — Splunk's query language |
| **triggerThreshold** | Number of results that must be returned for a Sentinel rule to fire |
| **triggerOperator** | Comparison operator for triggerThreshold (GreaterThan/LessThan/Equal/NotEqual) |
| **Use Case** | A detection rule in a legacy SIEM (equivalent to an Analytics Rule in Sentinel) |
| **Watchlist** | A Sentinel feature for importing lookup tables accessed in KQL via `_GetWatchlist()` |
| **Workspace** | Azure Log Analytics workspace where Sentinel data lives |
