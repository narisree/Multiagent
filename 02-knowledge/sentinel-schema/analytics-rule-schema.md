# Sentinel Analytics Rule Schema (ARM Template)

Source: learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview

---

## Full ARM template schema

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workspaceName": {
      "type": "string",
      "metadata": { "description": "Log Analytics workspace name" }
    }
  },
  "resources": [
    {
      "type": "Microsoft.SecurityInsights/alertRules",
      "apiVersion": "2023-02-01-preview",
      "name": "[guid(resourceGroup().id, 'UNIQUE-RULE-IDENTIFIER')]",
      "kind": "Scheduled",
      "scope": "[concat('Microsoft.OperationalInsights/workspaces/', parameters('workspaceName'))]",
      "properties": {
        "displayName": "Alert Display Name",
        "description": "What this rule detects and why it matters.",
        "severity": "High",
        "enabled": true,
        "query": "SecurityEvent | where ...",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT1H",
        "suppressionEnabled": false,
        "tactics": ["CredentialAccess"],
        "techniques": ["T1110"],
        "alertDetailsOverride": {
          "alertDisplayNameFormat": "{{AccountName}} failed login from {{Computer}}",
          "alertDescriptionFormat": "Account {{AccountName}} had {{FailureCount}} failed logins.",
          "alertTacticsColumnName": null,
          "alertSeverityColumnName": null
        },
        "customDetails": {
          "FailureCount": "FailureCount",
          "SourceComputer": "Computer"
        },
        "entityMappings": [
          {
            "entityType": "Account",
            "fieldMappings": [
              { "identifier": "Name", "columnName": "AccountName" },
              { "identifier": "NTDomain", "columnName": "Domain" }
            ]
          },
          {
            "entityType": "Host",
            "fieldMappings": [
              { "identifier": "HostName", "columnName": "Computer" }
            ]
          }
        ],
        "incidentConfiguration": {
          "createIncident": true,
          "groupingConfiguration": {
            "enabled": false,
            "reopenClosedIncident": false,
            "lookbackDuration": "PT5H",
            "matchingMethod": "AllEntities",
            "groupByEntities": [],
            "groupByAlertDetails": [],
            "groupByCustomDetails": []
          }
        }
      }
    }
  ]
}
```

---

## Required fields

| Field | Type | Valid values | Notes |
|---|---|---|---|
| `kind` | string | `"Scheduled"` | Only Scheduled for custom rules |
| `displayName` | string | any | Shown in portal |
| `severity` | string | `"High"`, `"Medium"`, `"Low"`, `"Informational"` | Exact case required |
| `query` | string | valid KQL | Single-line, newlines escaped |
| `queryFrequency` | string | ISO 8601 duration | How often rule runs |
| `queryPeriod` | string | ISO 8601 duration | Lookback window; must be ≥ queryFrequency |
| `triggerOperator` | string | `"GreaterThan"`, `"LessThan"`, `"Equal"`, `"NotEqual"` | |
| `triggerThreshold` | integer | 0–10000 | 0 = fire on any results |
| `enabled` | boolean | true/false | |

## Optional but strongly recommended

| Field | Notes |
|---|---|
| `description` | Explain what is being detected |
| `tactics` | MITRE ATT&CK tactics (see `mitre-tactics.md`) |
| `techniques` | MITRE ATT&CK technique IDs (T1234) |
| `entityMappings` | Required for entity correlation in incidents |
| `customDetails` | Expose KQL column values in alert details |
| `alertDetailsOverride` | Dynamic display name and description |
| `suppressionDuration` | Dedup window; set to match queryFrequency |

---

## KQL in ARM templates

The `query` field must be a JSON string. Newlines become `\n`, quotes become `\"`.

**Readable multi-line format (in ARM template):**
```json
"query": "let lookback = ago(1h);\nSecurityEvent\n| where TimeGenerated >= lookback\n| where EventID == 4625\n| summarize count() by AccountName\n| project TimeGenerated, AccountName"
```

---

## Incident grouping — matchingMethod values

| Value | Behavior |
|---|---|
| `"AllEntities"` | Group alerts that share all mapped entities |
| `"AnyAlert"` | Group all alerts from this rule together |
| `"Selected"` | Group by specific entities in `groupByEntities` |

---

## alertDetailsOverride format strings

Use `{{ColumnName}}` (double curly braces) to reference query result columns:
```json
"alertDisplayNameFormat": "{{AccountName}} — {{FailureCount}} failures from {{Computer}}"
```
