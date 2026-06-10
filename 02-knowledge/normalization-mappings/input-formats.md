# Legacy SIEM Input Formats

Defines the expected input structure for the translation agent. Each batch combines a **CSV metadata file** with **native per-SIEM rule files** (JSON or XML depending on the SIEM).

---

## Dual-Input Model

```
batch/
├── rules.csv                  # universal metadata for all rules in the batch
├── qradar-rule-001.json       # QRadar rule JSON export (referenced from CSV)
├── splunk-rule-002.json       # Splunk savedsearch JSON export
├── arcsight-rule-003.xml      # ArcSight ESM rule XML export
└── logrhythm-rule-004.xml     # LogRhythm AI Engine rule XML export
```

Alternatively, the native query can be embedded inline in the CSV `query` column (escaped).

---

## CSV Metadata Schema

```
rule_name, siem_type, description, severity, mitre_tactics, mitre_techniques, query, rule_file_path
```

| Column | Required | Notes |
|---|---|---|
| `rule_name` | Yes | Display name for the translated Sentinel rule |
| `siem_type` | Yes | `QRadar`, `Splunk`, `ArcSight`, `LogRhythm`, `NetWitness`, `McAfee` |
| `description` | No | Human-readable purpose — used only to infer MITRE tactics if absent from query |
| `severity` | No | Source SIEM severity; mapped via `severity-mappings.md` |
| `mitre_tactics` | No | Comma-separated tactic names if already tagged in source |
| `mitre_techniques` | No | Comma-separated T-codes (e.g., `T1110,T1078`) |
| `query` | Conditional | Inline native query (escaped). Use this OR `rule_file_path`, not both |
| `rule_file_path` | Conditional | Path to `.json` / `.xml` rule file. Use this OR `query`, not both |

### Example CSV row
```csv
rule_name,siem_type,description,severity,mitre_tactics,mitre_techniques,rule_file_path
Multiple Failed Logins,QRadar,Brute force detection,High,CredentialAccess,T1110,qradar-rule-001.json
```

---

## Per-SIEM Native Format

### QRadar — JSON rule export

**Query location:** `.aqlQuery` (preferred) or `.buildingBlocks[].logic`

```json
{
  "id": 12345,
  "name": "Multiple Failed Logins",
  "type": "EventRule",
  "enabled": true,
  "groups": ["Authentication"],
  "priority": 7,
  "aqlQuery": "SELECT username, sourceip, count(*) AS cnt FROM events WHERE category = 'Authentication Failure' GROUP BY username, sourceip HAVING cnt > 5 LAST 10 MINUTES",
  "buildingBlocks": [
    { "id": 1, "name": "Auth failures", "logic": "SELECT ... FROM events WHERE ..." }
  ],
  "responseActions": []
}
```

**Extraction targets:**

| JSON key | Maps to |
|---|---|
| `aqlQuery` or `buildingBlocks[].logic` | KQL filter + summarize logic |
| `priority` (1-10) | Sentinel severity via `severity-mappings.md` |
| `groups[]` | MITRE tactic inference (e.g., "Authentication" → CredentialAccess) |
| `enabled` | Sentinel `enabled` field |

---

### Splunk — savedsearches JSON export

**Query location:** `.content.search`

```json
{
  "name": "Multiple Failed Logins",
  "content": {
    "search": "index=wineventlog EventCode=4625 | stats count as failures by Account_Name, src | where failures > 5",
    "cron_schedule": "*/15 * * * *",
    "dispatch.earliest_time": "-15m",
    "dispatch.latest_time": "now",
    "alert_threshold": "0",
    "alert_comparator": "greater than",
    "alert.severity": "3",
    "description": "Detects brute force login attempts"
  }
}
```

**Extraction targets:**

| JSON key | Maps to |
|---|---|
| `content.search` | The SPL query — PRIMARY source of detection logic |
| `content.cron_schedule` | `queryFrequency` in ISO 8601 (cron `*/15 * * * *` → `PT15M`) |
| `content.dispatch.earliest_time` | `queryPeriod` (`-15m` → `PT15M`) |
| `content.alert.severity` | Sentinel severity via `severity-mappings.md` |
| `content.description` | Secondary context — consult only if SPL lacks field context |

---

### ArcSight — ESM rule XML export

**Query location:** `<Filter>` + `<Threshold>` elements inside `<Rule>`

See `arcsight-esm-rule-syntax.md` for the full XML parsing guide.

```xml
<Rule name="Multiple Failed Logins" severity="High">
  <Filter operator="AND">
    <Condition field="eventId" op="=" value="4625"/>
    <Condition field="targetAccountName" op="!=" value="SYSTEM"/>
  </Filter>
  <Threshold field="targetAccountName" type="EventCount" limit="5"
             timeUnit="Minute" timeWindow="15"/>
</Rule>
```

**Extraction targets:**

| XML element/attribute | Maps to |
|---|---|
| `<Condition field op value>` | KQL `where` filter |
| `<Threshold limit timeWindow>` | `summarize count()` + threshold + lookback |
| `<Filter operator="AND/OR">` | KQL and/or logic |
| `severity` attribute on `<Rule>` | Sentinel severity |

---

### LogRhythm — AI Engine XML or JSON export

**Query location:** `<Blocks>/<Block>/<FieldConstraint>` (XML) or `ruleBlocks[].conditions[]` (JSON)

See `logrhythm-ai-engine-syntax.md` for the full parsing guide.

**XML form:**
```xml
<AIERuleBlock name="Multiple Failed Logins">
  <Blocks>
    <Block matchCount="5" withinSeconds="900">
      <FieldConstraint field="originLogin" comparator="=" value="*"/>
      <FieldConstraint field="classificationName" comparator="=" value="Authentication Failure"/>
    </Block>
  </Blocks>
</AIERuleBlock>
```

**JSON form:**
```json
{
  "ruleId": 456,
  "name": "Multiple Failed Logins",
  "ruleBlocks": [{
    "matchCount": 5,
    "withinSeconds": 900,
    "conditions": [
      { "field": "classificationName", "comparator": "=", "value": "Authentication Failure" }
    ]
  }],
  "logSourceFilters": [{ "logSourceType": "MS Windows Event Logging" }]
}
```

**Extraction targets:**

| Element/key | Maps to |
|---|---|
| `matchCount` / `withinSeconds` | `summarize count() >= N` within `ago(Xs)` |
| `conditions[].field + comparator + value` | KQL `where` filters |
| `logSourceFilters[].logSourceType` | Sentinel table selection |

---

## Parser Priority Rule

**Always extract detection logic FROM the native query/rule body. The `description` field is secondary context, used only to infer MITRE tactics/techniques when they are absent from the query.**

```
Priority order:
1. Native query/rule syntax  → filter conditions, thresholds, time windows, field names
2. CSV metadata              → rule_name, severity, mitre_tactics, mitre_techniques
3. description field         → MITRE inference only (last resort)
```
