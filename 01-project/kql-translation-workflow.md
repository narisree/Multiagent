# KQL Translation Workflow — 8 steps, non-negotiable

When the user provides a legacy SIEM alert, execute these steps IN ORDER.

---

## Step 0 — Input classification (before translating)

Classify the input as **easy, medium, or hard**:

- **Easy:** standard event log detection, single table, close precedent in `02-knowledge/sentinel-rules/`, no complex logic, clear field mappings.
- **Medium:** familiar detection type with twists — custom thresholds, moderate field mapping ambiguity, simple joins, partial precedent.
- **Hard:** ANY of: unfamiliar source SIEM, no close precedent, complex correlation across tables, regex-heavy logic, custom aggregations, time-series detection, multi-stage kill-chain, ambiguous field semantics.

**For hard inputs, you ARE authorized to ask 1-2 clarifying questions before translating.**

State classification in 1 line at the top of the reply.

---

## Step 1 — Identify source SIEM and parse the input

Extract from the input:
- Source SIEM (ArcSight, QRadar, LogRhythm, Splunk, other)
- Detection intent (what behavior is being detected)
- Source log types / event categories referenced
- Field names used (raw from source SIEM)
- Threshold / aggregation logic
- Time window / lookback period
- MITRE ATT&CK tagging if present
- Severity / priority in source SIEM scale

State findings in 3-6 bullets.

---

## Step 2 — Consult `02-knowledge/sentinel-rules/` for precedents (MANDATORY)

Search the precedent index. Find the closest matching translated rule. Read it fully. State:
- "Closest precedent: `02-knowledge/sentinel-rules/<file>.md`."
- "Idioms I will reuse: <list>."
- "Deltas from precedent: <none / list with reasons>."

If no precedent: say so explicitly. Look at the closest category neighbor.

**This step prevents the most common failure mode. Skipping it is a known-mistake violation.**

---

## Step 3 — Resolve field mappings

1. Open the relevant normalization mapping file:
   - ArcSight → `02-knowledge/normalization-mappings/arcsight-to-sentinel.md`
   - QRadar → `02-knowledge/normalization-mappings/qradar-to-sentinel.md`
   - LogRhythm → `02-knowledge/normalization-mappings/logrhythm-to-sentinel.md`
   - Splunk → `02-knowledge/normalization-mappings/splunk-to-sentinel.md`
2. Map every source field to its Sentinel equivalent.
3. Determine the correct Sentinel table(s) for this data.
4. For any field with no mapping: flag as inference, drop Field Mapping confidence by ≥10 points, add to `07-questions/open-questions.md`.

State a mapping table:
```
| Source Field | Source SIEM | Sentinel Table | Sentinel Field | Confidence |
```

---

## Step 4 — Apply lessons learned

Read `06-lessons/lessons-learned.md`. For each active lesson matching this source SIEM and detection type, state which lessons apply and how they shape the translation.

---

## Step 5 — Determine Sentinel rule metadata

Pin these values from canonical sources:

| Field | Value | Source |
|---|---|---|
| displayName | <translated name> | from source rule name |
| severity | High/Medium/Low/Informational | `02-knowledge/normalization-mappings/severity-mappings.md` |
| queryFrequency | ISO 8601 duration | match source rule run frequency |
| queryPeriod | ISO 8601 duration | match source lookback window |
| triggerOperator | GreaterThan/LessThan/Equal/NotEqual | from source threshold direction |
| triggerThreshold | integer | from source threshold value (0 = any match) |
| tactics | MITRE tactic names | from source tagging or inferred |
| techniques | T-codes | from source tagging or inferred |

If any value is not determinable from the source: flag as inference.

---

## Step 6 — Write the KQL query

Use this standard skeleton:

```kql
// Source: <SIEM> — <original rule name>
// Description: <what this detects>
let lookback = ago(1h); // adjust to match queryPeriod
let threshold = 5;       // adjust to match source threshold
<TableName>
| where TimeGenerated >= lookback
| where <translated filter conditions>
| summarize <aggregations> by <grouping fields>
| where <post-aggregation threshold filter>
| project TimeGenerated, <key fields for incident>
```

Rules:
- Always start with `// Source:` header comment
- Always use `let lookback` for the time window
- Always use `let threshold` for numeric thresholds
- Always include `TimeGenerated` filter
- Always end with `| project` to limit columns
- Preserve ALL detection logic from source — do not simplify away conditions
- Use `tolower()` for case-insensitive string comparisons
- Use explicit `join kind=` — never rely on default

Write test cases: at least 2 positive (should trigger) and 1 negative (should not trigger).

---

## Step 7 — Build the ARM template

Use this structure:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.SecurityInsights/alertRules",
      "apiVersion": "2023-02-01-preview",
      "name": "[guid(resourceGroup().id, '<unique-name>')]",
      "kind": "Scheduled",
      "scope": "[concat('Microsoft.OperationalInsights/workspaces/', parameters('workspaceName'))]",
      "properties": {
        "displayName": "<Alert Display Name>",
        "description": "<Description>",
        "severity": "High",
        "enabled": true,
        "query": "<KQL QUERY — single-line escaped>",
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT1H",
        "suppressionEnabled": false,
        "tactics": [],
        "techniques": [],
        "entityMappings": [],
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
  ],
  "parameters": {
    "workspaceName": {
      "type": "string"
    }
  }
}
```

---

## Step 8 — Run quality gates and deliver

In order:

1. **Run KQL linter**: `python3 .claude/skills/kql-sentinel-lint/lint.py 08-generated/<name>/rule.json`
   - If unavailable: run cognitive checklist from `.claude/skills/kql-sentinel-lint/SKILL.md`
   - State which mode ran.
2. **Invoke blind critic** for medium/hard inputs (subagent `sentinel-rule-critic`).
3. **Produce structured confidence breakdown** per `01-project/confidence-framework.md`.
4. **Save outputs:**
   - `08-generated/<name>/query.kql` — KQL only
   - `08-generated/<name>/rule.json` — full ARM template
   - `08-generated/<name>/tests.md` — test cases
   - `08-generated/<name>/notes.md` — translation notes, field mapping decisions
5. **Deliver** in this format:

```
## Delivery — <rule name>

**Classification:** easy | medium | hard
**Source SIEM:** <SIEM>
**Closest precedent:** `02-knowledge/sentinel-rules/<file>.md`

**KQL Query:**
```kql
<query>
```

**ARM Template:** `08-generated/<name>/rule.json`

**Test cases:**
- Positive: <event that should trigger>
- Negative: <event that should not trigger>

**Lint findings:** (mode: script | cognitive)
- Errors: <none / list>
- Schema violations: <none / list>
- Semantic mismatches: <none / list>
- Field mapping errors: <none / list>
- House-style deviations: <none / list>
- Risks: <list>

**Critic findings:** (medium/hard only)
<findings or "not invoked — easy input">

**Confidence breakdown:**
- KQL Syntax: NN% — <failure mode>
- Table/Schema Mapping: NN% — <failure mode>
- Logic Fidelity: NN% — <failure mode>
- Field Mapping Accuracy: NN% — <failure mode>
- Sentinel Metadata: NN% — <failure mode>
- Entity Mapping: NN% — <failure mode>
- Query Performance: NN% — <failure mode>
- **Overall: NN% (governed by <element>)**

**What I'd test first:**
1. <riskiest element>
2. <second riskiest>

**Files saved:**
- Query: `08-generated/<name>/query.kql`
- ARM template: `08-generated/<name>/rule.json`
- Tests: `08-generated/<name>/tests.md`
- Notes: `08-generated/<name>/notes.md`
```

6. **Append pattern to `06-lessons/pattern-library.md`.**
