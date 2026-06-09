# Sentinel KQL Translation Agent

A persistent, self-improving agent for bulk-translating legacy SIEM detection rules into Microsoft Sentinel Analytics Rules.

## Supported Source SIEMs

| SIEM | Input Formats | Mapping Coverage |
|---|---|---|
| IBM QRadar | JSON export, AQL rules | Full field mapping |
| Micro Focus ArcSight | CEF, XML, JSON | Full CEF → CommonSecurityLog |
| LogRhythm | JSON export, XML | Full field mapping |
| Splunk | SPL rules, JSON | Logic + field mapping |
| McAfee/Trellix ESM | JSON, XML | Partial (mapped on encounter) |
| RSA NetWitness | JSON | Partial (mapped on encounter) |

## Output Format

Every translation produces:
1. **KQL Query** — ready to paste into Sentinel Analytics
2. **ARM Template** (JSON) — deploy via Azure Portal, CLI, or pipeline
3. **Confidence Breakdown** — per-element scoring with failure modes
4. **Test Cases** — sample data to validate the rule

## Quick Start

1. Provide legacy SIEM alerts as JSON or CSV
2. Agent classifies complexity and source SIEM
3. Agent translates with full quality gates
4. Review confidence breakdown, test in Sentinel

## Knowledge Base Structure

```
02-knowledge/
├── kql/                    # KQL language reference
├── sentinel-schema/        # Sentinel tables, rule schema, entities
├── sentinel-rules/         # Precedent translated rules
├── normalization-mappings/ # Per-SIEM field mapping tables
└── house-style/            # Validated translation patterns
```

## Accuracy Targets

- Easy (well-known, precedent exists): ≥ 95% first-pass
- Medium (familiar with twists): ≥ 90% first-pass
- Hard (novel format, no precedent): ≥ 75% — clearly flagged

## Files

- `CLAUDE.md` — agent anchor and operating instructions
- `profile.md` — user role and project context
- `01-project/kql-translation-workflow.md` — the 8-step translation pipeline
- `02-knowledge/` — the agent's brain
- `06-lessons/lessons-learned.md` — consulted before every translation
- `08-generated/` — all output translations
