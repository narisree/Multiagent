# Project Overview — Sentinel KQL Translation Agent

## Mission

Bulk-translate legacy SIEM detection rules (ArcSight, QRadar, LogRhythm, Splunk, and others) into Microsoft Sentinel Analytics Rules with production-ready KQL queries and ARM-deployable templates. Every output must be deployable without manual editing.

## Supported Source SIEMs

| SIEM | Input Formats | Coverage Level |
|---|---|---|
| IBM QRadar | JSON rule export, AQL/QRadar rule definitions | Full |
| Micro Focus ArcSight | CEF events, XML rule definitions, JSON | Full |
| LogRhythm | JSON export, XML rule definitions | Full |
| Splunk | SPL saved searches/alerts, JSON export | Full |
| McAfee/Trellix ESM | JSON, XML | Mapped on encounter |
| RSA NetWitness | JSON rule export | Mapped on encounter |

## Output per Translation

1. **KQL Query** — paste-ready, time-bounded, house-style compliant
2. **ARM Template** (JSON) — full Sentinel Analytics Rule deployable via portal, CLI, or pipeline
3. **Confidence Breakdown** — per-element scored, weakest-link governs
4. **Test Cases** — sample event data to validate the rule fires correctly

## Accuracy Targets

| Complexity | Target | Condition |
|---|---|---|
| Easy | ≥ 95% first-pass | Close precedent in corpus, standard format |
| Medium | ≥ 90% first-pass | Familiar with twists, partial precedent |
| Hard | ≥ 75% first-pass | Novel format, no precedent — clearly flagged |

## Volume Handling

- Batch mode: accept JSON or CSV with N alerts, translate in groups of 10
- Each group delivered with aggregate confidence
- Batch summary after all groups: counts, accuracy assessment, retry recommendations

## Key References

- `02-knowledge/kql/` — KQL language reference
- `02-knowledge/sentinel-schema/` — Sentinel rule schema, tables, entities
- `02-knowledge/normalization-mappings/` — per-SIEM field mapping tables
- `02-knowledge/house-style/` — validated patterns from existing translations
- `06-lessons/lessons-learned.md` — consulted before EVERY translation
