# Knowledge Base Index

## KQL Language Reference
- `kql/operators-reference.md` — all KQL tabular operators with signatures and examples
- `kql/functions-reference.md` — scalar and aggregation functions
- `kql/time-operators.md` — time syntax, datetime, ago(), bin(), time series

## Sentinel Schema
- `sentinel-schema/analytics-rule-schema.md` — full ARM template schema for Analytics Rules
- `sentinel-schema/tables-reference.md` — ~50 native Sentinel tables with key fields
- `sentinel-schema/entity-mappings.md` — entity types and valid identifiers
- `sentinel-schema/mitre-tactics.md` — valid tactic and technique values for Sentinel
- `sentinel-schema/asim/_index.md` — ASIM normalized schemas (9 schemas from Azure/Azure-Sentinel repo)

## Precedent Translated Rules
- `sentinel-rules/_index.md` — index of all validated translated rules (HOUSE STYLE)

## Normalization Mappings (Source SIEM → Sentinel)
- `normalization-mappings/input-formats.md` — dual-input spec (CSV + native per-SIEM format)
- `normalization-mappings/arcsight-to-sentinel.md` — CEF fields → CommonSecurityLog + Sentinel
- `normalization-mappings/arcsight-esm-rule-syntax.md` — ArcSight ESM XML rule parsing guide + hard constructs (active lists, session lists, variables, MatchesFilter)
- `normalization-mappings/qradar-to-sentinel.md` — QRadar AQL + JSON rule export → Sentinel + hard constructs (building blocks, reference-set writes, custom properties, offense chaining)
- `normalization-mappings/logrhythm-to-sentinel.md` — LogRhythm fields → Sentinel tables
- `normalization-mappings/logrhythm-ai-engine-syntax.md` — LogRhythm AI Engine XML/JSON rule parsing guide + hard constructs (ordered sequences, observation windows, cross-block uniqueness)
- `normalization-mappings/splunk-to-sentinel.md` — Splunk SPL + JSON savedsearch → Sentinel + hard constructs (tstats/data models, transaction, streamstats/eventstats, macros, subsearches, throttling)
- `normalization-mappings/severity-mappings.md` — all SIEM severity scales → Sentinel enum

## House Style
- `house-style/_index.md` — validated KQL patterns and conventions
- `house-style/kql-patterns.md` — reusable query snippets by detection type (18 patterns incl. scan sequences, session reconstruction, stateful-write decomposition, running aggregates)
