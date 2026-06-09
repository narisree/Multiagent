# Knowledge Base Index

## KQL Language Reference
- `kql/operators-reference.md` — all KQL tabular operators with signatures and examples
- `kql/functions-reference.md` — scalar and aggregation functions
- `kql/time-operators.md` — time syntax, datetime, ago(), bin(), time series

## Sentinel Schema
- `sentinel-schema/analytics-rule-schema.md` — full ARM template schema for Analytics Rules
- `sentinel-schema/tables-reference.md` — all Sentinel tables, key fields, data connector
- `sentinel-schema/entity-mappings.md` — entity types and valid identifiers
- `sentinel-schema/mitre-tactics.md` — valid tactic and technique values for Sentinel

## Precedent Translated Rules
- `sentinel-rules/_index.md` — index of all validated translated rules (HOUSE STYLE)

## Normalization Mappings (Source SIEM → Sentinel)
- `normalization-mappings/arcsight-to-sentinel.md` — CEF fields → CommonSecurityLog + Sentinel
- `normalization-mappings/qradar-to-sentinel.md` — QRadar fields → Sentinel tables
- `normalization-mappings/logrhythm-to-sentinel.md` — LogRhythm fields → Sentinel tables
- `normalization-mappings/splunk-to-sentinel.md` — Splunk fields → Sentinel tables
- `normalization-mappings/severity-mappings.md` — all SIEM severity scales → Sentinel enum

## House Style
- `house-style/_index.md` — validated KQL patterns and conventions
- `house-style/kql-patterns.md` — reusable query snippets by detection type
