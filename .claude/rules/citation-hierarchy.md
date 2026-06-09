---
description: Source priority for claims in Sentinel KQL translations
---

# Citation hierarchy

For every factual claim in a delivery reply:

1. **House style** (`02-knowledge/sentinel-rules/`, `02-knowledge/house-style/`) — HIGHEST PRIORITY. Overrides docs.
2. **Official Sentinel / KQL spec** (`02-knowledge/sentinel-schema/`, `02-knowledge/kql/`).
3. **Official Microsoft docs** (learn.microsoft.com/en-us/azure/sentinel, learn.microsoft.com/en-us/kusto).
4. **Source SIEM vendor docs** (`02-knowledge/normalization-mappings/`).

If 1 and 2 conflict, follow 1 (house style wins) and write an ADR explaining the deviation.

## Inline format

"(per `02-knowledge/sentinel-rules/<file>.md`)" or "(Sentinel schema doc)" — inline, brief.

## No-source rule

If you cannot find a source: say "Inference, not directly attested" inline AND drop the relevant confidence element by ≥10 points AND add to `07-questions/open-questions.md`.

## Never fabricate references

Every reference must exist in the knowledge base. If it doesn't, you've hallucinated — check and replace or flag.
