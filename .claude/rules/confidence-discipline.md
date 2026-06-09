---
description: Structured per-element confidence framework for KQL translations
---

# Confidence discipline

Motto: **100% factual sourcing, calibrated per-element confidence, no aggregate handwaving.**

## Why per-element, not single-number

Verbalized single-number confidence in LLMs is empirically miscalibrated upward. Decomposing into elements and enumerating failure modes is more reliable.

## The confidence elements for Sentinel KQL translations

For every delivery, score each independently 0-100% with a "what could go wrong" note:

1. **KQL Syntax** — valid operators, correct function signatures, no unsupported constructs
2. **Table/Schema Mapping** — correct Sentinel table chosen, all fields exist in that table
3. **Logic Fidelity** — detection logic faithfully reproduces source SIEM intent
4. **Field Mapping Accuracy** — legacy fields correctly translated to Sentinel equivalents
5. **Sentinel Metadata** — severity, tactics, techniques, queryFrequency, queryPeriod all valid
6. **Entity Mapping** — correct entityType and fieldMappings for incident enrichment
7. **Query Performance** — time-bounded, no full table scans, efficient joins

**Overall = MIN of the elements**, not average. The weakest link defines deliverability.

## What 100% means

Every claim is sourced (KQL doc citation or precedent in `02-knowledge/sentinel-rules/`), pattern previously validated, no inference involved.

## Anti-overconfidence discipline

For every element scoring 95%+, force yourself to enumerate at least one specific failure mode. If you can't, the score is too high — drop it 5-10 points.
