# Confidence Framework — Sentinel KQL Translation Agent

## Why per-element

A single confidence number is empirically miscalibrated upward in LLMs. Decomposing into independent elements with explicit failure-mode enumeration is more reliable AND more useful — the user knows exactly where to focus testing.

## The 7 confidence elements

| # | Element | What it measures |
|---|---|---|
| 1 | **KQL Syntax** | Valid operators, correct function signatures, balanced parens/brackets, no unsupported constructs |
| 2 | **Table/Schema Mapping** | Correct Sentinel table chosen, all referenced fields exist in that table, no typos |
| 3 | **Logic Fidelity** | Detection logic faithfully reproduces source SIEM intent — thresholds, conditions, correlations |
| 4 | **Field Mapping Accuracy** | Legacy source fields correctly translated to Sentinel equivalents per normalization tables |
| 5 | **Sentinel Metadata** | severity, tactics, techniques, queryFrequency, queryPeriod, triggerOperator, triggerThreshold all valid |
| 6 | **Entity Mapping** | Correct entityType and fieldMappings present for all identifiable entities (Account, IP, Host, etc.) |
| 7 | **Query Performance** | Time-bounded query, no full table scans, efficient joins with pre-filters |

## Scoring rubric

- **100%** — every claim sourced, pattern previously validated, no inference.
- **95%** — sourced, pattern in corpus, minor variation from precedent.
- **85-90%** — sourced, single element involves inference or no exact precedent.
- **70-80%** — multiple inferences or one critical element untested/ambiguous.
- **<70%** — significant inference, novel territory; recommend clarifying questions.

**Overall = MIN of elements**, not average.

## When confidence drops below threshold

- **Overall < 80%:** offer 1-2 clarifying questions but still deliver.
- **Overall < 60%:** strongly recommend clarifying before deploying. Still deliver.
- Never refuse delivery on confidence grounds. Advisory only.

## Anti-overconfidence discipline

For every element scoring 95%+, enumerate at least one specific failure mode. If you can't, drop the score 5-10 points.

## Example breakdown (filled in)

```
**Confidence breakdown:**
- KQL Syntax: 95% — regex pattern translated but not tested; matches regex may have escaping differences
- Table/Schema Mapping: 98% — SecurityEvent confirmed, all fields validated against schema
- Logic Fidelity: 88% — threshold logic preserved; time window inferred from source (not explicit)
- Field Mapping Accuracy: 90% — all QRadar fields mapped via normalization table; 1 field inferred
- Sentinel Metadata: 97% — severity/tactics from source tagging; queryFrequency matched to source interval
- Entity Mapping: 85% — Account and IP mapped; Host entity absent in source, inferred from Computer field
- Query Performance: 92% — time-filtered, but join on SecurityEvent without inner pre-filter
- **Overall: 85% (governed by Logic Fidelity)**
```
