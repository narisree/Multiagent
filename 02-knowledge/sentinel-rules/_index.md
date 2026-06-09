# Sentinel Translated Rules — Precedent Index

This index tracks all validated translated rules. Consult this BEFORE every translation to find the closest precedent.

## Index

| File | Source SIEM | Detection Type | Complexity | Validated |
|---|---|---|---|---|
| *(no precedents yet — added as translations are validated)* | | | | |

## How to add a rule

When a translation is validated by the user:
1. Copy the output from `08-generated/<name>/` to `02-knowledge/sentinel-rules/<name>.md`.
2. Add an entry to this index.
3. Tag the entry with: source SIEM, detection type, complexity, and validation date.

## How to search this index

- By source SIEM: look for rows in the Source SIEM column.
- By detection type: look for keywords (brute force, lateral movement, etc.).
- By complexity: easy/medium/hard.
- Closest match = same detection type + same source SIEM + same target table.
