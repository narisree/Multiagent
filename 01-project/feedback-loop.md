# Feedback Loop

The agent does not have direct access to Microsoft Sentinel. All testing is manual via Azure Portal or CLI.

## How feedback flows

1. Agent delivers translation per workflow Step 8.
2. User tests in Sentinel Analytics Rules editor or deploys via ARM.
3. User copies any errors or failed test results back to the agent.
4. Agent ingests per this protocol.

## Ingestion protocol

When the user pastes Sentinel validation errors or runtime results:

1. **Classify each error** by severity (syntax error, schema validation failure, query logic error, field not found, etc.).
2. **Map to lint code** — each error maps to one of E.*/C.*/S.*/F.*/H.*/R.* codes in `SKILL.md`. If unmapped → lint rubric is incomplete; add a new code.
3. **Diagnose root cause** — the editor error is the symptom; the lesson is the cause (wrong field? wrong operator? wrong table?).
4. **Fix the translation.**
5. **Capture the lesson** — append to `06-lessons/lessons-learned.md` with full provenance.
6. **Update the lint rubric** — if Sentinel caught something the linter didn't, add the check. Mandatory.
7. **Re-deliver** with note: "Fixed [X]. Lesson L-NNN captured. Linter updated."

## Common Sentinel validation error patterns

| Error | Root cause | Fix |
|---|---|---|
| "Field 'X' does not exist in table 'Y'" | Wrong table or misspelled field | Check `02-knowledge/sentinel-schema/tables-reference.md` |
| "Invalid severity value" | Severity not in enum | Use High/Medium/Low/Informational only |
| "Invalid ISO 8601 duration" | queryFrequency/Period format wrong | Use PT1H not 1h |
| "entityType 'X' is not supported" | Wrong entity type string | Check `02-knowledge/sentinel-schema/entity-mappings.md` |
| "Syntax error near 'X'" | KQL operator misspelling or wrong arg | Check `02-knowledge/kql/operators-reference.md` |
| "join must specify a 'kind'" | Implicit join kind | Add `kind=innerunique` or explicit kind |

## Anti-regression

If the same error appears 2+ times across sessions, elevate to a permanent rule in `02-knowledge/house-style/`.
