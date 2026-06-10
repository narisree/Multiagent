# Sentinel KQL Translation Agent — Project Anchor

This folder is a persistent, self-improving, self-evaluating knowledge base for translating legacy SIEM use cases (ArcSight, QRadar, LogRhythm, Splunk, and others) into Microsoft Sentinel Analytics Rules with KQL queries.

Single-user. Version-controlled. Acts on the user's behalf without command invocations. Advisory gates only — never blocks delivery.

## Always read at session start

@profile.md
@01-project/overview.md
@01-project/kql-translation-workflow.md
@01-project/confidence-framework.md

## Operating rules (always apply)

@.claude/rules/agent-posture.md
@.claude/rules/data-sovereignty.md
@.claude/rules/library-judgment.md
@.claude/rules/confidence-discipline.md
@.claude/rules/citation-hierarchy.md
@.claude/rules/self-improvement.md
@.claude/rules/session-discipline.md
@.claude/rules/advisory-gates.md

## Always-loaded knowledge

@02-knowledge/sentinel-schema/analytics-rule-schema.md
@02-knowledge/sentinel-schema/entity-mappings.md
@02-knowledge/sentinel-schema/asim/_index.md
@02-knowledge/house-style/_index.md
@06-lessons/lessons-learned.md
@06-lessons/known-mistakes.md

## Folder map

- `02-knowledge/kql/` — KQL operators, functions, time syntax, query patterns.
- `02-knowledge/sentinel-schema/` — Sentinel table schemas, rule schema, entity mappings, MITRE tactics.
- `02-knowledge/sentinel-rules/` — existing translated rules (HOUSE STYLE OVERRIDES DOCS).
- `02-knowledge/normalization-mappings/` — ArcSight/QRadar/LogRhythm/Splunk → Sentinel field maps.
- `02-knowledge/house-style/` — patterns extracted from existing translated rules.
- `04-decisions/` — ADRs for translation decisions and design choices.
- `05-sessions/` — session journals, auto-written.
- `06-lessons/` — append-only learning; consulted before EVERY translation.
- `07-questions/` — open questions tracked across sessions.
- `08-generated/` — all translated Sentinel rules, one folder per batch.

## At the start of every session

1. Read profile, project files, all rules (loaded via @import above).
2. Read the 3 most recent entries in `05-sessions/`.
3. Skim `07-questions/open-questions.md`.
4. Briefly state what was loaded plus any unresolved questions worth flagging.

## When the user provides legacy SIEM alerts

Follow `01-project/kql-translation-workflow.md` exactly. The 8-step pipeline is non-negotiable. Skipping the "consult precedents" step is the failure mode that costs the most.

## Bulk processing mode

When the user provides a JSON or CSV file with multiple alerts:
1. Parse and count total alerts.
2. Classify each by source SIEM, detection category, and complexity.
3. Report the batch summary (counts by SIEM, complexity breakdown) before translating.
4. Translate in groups of 10. Deliver each group with confidence breakdown.
5. After all groups: produce batch summary report with overall accuracy assessment.

## Quality gates (advisory, never blocking)

After each translation:
1. Run KQL linter (script or cognitive). State which mode ran.
2. Invoke blind critic for medium/hard inputs.
3. Produce structured confidence breakdown per `01-project/confidence-framework.md`.
4. Deliver: translated rule + ARM template + confidence breakdown + fix-list.

## Self-improvement (no permission asked)

When the user corrects a translation, points out a mistake, or expresses a preference:
1. Append to `06-lessons/lessons-learned.md` with stable ID, provenance, and applicability tags.
2. If correction supersedes a knowledge file, update that file and write an ADR.
3. If the same correction appears 2+ times, propose elevating to `02-knowledge/house-style/`.
4. Mention what was captured in one sentence.

## Session end

When work has been substantive: write `05-sessions/YYYY-MM-DD-short-topic.md`, update relevant `_index.md` files, write any ADRs. One sentence about what was written. No permission asked.
