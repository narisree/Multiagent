---
description: Capture lessons without being asked; consolidate periodically
---

# Self-improvement loop

## Capture triggers

When ANY of these happen, capture immediately:
1. The user corrects a translation I generated.
2. The user explains why house style differs from docs.
3. I encounter a field mapping error I haven't seen before.
4. I make an inference that turns out wrong.
5. The user states a durable preference ("always do X going forward").
6. The Sentinel editor returns a validation error I haven't catalogued.
7. A KQL query fails with a runtime error.

## Lesson format

Append to `06-lessons/lessons-learned.md`:

```
## L-YYYY-MM-DD-NNN — <one-line title>

**Status:** active
**Applies to:** <source-siem> | <detection-category> | all
**Provenance:** correction-from-user | doc-citation | precedent-in-corpus | runtime-error | test-iteration
**Context:** what was being translated.
**Mistake / discovery:** what I got wrong or learned.
**Generalized rule:** the rule going forward.
**Source:** <URL or file ref>
**Promote to house-style?** Yes/No
```

Statuses: `active`, `superseded`, `deprecated`.

## Recurring-pattern detection

If a similar lesson appears 2+ times, propose elevating to `02-knowledge/house-style/`. One-line confirmation, then act.

## Pattern library

After every successful translation, append to `06-lessons/pattern-library.md`:

```
### <source-siem> — <detection-type> — <input-shape signature>

**Example input:** <one line>
**KQL snippet:**
```
<the snippet>
```
**When to use:** <one sentence>
**Source output:** 08-generated/<folder>/
**Lesson refs:** L-XXXX-XX-XX-NNN, ...
```

## Consolidation hygiene (quarterly or on user request)

1. List all `active` lessons by `applies-to`.
2. Merge duplicates → mark older as `superseded`.
3. Resolve contradictions → ADR, mark loser as `superseded`.
4. Mark stale lessons as `deprecated`.
5. Append summary to `06-lessons/consolidation-log.md`.

## Non-negotiable

I will not silently re-make the same mistake. If `lessons-learned.md` covers the situation, I follow that rule.
