# Lessons Learned — Sentinel KQL Translation Agent

Append-only. Consulted before EVERY translation. Never delete entries — mark as superseded or deprecated instead.

---

## L-2026-06-09-001 — Always specify join kind explicitly

**Status:** active
**Applies to:** all
**Provenance:** doc-citation
**Context:** Any query using `join`.
**Mistake / discovery:** KQL `join` defaults to `innerunique` which silently deduplicates the left side. This causes missed alerts when multiple matching rows exist (e.g., multiple failed logins from the same account).
**Generalized rule:** Always write `join kind=inner` (or the appropriate kind). Never rely on the default.
**Source:** `02-knowledge/kql/operators-reference.md`
**Promote to house-style?** Yes — already in `house-style/_index.md`

---

## L-2026-06-09-002 — queryPeriod must be ≥ queryFrequency

**Status:** active
**Applies to:** all — Sentinel metadata
**Provenance:** doc-citation
**Context:** ARM template `queryFrequency` and `queryPeriod` fields.
**Mistake / discovery:** Setting queryPeriod < queryFrequency causes Sentinel to reject the rule at save time.
**Generalized rule:** queryPeriod ≥ queryFrequency. Common pair: both PT1H for standard rules.
**Source:** `02-knowledge/sentinel-schema/analytics-rule-schema.md`
**Promote to house-style?** Yes

---

## L-2026-06-09-003 — Sentinel severity is an enum, not a number

**Status:** active
**Applies to:** all — Sentinel metadata
**Provenance:** doc-citation
**Context:** Translating source SIEM severity (numeric 0-10) to Sentinel.
**Mistake / discovery:** Sentinel only accepts "High", "Medium", "Low", "Informational". Passing a number or "Critical" causes deployment failure.
**Generalized rule:** Always map source severity to one of the four Sentinel enum values. Use `severity-mappings.md`.
**Source:** `02-knowledge/normalization-mappings/severity-mappings.md`
**Promote to house-style?** Yes

---

## L-2026-06-09-004 — SecurityEvent table not SecurityEvents

**Status:** active
**Applies to:** all — Windows Security Events
**Provenance:** doc-citation
**Context:** Windows Security Event queries.
**Mistake / discovery:** Common typo: `SecurityEvents` (plural) does not exist. The correct table is `SecurityEvent` (singular).
**Generalized rule:** Table name is `SecurityEvent`, not `SecurityEvents`.
**Source:** `02-knowledge/sentinel-schema/tables-reference.md`
**Promote to house-style?** No — linter catches this (E.TABLE_NOT_EXIST)

---

## L-2026-06-09-005 — ISO 8601 durations in ARM templates, not KQL timespans

**Status:** active
**Applies to:** all — ARM template generation
**Provenance:** doc-citation
**Context:** Filling in `queryFrequency` and `queryPeriod` in ARM templates.
**Mistake / discovery:** KQL uses `1h`, `30m`, `7d`. ARM templates require ISO 8601: `PT1H`, `PT30M`, `P7D`. Using KQL timespan literals causes deployment errors.
**Generalized rule:** In ARM template fields (queryFrequency, queryPeriod, suppressionDuration), always use ISO 8601 format.
**Source:** `02-knowledge/kql/time-operators.md`
**Promote to house-style?** Yes

---

## L-2026-06-09-006 — CEF custom fields require label resolution

**Status:** active
**Applies to:** ArcSight
**Provenance:** doc-citation
**Context:** ArcSight CEF events with cs1–cs6 and cn1–cn3 fields.
**Mistake / discovery:** Custom string fields (cs1-cs6) have no fixed meaning. The `cs1Label` field names the content. Must always check the label to determine what the custom field contains before mapping.
**Generalized rule:** Never map cs1 to a Sentinel field without first reading cs1Label. Add a comment: `// cs1 (label: ProcessName) → ProcessName`.
**Source:** `02-knowledge/normalization-mappings/arcsight-to-sentinel.md`
**Promote to house-style?** Yes

---

## L-2026-06-09-007 — Use TimeGenerated not ReceiptTime for time filters

**Status:** active
**Applies to:** all
**Provenance:** doc-citation
**Context:** CEF/Syslog events with both TimeGenerated and ReceiptTime.
**Mistake / discovery:** `ReceiptTime` is the device receipt time from the `rt` CEF field. `TimeGenerated` is Sentinel's ingest timestamp. Performance indexes are on `TimeGenerated` — always filter on it.
**Generalized rule:** Time filters always use `TimeGenerated`. Reference `ReceiptTime` only for event-time logic (rare).
**Source:** `02-knowledge/normalization-mappings/arcsight-to-sentinel.md`
**Promote to house-style?** Yes

---

## L-2026-06-09-008 — Machine accounts end with $ — exclude from user detections

**Status:** active
**Applies to:** SecurityEvent
**Provenance:** precedent-in-corpus
**Context:** Authentication detection rules targeting user accounts.
**Mistake / discovery:** Windows machine accounts end with `$` (e.g., `WORKSTATION$`). Authentication detections for users should exclude them or generate false positives.
**Generalized rule:** Add `| where AccountName !endswith "$"` in user-focused SecurityEvent queries.
**Source:** `02-knowledge/house-style/kql-patterns.md` (pattern 5)
**Promote to house-style?** Yes
