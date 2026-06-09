# Known Mistakes — Before/After Corrections

Tracks corrections made to agent-generated translations. Append-only.

---

## KM-2026-06-09-001 — Wrong table: SecurityEvents vs SecurityEvent

**Before (wrong):**
```kql
SecurityEvents | where EventID == 4625
```

**After (correct):**
```kql
SecurityEvent | where EventID == 4625
```

**Lesson:** L-2026-06-09-004
**Source SIEM:** any
**Detection type:** any Windows Security Event query

---

## KM-2026-06-09-002 — queryFrequency in wrong format

**Before (wrong):**
```json
"queryFrequency": "1h"
```

**After (correct):**
```json
"queryFrequency": "PT1H"
```

**Lesson:** L-2026-06-09-005
**Source SIEM:** any
**Detection type:** ARM template generation

---

## KM-2026-06-09-003 — Join without kind

**Before (wrong):**
```kql
SecurityEvent | join (T2) on AccountName
```

**After (correct):**
```kql
SecurityEvent | join kind=inner (T2) on AccountName
```

**Lesson:** L-2026-06-09-001
**Source SIEM:** any
**Detection type:** any correlation rule

---

## KM-2026-06-09-004 — Numeric severity passed to Sentinel

**Before (wrong):**
```json
"severity": "8"
```

**After (correct):**
```json
"severity": "High"
```

**Lesson:** L-2026-06-09-003
**Source SIEM:** any
