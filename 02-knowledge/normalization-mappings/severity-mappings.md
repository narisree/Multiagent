# Severity Scale Mappings → Sentinel

Sentinel accepts exactly four severity values: `High`, `Medium`, `Low`, `Informational`.

---

## ArcSight / CEF Severity → Sentinel

CEF uses 0-10 (integer) or word values.

| CEF Severity (int) | CEF Severity (word) | Sentinel Severity |
|---|---|---|
| 9-10 | Very-High | High |
| 7-8 | High | High |
| 5-6 | Medium | Medium |
| 3-4 | Low | Low |
| 1-2 | Very-Low | Informational |
| 0 | Unknown | Informational |

ArcSight ESM Manager Severity (0-10, continuous):
- ≥ 8: High
- 5-7: Medium
- 2-4: Low
- < 2: Informational

---

## QRadar Severity → Sentinel

QRadar uses **Magnitude** (0-10) and **Severity** (0-10 or Low/Medium/High).

| QRadar Magnitude | Sentinel Severity |
|---|---|
| 9-10 | High |
| 7-8 | High |
| 5-6 | Medium |
| 3-4 | Low |
| 0-2 | Informational |

| QRadar Severity (word) | Sentinel Severity |
|---|---|
| High | High |
| Medium | Medium |
| Low | Low |
| Info | Informational |
| Unknown | Informational |

QRadar `CREDIBILITY` and `RELEVANCE` (0-10 each) influence Magnitude but don't map directly.

---

## LogRhythm Severity → Sentinel

LogRhythm uses Risk Rating (0-100) and Severity (1-10 or Critical/High/Medium/Low/Informational).

| LR Severity (1-10) | LR Severity (word) | Sentinel Severity |
|---|---|---|
| 9-10 | Critical | High |
| 7-8 | High | High |
| 5-6 | Medium | Medium |
| 3-4 | Low | Low |
| 1-2 | Informational | Informational |

LogRhythm Risk Rating (0-100):
- 75-100: High
- 50-74: Medium
- 25-49: Low
- 0-24: Informational

---

## Splunk CIM Severity → Sentinel

| Splunk Severity | Sentinel Severity |
|---|---|
| critical | High |
| high | High |
| medium | Medium |
| low | Low |
| informational | Informational |
| unknown | Informational |

---

## Generic Numeric Severity → Sentinel

For unknown SIEMs with numeric severity scales:

| Scale | High | Medium | Low | Informational |
|---|---|---|---|---|
| 1-10 | ≥8 | 5-7 | 2-4 | ≤1 |
| 1-5 | 5 | 3-4 | 2 | 1 |
| 0-100 | ≥75 | 50-74 | 25-49 | <25 |
| Critical/High/Medium/Low | Critical→High | Medium | Low | Low/Info |

---

## KQL severity mapping snippet

```kql
// For numeric severity (e.g., CEF 0-10)
| extend SentinelSeverity = case(
    toint(LogSeverity) >= 8, "High",
    toint(LogSeverity) >= 5, "Medium",
    toint(LogSeverity) >= 2, "Low",
    "Informational")

// For word severity
| extend SentinelSeverity = case(
    tolower(Severity) in ("critical", "high", "very-high"), "High",
    tolower(Severity) == "medium",                          "Medium",
    tolower(Severity) in ("low", "very-low"),               "Low",
    "Informational")
```

---

## Rule: when severity is ambiguous

If the source rule does not specify severity:
1. Check the detection category — brute force, ransomware, C2 → **High**.
2. Check event volume expectations — high-frequency informational events → **Low/Informational**.
3. Default to **Medium** if unsure — flag as inference in confidence breakdown.
