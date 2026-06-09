# House Style Index — Validated KQL Translation Patterns

These patterns are extracted from tested Sentinel translations and represent the team's conventions. **House style overrides docs when they conflict.**

---

## Core conventions

1. **Always start KQL with `// Source: <SIEM> — <original rule name>`**
2. **Always store time window as `let lookback = ago(Xh);`** — never hardcode ago() inline
3. **Always store thresholds as `let threshold = N;`** — never hardcode in where clause
4. **Always end with `| project`** — limit columns to what's needed for the alert
5. **Always specify `join kind=`** — never rely on default innerunique
6. **Always use `tolower()` for case-insensitive string comparisons**
7. **Always include entity mappings** for Account, IP, Host when present in query output

---

## Approved query skeletons

See `kql-patterns.md` for full skeletons by detection type:
- Brute force / failed authentication
- Privilege escalation (admin group membership)
- Lateral movement / pass-the-hash
- Process execution / command line
- Network anomaly / beaconing
- Data exfiltration (volume)
- Threat intel lookup
- Scheduled task / service creation
- Account creation / modification
- Log clearing / defense evasion

---

## ARM template conventions

- `displayName`: `"<Source>: <Description>"` — prepend source SIEM name when migrating
- `description`: Always fill in. Include source rule name and SIEM.
- `suppressionDuration`: Match `queryFrequency` value.
- `createIncident`: Always `true` for production rules.
- `groupingConfiguration.enabled`: `false` unless explicit grouping required.

---

## Confidence floor by translation type

| Translation type | Minimum first-pass confidence |
|---|---|
| Direct 1:1 field map to SecurityEvent | 90% |
| CEF/CommonSecurityLog with custom fields | 80% |
| QRadar AQL with INCIDR / regex | 85% |
| Multi-table correlation | 75% |
| Novel SIEM or undocumented format | 70% |
