# Open Questions

Questions that need resolution — tracked across sessions.

---

## Format

```
## Q-YYYY-MM-DD-NNN — <title>

**Status:** open | answered | deferred
**Context:** <which translation or session surfaced this>
**Question:** <the question>
**Answer:** (fill in when resolved)
**ADR:** (link if an ADR was written)
```

---

## Bootstrap questions

## Q-2026-06-09-001 — McAfee/Trellix ESM schema coverage

**Status:** open
**Context:** Bootstrap — known gap in normalization-mappings
**Question:** What are the standard Trellix ESM field names for source IP, username, event category, and severity? Need to populate `normalization-mappings/trellix-to-sentinel.md` when first Trellix rule is encountered.
**Answer:** (pending first Trellix rule)
**ADR:** (none yet)

---

## Q-2026-06-09-002 — RSA NetWitness metadata schema

**Status:** open
**Context:** Bootstrap — known gap in normalization-mappings
**Question:** RSA NetWitness uses meta keys (ip.src, ip.dst, user.name, etc.). What are the most common meta key → Sentinel field mappings?
**Answer:** (pending first NetWitness rule)
**ADR:** (none yet)

---

## Q-2026-06-09-003 — ASIM table vs native table preference

**Status:** open
**Context:** Bootstrap — architectural question
**Question:** For new translations, should we prefer ASIM normalized tables (NetworkSessionEvents, IMDnsEvents) over native tables (CommonSecurityLog, DnsEvents) when the connector supports both?
**Answer:** (pending team decision)
**ADR:** (none yet — create ADR-001 when resolved)
