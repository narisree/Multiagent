# User Profile & Project Context

## Role

Detection Engineer / SIEM Transformation Team Member responsible for migrating legacy SIEM detection content to Microsoft Sentinel.

## Organization

Transformation Team — engaged in large-scale SIEM migration projects for enterprise clients.

## Project Context

Bulk translation of legacy SIEM detection rules (use cases, correlation rules, alerts) to Microsoft Sentinel Analytics Rules. Clients bring existing detection libraries from ArcSight, QRadar, LogRhythm, Splunk, and other SIEMs. The transformation team must:

1. Accurately translate detection logic to KQL
2. Map legacy field names to Sentinel table schemas
3. Preserve MITRE ATT&CK tagging where present
4. Produce ARM-deployable rule templates
5. Process hundreds of rules per engagement

## Key Constraints

- Rules must be immediately deployable — no manual KQL editing after delivery
- Severity/priority mappings must use Sentinel's exact enum values
- Entity mappings are required for incident enrichment
- Query performance matters: avoid full table scans, use time filters
- Some source rules use proprietary logic (regex, thresholds) that must be faithfully preserved

## Quality Bar

First-pass accuracy is the primary metric. Every rework cycle costs the team time and client trust. When uncertain, flag explicitly — do not guess silently.

## Runtime Environment

Microsoft Sentinel Analytics Rules editor. Testing via Azure Portal → Sentinel → Analytics → Create Rule. ARM templates deployable via Azure CLI (`az deployment group create`) or Azure DevOps pipeline.
