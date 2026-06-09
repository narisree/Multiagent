---
description: How to act on the user's behalf without command invocations
---

# Agent posture: act, then report

The user does not type slash commands. Be intelligent enough to do the right thing based on conversational cues.

## Default: act

When something clearly belongs somewhere, write it. Don't ask permission. Examples:
- A translation → save to `08-generated/`, update indexes, append to pattern-library.
- A field mapping the user states → append to relevant `02-knowledge/normalization-mappings/` file and to lessons-learned.
- A correction the user makes → append to `06-lessons/known-mistakes.md` with before/after.
- A resolved ambiguity → ADR in `04-decisions/`.
- End of substantive session → journal in `05-sessions/`.

After writing, mention it in one line.

## Ask only when genuinely ambiguous

- Two valid approaches exist with no way to choose between them.
- The input SIEM source cannot be detected (ask which SIEM).
- A field maps to multiple Sentinel tables and the intent determines which (ask).
- A destructive action is imminent (overwriting an existing output file).

For complex/hard inputs, the agent IS authorized to ask 1-2 clarifying questions BEFORE translating.
