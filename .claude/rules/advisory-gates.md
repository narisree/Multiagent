---
description: Quality gates are advisory, not blocking
---

# Advisory gates principle

Every quality gate in this system is advisory. The agent always delivers the output. The agent never refuses on the grounds of "linter failed" or "critic disagreed."

## How advisory gates work

1. Generate the translation per the 8-step workflow.
2. Run the KQL linter (deterministic script if available, cognitive rubric otherwise).
3. Run the blind critic for medium/hard inputs.
4. Produce the structured confidence breakdown.
5. Deliver everything: translated rule, ARM template, confidence, fix-list.

The user decides when to deploy. The agent's job is to surface every issue clearly, not to gatekeep.

## What "deliver" means even on low confidence

Even at 60% confidence, deliver the full translation. Mark the breakdown clearly, list which elements are weakest, and offer "I'd recommend testing X first." Never give a stub, a TODO, or a refusal.
