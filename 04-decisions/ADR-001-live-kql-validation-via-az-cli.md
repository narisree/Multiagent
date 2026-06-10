# ADR-001 — Live KQL validation via az CLI against the user's own tenant

**Date:** 2026-06-10
**Status:** accepted
**Context:** The KQL linter (`.claude/skills/kql-sentinel-lint/lint.py`) is regex-based static analysis. It cannot catch real Kusto syntax errors or unresolvable tables/columns. The data-sovereignty rule (`.claude/rules/data-sovereignty.md`) forbids sending client detection logic to online KQL validators or any third-party service; only Azure services in the user's authenticated tenant are allowed. The agent's sandbox may not have `az` or tenant credentials, so live validation cannot be mandatory.

**Decision:** Add `validate.py` next to `lint.py`, surfaced via a `--live` flag on `lint.py`. It runs the rule's query (with `| take 0` appended so no data rows return) through `az monitor log-analytics query --workspace <guid>` using the user's existing `az login` session. Workspace GUID comes from `SENTINEL_VALIDATE_WORKSPACE_ID` or an untracked `validate-config.local.json`. Missing prerequisites, timeouts, and throttling produce `status: skipped` — never a failure. Exit code is always 0 (advisory gates never block).

**Rationale:**
- az CLI is already part of the user's documented runtime (profile.md) and reuses existing auth — zero new dependencies (stdlib `subprocess`/`shutil`/`json` only).
- Query text goes only to the user's authenticated tenant — compliant with data sovereignty.
- Rejected: Azure Monitor Query REST API (re-implements what az already does), `azure-monitor-query` Python SDK (new pip dependency, no capability gain), Microsoft Kusto.Language (.NET) — the only true *offline* parser, but requires a .NET runtime, which `.claude/rules/library-judgment.md` classifies as a native binary needing explicit user approval. Revisit if the user wants offline validation.

**Consequences:** Quality gate Step 8 gains a third mode (`static+live`). New lint codes `E.KQL_LIVE_SYNTAX` and `E.KQL_LIVE_SEMANTIC`. A live semantic failure may mean the validation workspace lacks a table the client workspace has — findings are worded to demand verification, not assert translation error. `.gitignore` excludes `validate-config.local.json` because workspace GUIDs are client engagement data.
