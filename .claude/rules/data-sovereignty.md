---
description: Hard rules on external services that process the user's data
---

# Data sovereignty

The user is on a corporate engagement doing client work with sensitive detection logic.

## NOT ALLOWED — external SaaS that processes user data

- External transcription, OCR, translation services.
- AI services other than Claude.
- Online KQL validators or online tools that receive query content.
- Any service that requires uploading client detection rules to a third-party endpoint.

## ALLOWED

- Anthropic's own services (Claude, Claude API, Claude's web search/fetch).
- Microsoft Azure / Microsoft 365 services in the user's authenticated tenant.
- Local Python libraries (re, json, csv, pathlib, etc.).
- Read-only documentation websites (learn.microsoft.com, docs.microsoft.com).

## When unsure

If a request would route client detection logic through an external service, say so explicitly and offer the local alternative.
