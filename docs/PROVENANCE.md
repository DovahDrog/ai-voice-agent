# Provenance and attribution

## Attribution

Created/developed under **Harley Katt's direction with AI-assisted implementation**. GitHub identity: **DovahDrog**. This public portfolio export does not claim sole unaided authorship, fabricated clients, usage, endorsements, credentials, original commit dates or business performance.

## Source lineage

Prepared from explicitly supplied immutable source snapshots:

| Snapshot | Retained lineage in this export |
| --- | --- |
| `voice_tools.py` | FastAPI models/routes, local JSONL orchestration, deterministic calendar, caller/outcome/audit workflow, messaging composition, permission/suppression controls and GHL/LeadConnector adapters |
| `tool_schemas.json` | Named tool routes and request/response reference organization, sanitized and aligned with the standalone models |
| `export_retell_manifest.py` | Local loading/writing, recursive reference rewriting, OpenAPI operation generation, Retell-oriented manifest assembly and CLI |
| Voice-related portions of `test_tools.py` | Endpoint, adapter, suppression, authentication, contract and export test scenarios; rewritten as isolated offline unittest coverage with synthetic data |
| `original_pyproject.toml` | Python/FastAPI/Pydantic/Uvicorn dependency structure, adapted into standalone packaging metadata |

The original private application was **not imported or executed**, and its repository history, live databases, credentials, runtime logs and account exports were not used. Only the staged standalone code was exercised. This is a source-derived implementation, not a fabricated provider demo or a replacement toy.

## Sanitization and hardening

- Removed unrelated application imports, routes and helpers so the backend is independently runnable.
- Replaced company branding, private attendees, personal routing, domains, outbound footer and account defaults with generic `VOICE_` configuration, `X-Voice-Webhook-Secret`, `operator`/`team` and `transfer_to_operator`.
- Removed financial/proprietary caller fields and any real deployment/contact/location defaults.
- Changed unauthenticated tool behavior to fail-closed 503/401, added strict request/identifier/phone validation and made demo/live gates explicit.
- Added permission confirmation to all messaging intents; retained local suppression and extended it across known email/contact IDs.
- Hardened link validation, recipient matching, provider configuration/transport/error boundaries and minimized event/intent/outcome/escalation logs.
- Updated contracts/export safety metadata to reflect disabled delivery and the actual provider/demo boundary.
- Added a synthetic smoke, generic example prompt and documentation of limitations. New example data and fixture responses are synthetic/local; none is represented as production evidence.

## Limits and rights

Calendar slots, booking messages, operator transfer, generic snapshot text and local audit fixtures are explicitly deterministic/local placeholders. Optional provider adapters are real code paths but only locally mock-tested; hosted speech, real delivery, public deployment and provider import are unverified.

No original Git history or invented development timestamps are included. No permissive license has been added because licensing was not requested. This document records provenance/attribution, not a grant of reuse rights or an independent legal determination about publication permissions.
