# Portfolio and technical ownership

**Harley Katt · GitHub DovahDrog**

Created/developed under Harley Katt's direction with **AI-assisted implementation**. This attribution covers direction and the portfolio project; it does not assert sole unaided authorship, an employment credential, certification, paid client, production adoption or a deployment endorsement.

## What a reviewer can inspect

- **Tool orchestration:** Typed FastAPI request/response contracts and nine meaningful tool routes, separating local records from optional provider effects.
- **Safety boundaries:** Fail-closed secret authentication, strict inputs, explicit permission flags/evidence, cross-channel suppression, safe links and disabled live integrations.
- **Provider adaptation:** GHL/LeadConnector contact lookup/create, exact-recipient checks, HTML escaping, gated message submission and error/result handling. Mocked HTTP fixtures test the real adapter path rather than replacing routes with canned success.
- **API contracts:** Standalone JSON contracts, runtime model parity tests, recursive OpenAPI reference conversion, a secret-free Retell-oriented configuration manifest and a generic prompt template.
- **Verification:** Real local endpoint/storage tests and a synthetic in-process smoke that exercises all tools plus export generation, while actively forbidding external networking.
- **Privacy engineering:** Sanitized source lineage, removal of private configuration and unrelated application coupling, metadata-only event/intent logging and explicit handling of private runtime data.

These are implemented artifacts and observable behaviors, not claims about business outcomes or ownership of hosted STT/LLM/TTS/carrier technology. The project's technical ownership is expressed through the boundaries, contracts, tradeoffs and verification supplied for review.

## What the demonstration proves

The canonical offline suite and smoke exercise the staged standalone backend. The local smoke checks authentication, consent rejection, example slots, logged-only messages, safe-link rejection, an explicitly synthetic audit fixture, an operator-review intent, cross-channel opt-out and local manifest generation.

Adapter success/error tests use labeled fixtures at the HTTP transport boundary. They prove request construction and local response handling **only**. They do not prove a real provider accepted an API call, a contact existed, a recipient received anything or a carrier connected a call.

The locally exercised dependency environment used Python 3.11.16, FastAPI 0.133.1, Pydantic 2.13.4, HTTPX 0.28.1, Uvicorn 0.41.0 and jsonschema 4.26.0. Pytest was not installed in that environment; the stdlib unittest runner was actually used. Dependency installation into a fresh environment and online dependency vulnerability checks were not performed during this offline preparation.

## Remaining work, not hidden claims

A deployed system still needs provider-specific tool envelope mapping, a reviewed hosted-agent configuration, a real calendar/transfer implementation if desired, transactional/private persistence, consent/suppression synchronization, replay/rate controls, idempotent delivery reconciliation and live sandbox validation. No latency, reliability, conversion, revenue, cost-saving or production-readiness claim is made.

[Architecture](ARCHITECTURE.md) explains implementation tradeoffs. [Security](SECURITY.md) identifies risks. [Provenance](PROVENANCE.md) explains the source and sanitization boundary.
