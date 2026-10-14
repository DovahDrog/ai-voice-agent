# AI Voice Agent — Tool Backend

**A Python/FastAPI backend that turns a hosted voice assistant's tool calls into validated local workflows and explicitly gated follow-up messages.** It demonstrates the application layer behind an AI voice experience: contracts, caller records, permission checks, suppression, provider adapters, and truthful tool results.

Created/developed under **Harley Katt's direction with AI-assisted implementation**. GitHub identity: **DovahDrog**. See [provenance](docs/PROVENANCE.md) and [technical ownership](docs/PORTFOLIO.md).

## What this is — and is not

This repository supplies **HTTP tools**, not a streaming speech engine. A hosted service such as **Retell or Vapi** would supply STT, the LLM, TTS, audio sessions and carrier connectivity. The repository does not place calls, stream audio, run a speech model, or include a deployed agent.

The bundled prompt is a **synthetic example template**. The Retell-oriented manifest is a **local configuration/import aid**, not evidence of a successful provider import. Hosted-provider configuration, tool-call envelope mapping, real delivery and deployment have **not** been validated here.

## Feature walkthrough

Every named tool is a protected `POST /tools/<name>` endpoint.

| Tool | Implemented behavior | Boundary |
| --- | --- | --- |
| `create_prospect` | Stores caller-provided fields in a local JSONL record; generates an opaque ID | No CRM sync |
| `check_calendar` | Produces three next-day UTC example slots | Deterministic placeholder; ignores `date_range`, reserves nothing |
| `send_lead_leak_snapshot_sms` | Composes a short follow-up snapshot; checks permission, suppression and links; optionally uses GHL/LeadConnector | External SMS disabled by default |
| `send_lead_leak_snapshot_email` | Composes escaped HTML follow-up; same safety gates and optional adapter | External email disabled by default |
| `send_sms_close_packet` | Validates agreement/payment/onboarding links and gates optional SMS delivery | Requires a verified matching provider contact; no payment processing |
| `send_sms_booking_link` | Records a permission-gated booking-message intent | No delivery adapter; always `sent=false` |
| `transfer_to_operator` | Records an operator-review request | No phone transfer; `actual_transfer=false` |
| `log_call_outcome` | Records a decision; `do_not_call` suppresses a known prospect across phone, email and contact ID | Local suppression, not a provider-wide opt-out synchronization service |
| `look_up_audit` | Reads an operator-supplied local JSON audit, if present | No research, scraping, scoring or generated audit claims |

`GET /health` is a public health check. `POST /retell/webhook` is **unsigned, untrusted, metadata-only telemetry**: it never sends messages, creates contacts or changes suppression. A protected legacy audit GET route is also retained.

## Architecture

```text
Hosted speech / LLM / carrier (not included)
          │ root-level JSON tool arguments + secret header
          ▼
FastAPI routes → Pydantic contracts → permission / DNC / URL / config guards
          ├─ local JSONL records, local audit lookup, example calendar
          └─ explicitly enabled GHL/LeadConnector adapter
                    → contact lookup/create → recipient verification → API submission

Unsigned event callbacks → bounded metadata log only (no action path)
Local contracts → export script → OpenAPI + Retell-oriented manifest
```

The original substantial orchestration and messaging-adapter architecture is retained and sanitized, rather than replaced by canned successful provider results. Details and design tradeoffs: [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Setup

Python **3.11+**. From the repository root, create your own environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
```

Installing dependencies may need network access; **running the demo does not**. The setup command is for a fresh user environment, not an instruction to modify a shared or production interpreter. Direct dependencies are pinned to the public snapshot's exercised versions, including the HTTP test client and schema generator; this is not a hash-locked transitive environment. See [verification](docs/VERIFICATION.md) for fresh-install results and [PORTFOLIO.md](docs/PORTFOLIO.md) for implementation evidence.

`.env.example` documents the environment variables. The application **does not automatically load `.env` files**. Set only the values you need in the server process.

## Run the offline walkthrough first

```sh
PYTHONDONTWRITEBYTECODE=1 python -B scripts/smoke_demo.py
```

The smoke script clears ambient environment values, generates a fresh ephemeral secret, freezes an explicitly synthetic example clock, calls all nine tools **in-process**, verifies consent rejection and cross-channel opt-out, checks metadata logging, and writes both manifests in a temporary directory outside the repository. It actively forbids DNS/socket connections and does not invoke a mocked or real messaging provider.

Its JSON result includes `fixture_classification: "synthetic_local_only"`, `tool_count: 9`, `network_attempts: 0`, `sms_sent: false`, and `email_sent: false` when the checks pass. These are local test results, **not production evidence**. Synthetic runtime files are retained for inspection; choose a new directory with `--work-dir` if you want an explicit location.

## Run the local HTTP server

```sh
export VOICE_TOOLS_SHARED_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export VOICE_DEMO_MODE=true
export VOICE_SMS_DELIVERY_ENABLED=false
export VOICE_EMAIL_DELIVERY_ENABLED=false
export VOICE_CALL_LOG_DIR=runtime
python -m uvicorn voice_tools:app --app-dir src --host 127.0.0.1 --port 8000
```

A missing or shorter-than-32-character secret gives **503** on tools. A missing/wrong `X-Voice-Webhook-Secret` header gives **401** once authentication is configured. Generate a fresh secret; never put its value into source, prompts, screenshots or manifests.

Example local request using only synthetic caller data:

```sh
curl -s http://127.0.0.1:8000/tools/create_prospect \
  -H 'Content-Type: application/json' \
  -H "X-Voice-Webhook-Secret: $VOICE_TOOLS_SHARED_SECRET" \
  --data '{"name":"Synthetic Resident","phone":"+12025550100","email":"synthetic@example.com"}'
```

Interactive API documentation is at the local server's `/docs`. Request bodies are **root-level tool arguments**. Provider-specific Retell/Vapi envelopes are not automatically decoded by this backend; configure argument mapping or add a separately reviewed adapter.

## Test

The canonical suite uses stdlib `unittest` with the real FastAPI `TestClient`; it does not require pytest to be installed:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest discover -s tests -p test_voice_tools.py -v
```

Optional equivalent runner:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -m pytest -p no:cacheprovider tests
```

Tests isolate environment/runtime state, forbid external DNS/socket connections, exercise real routes and local storage, validate schemas/export, and use **explicitly labeled mocked HTTP fixtures only for adapter success/error paths**. No call, SMS or email is sent by the suite.

## Export contracts

This script uses the Python standard library only and makes no network requests:

```sh
python -B scripts/export_retell_manifest.py \
  --base-url https://voice.example.invalid \
  --out-dir build/retell --json
```

It writes `openapi.json` and `retell-tools.json`, validates the HTTPS origin, carries authentication **metadata only**, and marks delivery disabled by default. `example.invalid` is deliberately non-deployable. See `config/agent.example.json` for a generic inbound-only prompt/config template.

## Security and privacy boundaries

- Tools fail closed; demo mode and delivery flags are independent gates. No ambient legacy credential fallbacks exist.
- All message tools require nonempty permission evidence **and** explicit `permission_confirmed=true`. These are assertions from the trusted caller/tool orchestrator, not independently verified legal consent.
- Do-not-contact decisions are checked before delivery. Unknown prospects cannot be falsely acknowledged as suppressed. Corrupt suppression storage fails closed.
- Side-effect links require HTTPS and exact approved hosts; userinfo, nonstandard ports, IP literals, localhost/internal names, malformed hosts and raw whitespace/backslashes are rejected even if allowlisted. Outgoing free-text URLs are checked too.
- Provider requests additionally disable redirects/proxies and reject non-public DNS answers before connecting to the checked address. Live TLS/provider behavior has not been tested.
- Telemetry and outbound intent logs omit recipients, transcripts, message bodies and consent quotations. **Prospect/suppression storage still contains caller-provided personal information**; keep the runtime directory private and out of source control. Authenticated previews/local audit responses can contain caller content.
- No credentials, recordings, real client data, account configuration exports or historical Git metadata are bundled.

[SECURITY.md](docs/SECURITY.md) covers the threat model, optional provider gates, operator responsibilities and remaining limitations. Do not expose this demonstration as a production service without independent security, privacy, consent and provider review. It has no multi-tenant authorization, distributed storage, replay protection, rate limiting, delivery reconciliation or exactly-once/idempotency guarantee.

## Attribution and licensing

Created/developed under **Harley Katt's direction with AI-assisted implementation**; GitHub **DovahDrog**. This is a sanitized portfolio export with honest implementation/provider boundaries. No license grant has been added; publication does not imply permission to reuse the code.
