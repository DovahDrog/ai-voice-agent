# Architecture and decisions

## Scope

The application is the **tool/backend layer** of a voice-agent system. Hosted Retell/Vapi infrastructure would provide speech recognition, an LLM, speech synthesis, audio sessions and a carrier. Nothing in this repository implements those engines or initiates a call. The example configuration is not a provider deployment export.

The backend has one Python module, explicit request/response models, nine protected POST tools, a protected legacy audit GET, public health and a public non-actionable event receiver. `schemas/tools.json` preserves the original route/contract organization, updated to match the standalone Pydantic models. The exporter retains the original recursive reference rewriting, operation generation and manifest assembly.

## Request pipeline

1. FastAPI parses a root-level JSON argument object. Unknown fields, invalid E.164 phone numbers, unsafe record identifiers and oversized strings are rejected.
2. `require_webhook_secret` reads only `VOICE_TOOLS_SHARED_SECRET`. An absent/weak configuration yields 503, while a missing/wrong header yields 401. Byte-based constant-time comparison avoids Unicode comparison errors. `APIKeyHeader` exposes the same contract in the runtime OpenAPI schema.
3. Local tools write/read the explicitly configured runtime directory. The service does not discover files in other projects or accounts.
4. Delivery tools check local phone/email/contact suppression, explicit channel permission, structured links and outgoing-text links. They return truthful blocked results rather than claiming success.
5. Optional GHL/LeadConnector adapters require the independent live gates, a user-supplied token, location, HTTPS API origin and exact API-host allowlist. They resolve/create contacts, verify recipient identity and recognizable provider suppression flags, then submit the message.
6. Successful `sent=true` means an API acceptance with a valid message identifier, **not confirmed end delivery**. No automatic message retry is implemented.

The sequence preserves the source implementation's orchestration and adapter boundaries while closing unsafe defaults, first-unmatched-contact fallback, unchecked links and excessive logging.

## Local persistence

| Store | Purpose | Contents |
| --- | --- | --- |
| `prospects.jsonl` | Caller record and ID lookup | Caller-supplied name/phone/email/optional contact ID/vertical; private runtime data |
| `dnc.jsonl` | Cross-channel suppression | Normalized phone/email and known contact/prospect identifiers |
| `outcomes/*.jsonl` | Call decisions | Outcome and opaque prospect ID; free-text notes are not persisted |
| Messaging intent/sent JSONL | Submission decision metadata | Tool, channel, selected provider, status/reason and optional provider message ID; no recipient/body/evidence |
| `escalations.jsonl` | Human-review intent | Metadata only, not the supplied reason/context or a real transfer |
| `retell_events.jsonl` | Untrusted event telemetry | Timestamp, allowlisted event type, body byte count and `trusted=false` |
| `audits/*.json` | Explicit local input | Operator-supplied JSON; the demo creates a synthetic fixture only |

The storage helper serializes writes within one process and fails closed on corrupt JSONL instead of silently ignoring suppression. Filenames use validated identifiers without lossy sanitization. Responses return relative outcome paths, not host filesystem paths. Runtime data is not included in the public export.

## Deterministic/local placeholders

- Calendar availability is three fixed-hour slots on the next UTC day. The natural-language date range and attendee choice do not drive calendar search. No booking is reserved.
- Booking SMS is an intent logger with no delivery adapter, regardless of environment flags.
- Operator transfer is a logged review request. `escalated=true` means recorded, while `actual_transfer=false` is explicit.
- Snapshot content is caller-provided text or a generic deterministic template. It is not evidence of research or an independently calculated lead-loss audit.
- Audit lookup returns an explicitly supplied JSON file or null. It does no web access or scoring.

## Network boundary

Links are validated but never fetched. Exact host approval is mandatory; subdomain inheritance is deliberately absent. IP literals, localhost/internal aliases, userinfo, nonstandard ports, control/space characters and ambiguous host encodings are rejected. Operators must govern the destinations/content of approved links; URL syntax checks do not establish their legitimacy.

For optional provider HTTPS, proxies and redirects are disabled. DNS is resolved once; any non-public/multicast/reserved address blocks the connection, and the checked address is used for socket connection while normal HTTPS hostname/certificate verification remains in place. Transport, redirect and DNS logic is tested with local mocks, **not a live provider or TLS session**.

## Decisions and tradeoffs

### Retain a single-module backend

**Decision:** Preserve the substantial existing model/helper/route/provider code rather than introduce services or replace it with fake provider output. **Tradeoff:** It is navigable for a portfolio review but not a large-scale modular platform. **Alternative:** Separate provider/storage/security modules. **Rollback:** Independent extraction can follow once behavior remains covered by the suite.

### Fail closed and log-only by default

**Decision:** Require fresh authentication even in demos and require explicit demo-mode opt-out plus channel flags for external operations. **Tradeoff:** Setup has an extra secret-generation step. **Alternative:** Permit unauthenticated local tools; rejected because an accidental public bind would be unsafe. **Rollback:** Disable delivery flags/return to demo mode; do not relax authentication.

### Keep unsigned events non-actionable

**Decision:** Accept small unsigned telemetry only and remove all raw event fields. **Tradeoff:** It cannot support trusted delivery decisions or transcript analysis. **Alternative:** Provider signature/replay verification. **Future change:** Verify signatures before adding any trusted event-processing path; never infer authorization from the existing endpoint.

### Use local JSONL for inspectable demos

**Decision:** Retain append-only local records for simple offline inspection. **Tradeoff:** Linear scans, process-local locking, no transactional ordering across delivery/storage, and no multi-instance coordination. **Alternative:** Transactional datastore, consent/suppression ledger, job queue and idempotency keys. These are needed before serious deployment, not implied by this demo.

## Contract/export boundary

The export script performs local JSON transformations only. OpenAPI describes the protected tool surface; the Retell-oriented manifest includes schema, URLs and safety/authentication metadata without secret values. It is an import/configuration aid, **not a guaranteed current provider API payload**. Its arguments must be mapped at the JSON root. The generic agent prompt also documents the placeholders and prohibits outbound calls and false delivery claims.
