from __future__ import annotations

import html
import http.client
import hmac
import ipaddress
import json
import os
import re
import socket
from threading import RLock
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, field_validator


CALL_LOG_DIR = Path(os.environ.get("VOICE_CALL_LOG_DIR", "runtime"))
BOOKING_URL = os.environ.get("VOICE_BOOKING_URL", "https://example.invalid/book")
SHARED_SECRET_ENV = "VOICE_TOOLS_SHARED_SECRET"
WEBHOOK_SECRET_HEADER = "x-voice-webhook-secret"

app = FastAPI(title="AI Voice Agent Tool Backend", version="1.0.0")
_webhook_header = APIKeyHeader(name="X-Voice-Webhook-Secret", scheme_name="VoiceWebhookSecret", auto_error=False)


def require_webhook_secret(x_voice_webhook_secret: str | None = Security(_webhook_header)) -> None:
    """Fail closed; never log or return a configured secret."""
    expected = os.environ.get(SHARED_SECRET_ENV, "").strip()
    if len(expected) < 32 or len(expected) > 512:
        raise HTTPException(status_code=503, detail="Tool authentication is not configured")
    supplied = (x_voice_webhook_secret or "").encode("utf-8")
    if not supplied or not hmac.compare_digest(supplied, expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Unauthorized")


ToolAuth = Depends(require_webhook_secret)


class ToolModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=4000)

    @field_validator("phone", check_fields=False)
    @classmethod
    def validate_phone(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"\+[1-9][0-9]{6,14}", value):
            raise ValueError("phone must be an E.164 number")
        return value

    @field_validator("prospect_id", "contact_id", "call_id", check_fields=False)
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
            raise ValueError("identifier must contain 1-80 ASCII letters, digits, hyphens or underscores")
        return value

    @field_validator("name", "date_range", "reason", "slot", check_fields=False)
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("nonempty text is required")
        return value


class CalendarRequest(ToolModel):
    date_range: str = Field(..., min_length=1, max_length=400)
    attendee: Literal["operator", "team"] = "operator"


class CalendarResponse(ToolModel):
    slots: list[str]
    source: Literal["deterministic_example"] = "deterministic_example"


class CreateProspectRequest(ToolModel):
    contact_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    name: str = Field(..., min_length=1, max_length=400)
    phone: str = Field(..., pattern=r"^\+[1-9][0-9]{6,14}$", max_length=16, description="Recipient phone in E.164 format")
    email: str | None = None
    vertical: str | None = None


class CreateProspectResponse(ToolModel):
    prospect_id: str


class SmsBookingRequest(ToolModel):
    permission_confirmed: bool = Field(default=False, strict=True)
    permission_evidence: str | None = None
    phone: str = Field(..., pattern=r"^\+[1-9][0-9]{6,14}$", max_length=16, description="Recipient phone in E.164 format")
    slot: str = Field(..., min_length=1, max_length=400)
    calendar_url: str | None = None


class SmsBookingResponse(ToolModel):
    sent: bool
    provider_message_id: str | None = None
    blocked_reason: str | None = None


class ClosePacketSmsRequest(ToolModel):
    permission_evidence: str | None = None
    permission_confirmed: bool = Field(default=False, strict=True)
    phone: str = Field(..., pattern=r"^\+[1-9][0-9]{6,14}$", max_length=16, description="Recipient phone in E.164 format")
    contact_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    prospect_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    package_name: str | None = None
    contract_url: str | None = None
    payment_url: str | None = None
    onboarding_url: str | None = None
    summary: str | None = None


class ClosePacketSmsResponse(ToolModel):
    sent: bool
    provider_message_id: str | None = None
    blocked_reason: str | None = None
    logged: bool = True
    channel: Literal["sms"] = "sms"
    provider: str | None = None
    message_preview: str | None = None


class LeadLeakSnapshotEmailRequest(ToolModel):
    permission_confirmed: bool = Field(default=False, strict=True)
    email: str | None = Field(default=None, description="Recipient email collected or confirmed during the call")
    contact_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    contact_name: str | None = None
    company_name: str | None = None
    phone: str | None = Field(default=None, pattern=r"^\+[1-9][0-9]{6,14}$", max_length=16, description="Recipient phone in E.164 format")
    subject: str | None = None
    snapshot_summary: str | None = None
    next_step_url: str | None = None
    permission_evidence: str | None = Field(
        default=None,
        description="Exact call evidence that the prospect asked for or agreed to receive the email. Required before sending.",
    )
    call_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    source: str = "voice_call"


class LeadLeakSnapshotEmailResponse(ToolModel):
    sent: bool
    provider_message_id: str | None = None
    blocked_reason: str | None = None
    logged: bool = True
    channel: Literal["email"] = "email"
    provider: str | None = None
    contact_id: str | None = None
    subject: str | None = None
    message_preview: str | None = None


class LeadLeakSnapshotSmsRequest(ToolModel):
    permission_confirmed: bool = Field(default=False, strict=True)
    phone: str = Field(..., pattern=r"^\+[1-9][0-9]{6,14}$", max_length=16, description="Recipient phone in E.164 format")
    contact_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    contact_name: str | None = None
    company_name: str | None = None
    email: str | None = None
    snapshot_summary: str | None = None
    next_step_url: str | None = None
    permission_evidence: str | None = Field(
        default=None,
        description="Exact call evidence that the prospect asked for or agreed to receive the text/SMS. Required before sending.",
    )
    call_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    source: str = "voice_call"


class LeadLeakSnapshotSmsResponse(ToolModel):
    sent: bool
    provider_message_id: str | None = None
    blocked_reason: str | None = None
    logged: bool = True
    channel: Literal["sms"] = "sms"
    provider: str | None = None
    contact_id: str | None = None
    message_preview: str | None = None


class TransferRequest(ToolModel):
    reason: str = Field(..., min_length=1, max_length=400)
    context: str | None = None


class TransferResponse(ToolModel):
    actual_transfer: Literal[False] = False
    escalated: bool
    fallback_required_after_seconds: int = 90


CallOutcome = Literal[
    "booked",
    "thinking",
    "declined",
    "wrong_number",
    "do_not_call",
    "escalated",
    "no_answer",
    "bad_fit_or_spam",
    "internal_test",
]


class LogOutcomeRequest(ToolModel):
    prospect_id: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)
    outcome: CallOutcome
    notes: str | None = None
    next_action: str | None = None


class LogOutcomeResponse(ToolModel):
    logged: bool
    path: str


class AuditLookupResponse(ToolModel):
    audit_summary: dict | None


class AuditLookupRequest(ToolModel):
    prospect_id: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,80}$", max_length=80)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
        raise HTTPException(status_code=422, detail="Invalid record identifier")
    return value

_STORAGE_LOCK = RLock()


def _write_jsonl(path: Path, record: dict) -> None:
    try:
        with _STORAGE_LOCK:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Local record storage is unavailable") from exc

def _read_jsonl(path: Path) -> list[dict]:
    """Fail closed on corrupt/unreadable storage instead of ignoring suppressions."""
    try:
        if not path.exists():
            return []
        records: list[dict] = []
        with _STORAGE_LOCK, path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("record is not an object")
                records.append(record)
        return records
    except (OSError, UnicodeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Local record storage is unavailable or invalid") from exc

def _normalize_phone(phone: str | None) -> str:
    if not isinstance(phone, str):
        return ""
    return "".join(ch for ch in phone if ch.isdigit())


def _dnc_path() -> Path:
    return CALL_LOG_DIR / "dnc.jsonl"


def _is_do_not_contact(*, phone: str | None = None, email: str | None = None,
                       contact_id: str | None = None) -> bool:
    normalized = _normalize_phone(phone)
    normalized_email = email.strip().lower() if isinstance(email, str) else ""
    for record in _read_jsonl(_dnc_path()):
        phone_value, email_value, contact_value = (record.get(key) for key in ("phone_normalized", "email_normalized", "contact_id"))
        if (not any((phone_value, email_value, contact_value))
                or any(value is not None and not isinstance(value, str) for value in (phone_value, email_value, contact_value))):
            raise HTTPException(status_code=503, detail="Local suppression storage is invalid")
        if (normalized and record.get("phone_normalized") == normalized
                or normalized_email and record.get("email_normalized") == normalized_email
                or contact_id and record.get("contact_id") == contact_id):
            return True
    return False


def _is_do_not_call(phone: str) -> bool:
    return _is_do_not_contact(phone=phone)

def _find_prospect(prospect_id: str) -> dict | None:
    for record in reversed(_read_jsonl(CALL_LOG_DIR / "prospects.jsonl")):
        if record.get("prospect_id") == prospect_id and isinstance(record.get("prospect"), dict):
            return record["prospect"]
    return None

def _record_do_not_contact(*, prospect: dict, prospect_id: str) -> None:
    # Suppression is deliberately cross-channel. No expiry or automated removal.
    _write_jsonl(_dnc_path(), {
        "at": _utc_now().isoformat(), "phone_normalized": _normalize_phone(prospect.get("phone")),
        "email_normalized": str(prospect.get("email") or "").strip().lower(),
        "contact_id": prospect.get("contact_id"), "prospect_id": prospect_id, "source": "call_outcome",
    })

def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _sms_provider() -> str:
    return os.environ.get("VOICE_SMS_PROVIDER", "").strip().lower()


def _email_provider() -> str:
    return os.environ.get("VOICE_EMAIL_PROVIDER", "").strip().lower()


def _ghl_location_id() -> str:
    return os.environ.get("VOICE_GHL_LOCATION_ID", "").strip()


def _allowed_close_packet_hosts() -> set[str]:
    raw = os.environ.get("VOICE_ALLOWED_LINK_HOSTS", "example.com,example.invalid")
    return {host.strip().lower() for host in raw.split(",") if host.strip()}

def _public_hostname(host: str) -> bool:
    """Conservative hostname syntax. No IP literals, aliases, or internal names."""
    if not host or host != host.lower() or host.endswith(".") or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    if host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".test")):
        return False
    return all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)


def _host_is_allowed(host: str, allowed_hosts: set[str]) -> bool:
    return _public_hostname(host) and host in allowed_hosts


def _validate_public_url(url: str, *, allowed_hosts: set[str], field: str) -> str | None:
    """Validate links without fetching them. Host matches are exact, not wildcard."""
    if not url or re.search(r"[\x00-\x20\x7f\\]", url):
        return f"invalid_{field}_format"
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.netloc:
            return f"invalid_{field}_scheme"
        if parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443):
            return f"invalid_{field}_authority"
        if not _host_is_allowed(parsed.hostname or "", allowed_hosts):
            return f"invalid_{field}_host"
    except ValueError:
        return f"invalid_{field}_format"
    return None

def _validate_close_packet_urls(request: ClosePacketSmsRequest) -> str | None:
    for field in ("contract_url", "payment_url", "onboarding_url"):
        url = getattr(request, field)
        if url:
            reason = _validate_public_url(url, allowed_hosts=_allowed_close_packet_hosts(), field=field)
            if reason:
                return reason
    return None

def _permission_reason(request: BaseModel) -> str | None:
    if not (getattr(request, "permission_evidence", None) or "").strip():
        return "missing_permission_evidence"
    if not getattr(request, "permission_confirmed", False):
        return "permission_not_confirmed"
    return None


def _delivery_gate(channel: str, provider: str | None) -> str | None:
    if not _env_flag(f"VOICE_{channel.upper()}_DELIVERY_ENABLED"):
        return f"{channel}_delivery_disabled"
    # Only an explicit false disables demo mode; typos cannot enable delivery.
    if os.environ.get("VOICE_DEMO_MODE", "true").strip().lower() != "false":
        return "demo_mode"
    if provider not in {"ghl", "leadconnector"}:
        return f"unsupported_{channel}_provider" if provider else f"missing_{channel}_provider"
    return None


def _validate_message_links(message: str) -> str | None:
    for url in re.findall(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"]+", message):
        reason = _validate_public_url(url, allowed_hosts=_allowed_close_packet_hosts(), field="message_url")
        if reason:
            return reason
    if re.search(r"\bwww\.", message, re.IGNORECASE):
        return "invalid_message_url_scheme"
    return None


def _delivery_record(*, tool: str, channel: str, provider: str | None, sent: bool = False,
                     blocked_reason: str | None = None, provider_message_id: str | None = None) -> dict:
    """Outbound logs contain decisions, not recipients, bodies, or consent quotations."""
    return {"at": _utc_now().isoformat(), "request_id": uuid4().hex,
            "tool": tool, "channel": channel, "provider": provider, "sent": sent,
            "blocked_reason": blocked_reason, "provider_message_id": provider_message_id}


def _close_packet_message(request: ClosePacketSmsRequest) -> str:
    lines = ["Follow-up team: here is your secure close packet."]
    if request.package_name:
        lines.append(f"Package: {request.package_name}")
    if request.contract_url:
        lines.append(f"Agreement: {request.contract_url}")
    if request.payment_url:
        lines.append(f"Secure payment: {request.payment_url}")
    if request.onboarding_url:
        lines.append(f"Onboarding: {request.onboarding_url}")
    if request.summary:
        lines.append(request.summary.strip())
    lines.append("Do not send card details by text or phone. Reply STOP to opt out, HELP for help.")
    return "\n".join(line for line in lines if line).strip()


def _ghl_token() -> str | None:
    for name in ("VOICE_GHL_API_TOKEN",):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def _public_connect(address: tuple[str, int], timeout: float | None = 20,
                    source_address: tuple[str, int] | None = None) -> socket.socket:
    """Resolve once, reject all non-public answers, then connect to a pinned address."""
    if source_address is not None:
        raise OSError("Source address override is not supported")
    host, port = address
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers:
        raise OSError("No public provider address")
    for _, _, _, _, sockaddr in answers:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise OSError("Non-public provider address")
    last_error: OSError | None = None
    for family, kind, proto, _, sockaddr in answers:
        connection = socket.socket(family, kind, proto)
        try:
            connection.settimeout(timeout)
            connection.connect(sockaddr)
            return connection
        except OSError as exc:
            connection.close()
            last_error = exc
    raise last_error or OSError("No public provider address")


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _public_connect


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(_PublicHTTPSConnection, request, context=self._context, check_hostname=self._check_hostname)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _request_json(method: str, url: str, *, token: str, payload: dict | None = None,
                  version: str, timeout: int = 20) -> tuple[int, dict]:
    # Defense in depth for direct adapter/helper callers, not only HTTP routes.
    if os.environ.get("VOICE_DEMO_MODE", "true").strip().lower() != "false":
        return 0, {"error": "demo_mode"}
    if not (_env_flag("VOICE_SMS_DELIVERY_ENABLED") or _env_flag("VOICE_EMAIL_DELIVERY_ENABLED")):
        return 0, {"error": "external_delivery_disabled"}
    hosts = {host.strip().lower() for host in os.environ.get("VOICE_GHL_ALLOWED_API_HOSTS", "").split(",") if host.strip()}
    invalid = _validate_public_url(url, allowed_hosts=hosts, field="ghl_api_url")
    if invalid:
        return 0, {"error": invalid}
    try:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=body, method=method, headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json",
            "Accept": "application/json", "Version": version, "User-Agent": "VoiceTools/1.0",
        })
        # No environment proxies or bearer-token forwarding across redirects.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), _PublicHTTPSHandler())
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(1048577)
            if len(raw) > 1048576:
                return 0, {"error": "provider_response_too_large"}
            data = json.loads(raw.decode("utf-8")) if raw else {}
            if not isinstance(data, dict):
                return 0, {"error": "invalid_provider_response"}
            return response.status, data
    except urllib.error.HTTPError as exc:
        exc.close()
        return exc.code, {"error": f"ghl_http_{exc.code}"}
    except (urllib.error.URLError, OSError, ValueError, UnicodeError, RecursionError):
        # Never reflect raw provider bodies, URLs, or exception strings.
        return 0, {"error": "provider_unavailable_or_invalid_response"}

def _post_json(url: str, *, token: str, payload: dict, version: str) -> tuple[int, dict]:
    return _request_json("POST", url, token=token, payload=payload, version=version)


def _get_json(url: str, *, token: str, version: str) -> tuple[int, dict]:
    return _request_json("GET", url, token=token, payload=None, version=version)


def _ghl_config(channel: str) -> tuple[str, str, str, str | None]:
    reason = _delivery_gate(channel, _sms_provider() if channel == "sms" else _email_provider())
    if reason:
        return "", "", "", reason
    token = _ghl_token() or ""
    if not token:
        return "", "", "", "missing_ghl_api_token"
    if not re.fullmatch(r"[A-Za-z0-9._-]{16,4096}", token):
        return "", "", "", "invalid_ghl_api_token"
    location = _ghl_location_id()
    if not location:
        return "", "", "", "missing_ghl_location_id"
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", location):
        return "", "", "", "invalid_ghl_location_id"
    base = os.environ.get("VOICE_GHL_API_BASE_URL", "").rstrip("/")
    if not base:
        return "", "", "", "missing_ghl_api_base_url"
    hosts = {h.strip().lower() for h in os.environ.get("VOICE_GHL_ALLOWED_API_HOSTS", "").split(",") if h.strip()}
    reason = _validate_public_url(base, allowed_hosts=hosts, field="ghl_api_base_url")
    if reason:
        return "", "", "", reason
    parsed = urllib.parse.urlsplit(base)
    if parsed.path or parsed.query or parsed.fragment:
        return "", "", "", "invalid_ghl_api_base_url_format"
    version = os.environ.get("VOICE_GHL_API_VERSION", "2021-07-28")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", version):
        return "", "", "", "invalid_ghl_api_version"
    return token, base, version, None


def _ghl_verify_contact(*, token: str, contact_id: str, recipient: str,
                        channel: str, api_base: str, version: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", contact_id):
        return "invalid_ghl_contact_id"
    if _is_do_not_contact(contact_id=contact_id):
        return "do_not_call"
    status, data = _get_json(f"{api_base}/contacts/{contact_id}", token=token, version=version)
    contact = data.get("contact") if isinstance(data, dict) else None
    if status != 200 or not isinstance(contact, dict):
        return "ghl_contact_verification_failed"
    # A wrong provider account/contact must not redirect a caller's follow-up.
    if contact.get("locationId") != _ghl_location_id():
        return "ghl_contact_location_mismatch"
    if contact.get("id") != contact_id:
        return "ghl_contact_id_mismatch"
    if channel == "sms":
        values = [contact.get("phone"), contact.get("phoneNumber"), contact.get("mobilePhone")]
        matched = any(_normalize_phone(str(value or "")) == _normalize_phone(recipient) for value in values)
    else:
        matched = str(contact.get("email") or "").strip().lower() == recipient.strip().lower()
    if not matched:
        return "ghl_contact_recipient_mismatch"
    if _is_do_not_contact(phone=contact.get("phone"), email=contact.get("email"), contact_id=contact_id):
        return "do_not_call"
    dnd_settings = contact.get("dndSettings") or {}
    channel_setting = dnd_settings.get("SMS" if channel == "sms" else "Email", {}) if isinstance(dnd_settings, dict) else {}
    if contact.get("dnd") is True or isinstance(channel_setting, dict) and str(channel_setting.get("status", "")).lower() == "active":
        return "provider_do_not_contact"
    return None


def _message_result(status: int, data: dict) -> tuple[bool, str | None, str | None]:
    if 200 <= status < 300:
        provider_id = data.get("messageId") or data.get("id") or data.get("_id")
        if not isinstance(provider_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", provider_id):
            return False, None, "provider_missing_or_invalid_message_id"
        # Accepted by the API is not confirmed delivery to a handset/inbox.
        return True, provider_id, None
    return False, None, f"ghl_http_{status}" if status else "provider_unavailable_or_invalid_response"


def _send_ghl_close_packet_sms(request: ClosePacketSmsRequest, *, message: str) -> tuple[bool, str | None, str | None]:
    token, api_base, version, reason = _ghl_config("sms")
    if reason:
        return False, None, reason
    reason = _permission_reason(request) or _validate_close_packet_urls(request) or _validate_message_links(message)
    if reason:
        return False, None, reason
    if _is_do_not_contact(phone=request.phone, contact_id=request.contact_id):
        return False, None, "do_not_call"
    if not request.contact_id:
        return False, None, "missing_ghl_contact_id"
    reason = _ghl_verify_contact(token=token, contact_id=request.contact_id, recipient=request.phone,
                                channel="sms", api_base=api_base, version=version)
    if reason:
        return False, None, reason
    payload = {"type": "SMS", "contactId": request.contact_id, "message": message}
    return _message_result(*_post_json(f"{api_base}/conversations/messages", token=token, payload=payload, version=version))

def _valid_email(email: str | None) -> bool:
    return bool(email and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.strip()))


def _html_body(text: str) -> str:
    return "<p>" + html.escape(text).replace("\n\n", "</p><p>").replace("\n", "<br>") + "</p>"


def _lead_leak_email_subject(request: LeadLeakSnapshotEmailRequest) -> str:
    if request.subject and request.subject.strip():
        return request.subject.strip()[:180]
    company = (request.company_name or "your business").strip()
    return f"{company}: 3-point Lead Leak Snapshot"


def _lead_leak_email_text(request: LeadLeakSnapshotEmailRequest) -> str:
    company = (request.company_name or "your organization").strip()
    summary = (request.snapshot_summary or "").strip() or (
        "1. Review unanswered calls and forms.\n"
        "2. Identify a follow-up owner.\n"
        "3. Confirm a next step with the caller."
    )
    greeting = f"Hi {request.contact_name.strip()}," if request.contact_name else "Hello,"
    return (
        f"{greeting}\n\nAs requested, here is the follow-up snapshot for {company}:\n\n"
        f"{summary}\n\nNext step: {(request.next_step_url or BOOKING_URL).strip()}\n\n"
        "Your follow-up team\nReply unsubscribe to opt out."
    )


def _lead_leak_sms_text(request: LeadLeakSnapshotSmsRequest) -> str:
    company = (request.company_name or "your business").strip()
    summary = (request.snapshot_summary or "").strip()
    if not summary:
        summary = "1) Check missed calls/forms. 2) Add a fast response backstop. 3) Map the fix in a short Response Review."
    one_line_summary = " ".join(line.strip(" -•\t") for line in summary.splitlines() if line.strip())
    if len(one_line_summary) > 420:
        one_line_summary = one_line_summary[:417].rstrip() + "..."
    next_step_url = (request.next_step_url or BOOKING_URL).strip()
    return (
        f"Follow-up team: as requested, here is the 3-point Lead Leak Snapshot for {company}: "
        f"{one_line_summary} Next step: {next_step_url} Reply STOP to opt out, HELP for help."
    )


def _ghl_find_contact_id_by_phone(*, token: str, phone: str, api_base: str, version: str) -> str | None:
    query = urllib.parse.urlencode({"locationId": _ghl_location_id(), "query": phone})
    status, data = _get_json(f"{api_base}/contacts/?{query}", token=token, version=version)
    if status != 200 or not isinstance(data, dict):
        return None
    target = _normalize_phone(phone)
    contacts = data.get("contacts") or []
    for contact in contacts if isinstance(contacts, list) else []:
        if not isinstance(contact, dict):
            continue
        values = [contact.get("phone"), contact.get("phoneNumber"), contact.get("mobilePhone")]
        if any(_normalize_phone(str(value or "")) == target for value in values):
            return _extract_contact_id(contact)
    return None


def _ghl_create_sms_contact(*, token: str, request: LeadLeakSnapshotSmsRequest, api_base: str, version: str) -> str | None:
    payload: dict[str, str | list[str]] = {
        "locationId": _ghl_location_id(),
        "phone": request.phone.strip(),
        "name": (request.contact_name or request.company_name or request.phone).strip(),
        "source": "Voice follow-up SMS",
        "tags": ["voice-followup", "voice-permission-sms", "lead-leak-snapshot"],
    }
    if _valid_email(request.email):
        payload["email"] = request.email.strip()
    status, data = _post_json(f"{api_base}/contacts/", token=token, payload=payload, version=version)
    if 200 <= status < 300 and isinstance(data, dict):
        return _extract_contact_id(data)
    return _ghl_find_contact_id_by_phone(token=token, phone=request.phone, api_base=api_base, version=version)


def _send_ghl_lead_leak_sms(request: LeadLeakSnapshotSmsRequest, *, message: str) -> tuple[bool, str | None, str | None, str | None]:
    token, api_base, version, reason = _ghl_config("sms")
    reason = reason or _permission_reason(request) or _validate_message_links(message)
    if reason:
        return False, None, None, reason
    if _is_do_not_contact(phone=request.phone, email=request.email, contact_id=request.contact_id):
        return False, None, None, "do_not_call"
    contact_id = request.contact_id
    if not contact_id:
        contact_id = _ghl_find_contact_id_by_phone(token=token, phone=request.phone, api_base=api_base, version=version)
    if not contact_id:
        contact_id = _ghl_create_sms_contact(token=token, request=request, api_base=api_base, version=version)
    if not contact_id:
        return False, None, None, "missing_or_unresolved_ghl_contact_id"
    reason = _ghl_verify_contact(token=token, contact_id=contact_id, recipient=request.phone, channel="sms", api_base=api_base, version=version)
    if reason:
        return False, None, contact_id, reason
    payload = {"type": "SMS", "contactId": contact_id, "message": message}
    sent, provider_id, reason = _message_result(*_post_json(f"{api_base}/conversations/messages", token=token, payload=payload, version=version))
    return sent, provider_id, contact_id, reason

def _extract_contact_id(data: dict) -> str | None:
    contact = data.get("contact") if isinstance(data, dict) else None
    candidates = [contact.get("id")] if isinstance(contact, dict) else []
    if isinstance(data, dict):
        candidates.extend(data.get(key) for key in ("id", "_id", "contactId"))
    for candidate in candidates:
        if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", candidate):
            return candidate
    return None

def _ghl_find_contact_id_by_email(*, token: str, email: str, api_base: str, version: str) -> str | None:
    query = urllib.parse.urlencode({"locationId": _ghl_location_id(), "query": email})
    status, data = _get_json(f"{api_base}/contacts/?{query}", token=token, version=version)
    if status != 200 or not isinstance(data, dict):
        return None
    contacts = data.get("contacts") or []
    for contact in contacts if isinstance(contacts, list) else []:
        if isinstance(contact, dict) and str(contact.get("email") or "").lower() == email.lower():
            return _extract_contact_id(contact)
    return None


def _ghl_create_email_contact(*, token: str, request: LeadLeakSnapshotEmailRequest, api_base: str, version: str) -> str | None:
    if not _valid_email(request.email):
        return None
    payload: dict[str, str | list[str]] = {
        "locationId": _ghl_location_id(),
        "email": request.email.strip(),
        "name": (request.contact_name or request.company_name or request.email).strip(),
        "source": "Voice follow-up email",
        "tags": ["voice-followup", "voice-permission-email"],
    }
    if request.phone:
        payload["phone"] = request.phone
    status, data = _post_json(f"{api_base}/contacts/", token=token, payload=payload, version=version)
    if 200 <= status < 300 and isinstance(data, dict):
        return _extract_contact_id(data)
    if request.email:
        return _ghl_find_contact_id_by_email(token=token, email=request.email, api_base=api_base, version=version)
    return None


def _send_ghl_lead_leak_email(request: LeadLeakSnapshotEmailRequest, *, subject: str, message: str) -> tuple[bool, str | None, str | None, str | None]:
    token, api_base, version, reason = _ghl_config("email")
    reason = reason or _permission_reason(request) or _validate_message_links(subject + "\n" + message)
    if reason:
        return False, None, None, reason
    if not _valid_email(request.email):
        return False, None, None, "missing_valid_email"
    if _is_do_not_contact(phone=request.phone, email=request.email, contact_id=request.contact_id):
        return False, None, None, "do_not_call"
    contact_id = request.contact_id
    if not contact_id:
        contact_id = _ghl_find_contact_id_by_email(token=token, email=request.email.strip(), api_base=api_base, version=version)
    if not contact_id:
        contact_id = _ghl_create_email_contact(token=token, request=request, api_base=api_base, version=version)
    if not contact_id:
        return False, None, None, "missing_or_unresolved_ghl_contact_id"
    reason = _ghl_verify_contact(token=token, contact_id=contact_id, recipient=request.email, channel="email", api_base=api_base, version=version)
    if reason:
        return False, None, contact_id, reason
    payload = {"type": "Email", "contactId": contact_id, "subject": subject, "html": _html_body(message)}
    sent, provider_id, reason = _message_result(*_post_json(f"{api_base}/conversations/messages", token=token, payload=payload, version=version))
    return sent, provider_id, contact_id, reason

@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": "voice-tools", "version": "1.0.0"}


@app.post("/retell/webhook")
async def retell_webhook(request: Request) -> dict:
    """Unsigned, untrusted telemetry only. Never call tools or providers from here."""
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 65536:
            raise HTTPException(status_code=413, detail="Event exceeds size limit")
        body.extend(chunk)
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="Expected a JSON event object") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON event object")
    raw_type = payload.get("event")
    allowed_types = {"call_started", "call_ended", "call_analyzed"}
    event_type = raw_type if isinstance(raw_type, str) and raw_type in allowed_types else "unknown"
    _write_jsonl(CALL_LOG_DIR / "retell_events.jsonl", {
        "at": _utc_now().isoformat(), "event_type": event_type,
        "payload_bytes": len(body), "trusted": False,
    })
    return {"ok": True, "logged": True, "trusted": False}

@app.post("/tools/check_calendar", response_model=CalendarResponse, dependencies=[ToolAuth])
def check_calendar(request: CalendarRequest) -> CalendarResponse:
    # Deterministic example slots, not a real calendar query.
    base = _utc_now().replace(minute=0, second=0, microsecond=0) + timedelta(days=1)
    slots = [base.replace(hour=h).isoformat() for h in (14, 17, 19)]
    return CalendarResponse(slots=slots)


@app.post("/tools/create_prospect", response_model=CreateProspectResponse, dependencies=[ToolAuth])
def create_prospect(request: CreateProspectRequest) -> CreateProspectResponse:
    prospect_id = f"prospect_{uuid4().hex[:12]}"
    _write_jsonl(
        CALL_LOG_DIR / "prospects.jsonl",
        {"at": _utc_now().isoformat(), "prospect_id": prospect_id, "prospect": request.model_dump()},
    )
    return CreateProspectResponse(prospect_id=prospect_id)


@app.post("/tools/send_lead_leak_snapshot_email", response_model=LeadLeakSnapshotEmailResponse, dependencies=[ToolAuth])
def send_lead_leak_snapshot_email(request: LeadLeakSnapshotEmailRequest) -> LeadLeakSnapshotEmailResponse:
    """Permission-gated optional GHL email adapter; safe intent logging by default."""
    subject = _lead_leak_email_subject(request)
    message = _lead_leak_email_text(request)
    provider = _email_provider() or None
    reason = "do_not_call" if _is_do_not_contact(phone=request.phone, email=request.email, contact_id=request.contact_id) else None
    reason = reason or _permission_reason(request)
    if not reason and not _valid_email(request.email):
        reason = "missing_valid_email"
    reason = reason or _validate_public_url(request.next_step_url or BOOKING_URL,
                                          allowed_hosts=_allowed_close_packet_hosts(), field="next_step_url")
    reason = reason or _validate_message_links(subject + "\n" + message)
    reason = reason or _delivery_gate("email", provider)
    sent, provider_message_id, contact_id = False, None, None
    if not reason:
        sent, provider_message_id, contact_id, reason = _send_ghl_lead_leak_email(request, subject=subject, message=message)
    log_name = "lead_leak_email_sent.jsonl" if sent else "lead_leak_email_intents.jsonl"
    _write_jsonl(CALL_LOG_DIR / log_name, _delivery_record(tool="send_lead_leak_snapshot_email", channel="email", provider=provider, sent=sent, blocked_reason=reason, provider_message_id=provider_message_id))
    return LeadLeakSnapshotEmailResponse(sent=sent, provider_message_id=provider_message_id, blocked_reason=reason,
                                        provider=provider, contact_id=contact_id, subject=subject, message_preview=message[:240])

@app.post("/tools/send_lead_leak_snapshot_sms", response_model=LeadLeakSnapshotSmsResponse, dependencies=[ToolAuth])
def send_lead_leak_snapshot_sms(request: LeadLeakSnapshotSmsRequest) -> LeadLeakSnapshotSmsResponse:
    """Permission-gated optional GHL SMS adapter; DNC precedes all external work."""
    message = _lead_leak_sms_text(request)
    provider = _sms_provider() or None
    reason = "do_not_call" if _is_do_not_contact(phone=request.phone, email=getattr(request, "email", None), contact_id=getattr(request, "contact_id", None)) else None
    reason = reason or _permission_reason(request)
    reason = reason or _validate_public_url(request.next_step_url or BOOKING_URL,
                                          allowed_hosts=_allowed_close_packet_hosts(), field="next_step_url")
    reason = reason or _validate_message_links(message)
    reason = reason or _delivery_gate("sms", provider)
    sent, provider_message_id, contact_id = False, None, None
    if not reason:
        sent, provider_message_id, contact_id, reason = _send_ghl_lead_leak_sms(request, message=message)
    log_name = "lead_leak_sms_sent.jsonl" if sent else "lead_leak_sms_intents.jsonl"
    _write_jsonl(CALL_LOG_DIR / log_name, _delivery_record(tool="send_lead_leak_snapshot_sms", channel="sms", provider=provider, sent=sent, blocked_reason=reason, provider_message_id=provider_message_id))
    return LeadLeakSnapshotSmsResponse(sent=sent, provider_message_id=provider_message_id, blocked_reason=reason,
                                      provider=provider, contact_id=contact_id, message_preview=message[:240])

@app.post("/tools/send_sms_booking_link", response_model=SmsBookingResponse, dependencies=[ToolAuth])
def send_sms_booking_link(request: SmsBookingRequest) -> SmsBookingResponse:
    """Local booking intent only. This tool has no delivery adapter."""
    reason = "do_not_call" if _is_do_not_contact(phone=request.phone, email=getattr(request, "email", None), contact_id=getattr(request, "contact_id", None)) else None
    reason = reason or _permission_reason(request)
    reason = reason or _validate_public_url(request.calendar_url or BOOKING_URL,
                                          allowed_hosts=_allowed_close_packet_hosts(), field="calendar_url")
    reason = reason or "booking_adapter_not_implemented"
    log_name = "sms_blocked_dnc.jsonl" if reason == "do_not_call" else "sms_intents.jsonl"
    _write_jsonl(CALL_LOG_DIR / log_name, _delivery_record(tool="send_sms_booking_link", channel="sms", provider=None, blocked_reason=reason))
    return SmsBookingResponse(sent=False, blocked_reason=reason)

@app.post("/tools/send_sms_close_packet", response_model=ClosePacketSmsResponse, dependencies=[ToolAuth])
def send_sms_close_packet(request: ClosePacketSmsRequest) -> ClosePacketSmsResponse:
    """Permission-gated contract/payment/onboarding links, never card collection."""
    message = _close_packet_message(request)
    provider = _sms_provider() or None
    reason = "do_not_call" if _is_do_not_contact(phone=request.phone, email=getattr(request, "email", None), contact_id=getattr(request, "contact_id", None)) else None
    reason = reason or _validate_close_packet_urls(request)
    reason = reason or _permission_reason(request)
    reason = reason or _validate_message_links(message)
    reason = reason or _delivery_gate("sms", provider)
    sent, provider_message_id = False, None
    if not reason:
        sent, provider_message_id, reason = _send_ghl_close_packet_sms(request, message=message)
    log_name = "close_packet_sms_sent.jsonl" if sent else "close_packet_sms_intents.jsonl"
    _write_jsonl(CALL_LOG_DIR / log_name, _delivery_record(tool="send_sms_close_packet", channel="sms", provider=provider, sent=sent, blocked_reason=reason, provider_message_id=provider_message_id))
    return ClosePacketSmsResponse(sent=sent, provider_message_id=provider_message_id, blocked_reason=reason,
                                  provider=provider, message_preview=message[:240])

@app.post("/tools/transfer_to_operator", response_model=TransferResponse, dependencies=[ToolAuth])
def transfer_to_operator(request: TransferRequest) -> TransferResponse:
    """Record an escalation request; no telephony transfer is implemented."""
    _write_jsonl(CALL_LOG_DIR / "escalations.jsonl", {"at": _utc_now().isoformat(), "request_id": uuid4().hex, "kind": "operator_review_requested", "actual_transfer": False})
    return TransferResponse(escalated=True, actual_transfer=False)

@app.post("/tools/log_call_outcome", response_model=LogOutcomeResponse, dependencies=[ToolAuth])
def log_call_outcome(request: LogOutcomeRequest) -> LogOutcomeResponse:
    if request.outcome == "do_not_call":
        prospect = _find_prospect(request.prospect_id)
        if not prospect:
            raise HTTPException(status_code=404, detail="Prospect not found; suppression was not recorded")
        _record_do_not_contact(prospect=prospect, prospect_id=request.prospect_id)
    relative_path = f"outcomes/{_safe_id(request.prospect_id)}.jsonl"
    # Notes and next_action may contain private caller content; record only the decision.
    _write_jsonl(CALL_LOG_DIR / relative_path, {"at": _utc_now().isoformat(), "prospect_id": request.prospect_id, "outcome": request.outcome})
    return LogOutcomeResponse(logged=True, path=relative_path)

def _look_up_audit_by_prospect_id(prospect_id: str) -> AuditLookupResponse:
    audit_path = CALL_LOG_DIR / "audits" / f"{_safe_id(prospect_id)}.json"
    if not audit_path.exists():
        return AuditLookupResponse(audit_summary=None)
    try:
        return AuditLookupResponse(audit_summary=json.loads(audit_path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Stored audit JSON is invalid") from exc


@app.post("/tools/look_up_audit", response_model=AuditLookupResponse, dependencies=[ToolAuth])
def look_up_audit(request: AuditLookupRequest) -> AuditLookupResponse:
    return _look_up_audit_by_prospect_id(request.prospect_id)


@app.get("/tools/look_up_audit/{prospect_id}", response_model=AuditLookupResponse, dependencies=[ToolAuth])
def look_up_audit_legacy_get(prospect_id: str) -> AuditLookupResponse:
    return _look_up_audit_by_prospect_id(prospect_id)
