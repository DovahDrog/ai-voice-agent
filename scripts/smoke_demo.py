#!/usr/bin/env python3
"""Run a synthetic in-process backend walkthrough with networking forbidden.

No hosted speech provider, SMTP server, messaging API or telephone call is used.
A fresh work directory outside the repository retains only synthetic local data.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import sys
import tempfile
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def run_smoke(work_dir: Path) -> dict:
    work_dir = work_dir.resolve()
    if work_dir.is_relative_to(ROOT):
        raise ValueError("Smoke runtime data must be outside the repository")
    if work_dir.exists():
        raise ValueError("Use a new, empty work-directory path")
    work_dir.mkdir(parents=True)
    checks: list[dict] = []
    seen_tools: set[str] = set()
    network_attempts = 0

    def forbid_network(*_args, **_kwargs):
        nonlocal network_attempts
        network_attempts += 1
        raise AssertionError("External networking is forbidden in this smoke demo")

    def check(name: str, actual, expected) -> None:
        if actual != expected:
            raise AssertionError(f"Smoke check failed: {name}")
        checks.append({"name": name, "passed": True})

    safe_env = {
        "VOICE_CALL_LOG_DIR": str(work_dir / "data"),
        "VOICE_BOOKING_URL": "https://example.invalid/book",
        "VOICE_DEMO_MODE": "true",
        "VOICE_SMS_DELIVERY_ENABLED": "false",
        "VOICE_EMAIL_DELIVERY_ENABLED": "false",
    }
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, safe_env, clear=True))
        for target in ("socket.socket.connect", "socket.socket.connect_ex", "socket.getaddrinfo", "socket.create_connection"):
            stack.enter_context(patch(target, side_effect=forbid_network))
        sys.path.insert(0, str(ROOT / "src"))
        from fastapi.testclient import TestClient
        from jsonschema import Draft202012Validator
        import voice_tools as voice
        stack.enter_context(patch.object(voice, "CALL_LOG_DIR", work_dir / "data"))
        stack.enter_context(patch.object(voice, "BOOKING_URL", "https://example.invalid/book"))
        stack.enter_context(patch.object(voice, "_utc_now", return_value=datetime(2030, 1, 1, tzinfo=timezone.utc)))
        client = stack.enter_context(TestClient(voice.app))
        contracts = json.loads((ROOT / "schemas/tools.json").read_text(encoding="utf-8"))

        check("health", client.get("/health").status_code, 200)
        check("unconfigured_auth_fails_closed", client.post("/tools/check_calendar", json={"date_range": "next week"}).status_code, 503)
        os.environ["VOICE_TOOLS_SHARED_SECRET"] = secrets.token_urlsafe(32)
        check("configured_auth_required", client.post("/tools/check_calendar", json={"date_range": "next week"}).status_code, 401)
        headers = {"X-Voice-Webhook-Secret": os.environ["VOICE_TOOLS_SHARED_SECRET"]}

        def tool(name: str, body: dict) -> dict:
            result = client.post("/tools/" + name, json=body, headers=headers)
            check(name + "_http", result.status_code, 200)
            contract = contracts["tools"][name]
            request_name = contract["request"]["$ref"].split("/")[-1]
            response_name = contract["response"]["$ref"].split("/")[-1]
            Draft202012Validator(contracts["$defs"][request_name]).validate(body)
            Draft202012Validator(contracts["$defs"][response_name]).validate(result.json())
            seen_tools.add(name)
            return result.json()

        prospect = tool("create_prospect", {"name": "Synthetic Resident", "phone": "+12025550100", "email": "synthetic@example.com"})
        prospect_id = prospect["prospect_id"]
        slots = tool("check_calendar", {"date_range": "next week", "attendee": "operator"})
        check("three_example_slots", len(slots["slots"]), 3)
        check("calendar_is_explicitly_an_example", slots["source"], "deterministic_example")
        rejected = tool("send_lead_leak_snapshot_sms", {"phone": "+12025550100"})
        check("missing_consent_is_rejected", rejected["blocked_reason"], "missing_permission_evidence")
        permission = {"permission_confirmed": True, "permission_evidence": "Synthetic caller explicitly requested this channel's follow-up."}
        sms = tool("send_lead_leak_snapshot_sms", {"phone": "+12025550100", **permission})
        check("sms_is_disabled", sms["blocked_reason"], "sms_delivery_disabled")
        email = tool("send_lead_leak_snapshot_email", {"email": "synthetic@example.com", **permission})
        check("email_is_disabled", email["blocked_reason"], "email_delivery_disabled")
        packet = tool("send_sms_close_packet", {"phone": "+12025550100", "contract_url": "https://example.com/agreement", "payment_url": "https://example.com/payment", **permission})
        check("packet_is_log_only", packet["sent"], False)
        invalid = tool("send_sms_close_packet", {"phone": "+12025550100", "contract_url": "https://localhost/private", **permission})
        check("private_links_blocked", invalid["blocked_reason"], "invalid_contract_url_host")
        booking = tool("send_sms_booking_link", {"phone": "+12025550100", "slot": slots["slots"][0], **permission})
        check("booking_is_an_intent_not_delivery", booking["blocked_reason"], "booking_adapter_not_implemented")
        transfer = tool("transfer_to_operator", {"reason": "Synthetic human-review request"})
        check("no_real_phone_transfer", transfer["actual_transfer"], False)
        audit_dir = voice.CALL_LOG_DIR / "audits"
        audit_dir.mkdir()
        fixture = {"synthetic": True, "source": "local_demo_fixture", "observations": ["Example follow-up routing observation; not a real client audit."]}
        (audit_dir / f"{prospect_id}.json").write_text(json.dumps(fixture), encoding="utf-8")
        audit = tool("look_up_audit", {"prospect_id": prospect_id})
        check("audit_fixture_read_back", audit["audit_summary"], fixture)
        outcome = tool("log_call_outcome", {"prospect_id": prospect_id, "outcome": "do_not_call"})
        check("outcome_recorded", outcome["logged"], True)
        suppressed = tool("send_lead_leak_snapshot_email", {"email": "synthetic@example.com", **permission})
        check("opt_out_suppresses_email_without_phone", suppressed["blocked_reason"], "do_not_call")

        event = client.post("/retell/webhook", json={"event": "call_analyzed", "call": {"transcript": "synthetic-sensitive-marker", "from_number": "+12025550100"}})
        check("unsigned_event_accepted_as_untrusted", event.status_code, 200)
        check("event_is_not_authenticated", event.json()["trusted"], False)
        event_record = json.loads((voice.CALL_LOG_DIR / "retell_events.jsonl").read_text(encoding="utf-8"))
        check("event_log_contains_metadata_only", set(event_record), {"at", "event_type", "payload_bytes", "trusted"})
        check("event_has_no_transcript", "synthetic-sensitive-marker" in json.dumps(event_record), False)

        spec = importlib.util.spec_from_file_location("voice_manifest_export", ROOT / "scripts/export_retell_manifest.py")
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        paths = exporter.export_manifests(ROOT / "schemas/tools.json", work_dir / "manifests", "https://voice.example.invalid")
        openapi = json.loads(Path(paths["openapi"]).read_text(encoding="utf-8"))
        manifest = json.loads(Path(paths["retell_tools"]).read_text(encoding="utf-8"))
        check("openapi_export", openapi["openapi"], "3.1.0")
        check("exported_tools_match_exercised_tools", {entry["name"] for entry in manifest["tools"]}, seen_tools)
        check("exported_default_side_effects_disabled", any(entry["safety"]["external_side_effects_enabled"] for entry in manifest["tools"]), False)
        check("manifest_has_no_secret_value", os.environ["VOICE_TOOLS_SHARED_SECRET"] in json.dumps([openapi, manifest]), False)
        check("zero_network_attempts", network_attempts, 0)
        return {
            "ok": True, "fixture_classification": "synthetic_local_only", "tool_count": len(seen_tools),
            "exported_tool_count": len(manifest["tools"]), "network_attempts": network_attempts,
            "sms_sent": sms["sent"], "email_sent": email["sent"],
            "hosted_provider_used": False, "mock_provider_used": False,
            "temporary_data_retained": True, "checks": checks,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, help="New directory outside the repository for synthetic runtime data")
    args = parser.parse_args()
    # mkdtemp reserves the parent; run_smoke creates a new child without deleting anything.
    work_dir = args.work_dir or Path(tempfile.mkdtemp(prefix="voice-smoke-")) / "run"
    result = run_smoke(work_dir)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
