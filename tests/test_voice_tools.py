"""Offline regression tests for the standalone voice backend."""
import json
import os
import secrets
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from fastapi.testclient import TestClient
with patch.dict(os.environ, {}, clear=True):
    import voice_tools as voice

RUNTIME_ROOT = Path(tempfile.gettempdir())


class VoiceToolTests(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.runtime = Path(tempfile.mkdtemp(prefix="voice-tests-", dir=RUNTIME_ROOT))
        voice.CALL_LOG_DIR = self.runtime
        self.network = patch("socket.socket.connect", side_effect=AssertionError("Network forbidden in tests"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.dns = patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden in tests"))
        self.dns.start()
        self.addCleanup(self.dns.stop)
        self.client = TestClient(voice.app)
        self.addCleanup(self.client.close)
        self.secret = secrets.token_urlsafe(32)

    def post_tool(self, tool, body):
        os.environ["VOICE_TOOLS_SHARED_SECRET"] = self.secret
        return self.client.post("/tools/" + tool, json=body, headers={"X-Voice-Webhook-Secret": self.secret})

    def test_close_packet_requires_permission(self):
        result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contract_url": "https://example.com/agreement"})
        self.assertEqual(result.json()["blocked_reason"], "missing_permission_evidence")

    def test_side_effect_urls_reject_private_and_ambiguous_hosts(self):
        bad_urls = [
            "http://example.com/a", "https://localhost/a", "https://127.0.0.1/a",
            "https://10.1.2.3/a", "https://192.168.0.1/a", "https://[::1]/a",
            "https://[::ffff:127.0.0.1]/a", "https://2130706433/a", "https://127.1/a",
            "https://0177.0.0.1/a", "https://example.com@localhost/a",
            "https://someone@example.com/a", "https://example.com:8443/a",
            "https://example.com.evil.example.invalid/a", "https://sub.example.com/a",
            "https://example.com./a", "https://example.com\\@localhost/a",
            "https://%65xample.com/a", "https://example.com/a\n",
        ]
        os.environ["VOICE_ALLOWED_LINK_HOSTS"] = "example.com,localhost,127.0.0.1,10.1.2.3,192.168.0.1,::1,2130706433,127.1,0177.0.0.1"
        for url in bad_urls:
            with self.subTest(url=url):
                result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contract_url": url, "permission_evidence": "Synthetic caller requested the SMS.", "permission_confirmed": True})
                self.assertEqual(result.status_code, 200)
                self.assertFalse(result.json()["sent"])
                self.assertTrue(result.json()["blocked_reason"].startswith("invalid_contract_url_"))

    def test_allowed_link_is_log_only_by_default(self):
        result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contract_url": "https://example.com/agreement", "permission_evidence": "Synthetic caller requested the SMS.", "permission_confirmed": True})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["blocked_reason"], "sms_delivery_disabled")
        self.assertFalse(result.json()["sent"])

    def test_all_delivery_tools_reject_missing_permission(self):
        cases = {
            "send_lead_leak_snapshot_email": {"email": "synthetic@example.com"},
            "send_lead_leak_snapshot_sms": {"phone": "+12025550100"},
            "send_sms_booking_link": {"phone": "+12025550100", "slot": "2030-01-02T14:00:00Z"},
        }
        for tool, body in cases.items():
            with self.subTest(tool=tool):
                result = self.post_tool(tool, body)
                self.assertEqual(result.json()["blocked_reason"], "missing_permission_evidence")

    def test_evidence_without_explicit_confirmation_is_rejected(self):
        for tool, body in {
            "send_lead_leak_snapshot_email": {"email": "synthetic@example.com"},
            "send_lead_leak_snapshot_sms": {"phone": "+12025550100"},
            "send_sms_close_packet": {"phone": "+12025550100"},
            "send_sms_booking_link": {"phone": "+12025550100", "slot": "2030-01-02T14:00:00Z"},
        }.items():
            with self.subTest(tool=tool):
                result = self.post_tool(tool, {**body, "permission_evidence": "Synthetic refusal: do not send.", "permission_confirmed": False})
                self.assertEqual(result.json()["blocked_reason"], "permission_not_confirmed")

    def test_snapshot_and_booking_links_are_validated(self):
        cases = {
            "send_lead_leak_snapshot_email": {"email": "synthetic@example.com", "next_step_url": "https://127.0.0.1/a"},
            "send_lead_leak_snapshot_sms": {"phone": "+12025550100", "next_step_url": "https://localhost/a"},
            "send_sms_booking_link": {"phone": "+12025550100", "slot": "2030-01-02T14:00:00Z", "calendar_url": "http://example.com/a"},
        }
        for tool, body in cases.items():
            with self.subTest(tool=tool):
                result = self.post_tool(tool, {**body, "permission_evidence": "Synthetic caller requested follow-up.", "permission_confirmed": True})
                self.assertFalse(result.json()["sent"])
                self.assertTrue(result.json()["blocked_reason"].startswith("invalid_"))

    def test_unapproved_free_text_links_cannot_bypass_link_guard(self):
        result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "summary": "Visit https://localhost/private", "permission_evidence": "Synthetic caller requested SMS.", "permission_confirmed": True})
        self.assertEqual(result.json()["blocked_reason"], "invalid_message_url_host")

    def test_demo_mode_blocks_even_configured_delivery(self):
        os.environ.update({"VOICE_SMS_DELIVERY_ENABLED": "true", "VOICE_SMS_PROVIDER": "ghl", "VOICE_GHL_API_TOKEN": secrets.token_urlsafe(32), "VOICE_GHL_LOCATION_ID": "synthetic_location", "VOICE_GHL_API_BASE_URL": "https://api.example.invalid", "VOICE_GHL_ALLOWED_API_HOSTS": "api.example.invalid"})
        result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contact_id": "synthetic_contact", "permission_evidence": "Synthetic caller requested SMS.", "permission_confirmed": True})
        self.assertEqual(result.json()["blocked_reason"], "demo_mode")
        self.assertFalse(result.json()["sent"])

    def test_outbound_intent_logs_are_metadata_only(self):
        result = self.post_tool("send_lead_leak_snapshot_sms", {"phone": "+12025550100", "contact_name": "Synthetic Unique Person", "snapshot_summary": "synthetic-private-body-marker", "permission_evidence": "synthetic-consent-marker", "permission_confirmed": True})
        self.assertFalse(result.json()["sent"])
        record = (self.runtime / "lead_leak_sms_intents.jsonl").read_text()
        for private in ("+12025550100", "Synthetic Unique Person", "synthetic-private-body-marker", "synthetic-consent-marker", self.secret):
            self.assertNotIn(private, record)

    def create_synthetic_prospect(self):
        result = self.post_tool("create_prospect", {"name": "Synthetic Person", "phone": "+12025550100", "email": "synthetic@example.com", "contact_id": "synthetic_contact"})
        self.assertEqual(result.status_code, 200)
        return result.json()["prospect_id"]

    def test_do_not_contact_blocks_phone_email_and_contact_id(self):
        prospect_id = self.create_synthetic_prospect()
        result = self.post_tool("log_call_outcome", {"prospect_id": prospect_id, "outcome": "do_not_call"})
        self.assertEqual(result.status_code, 200)
        for tool, body in {
            "send_lead_leak_snapshot_email": {"email": "SYNTHETIC@example.com"},
            "send_lead_leak_snapshot_sms": {"phone": "+12025550101", "contact_id": "synthetic_contact"},
            "send_sms_close_packet": {"phone": "+12025550100"},
            "send_sms_booking_link": {"phone": "+12025550100", "slot": "2030-01-02T14:00:00Z"},
        }.items():
            with self.subTest(tool=tool):
                delivery = self.post_tool(tool, {**body, "permission_evidence": "Synthetic caller had requested follow-up.", "permission_confirmed": True})
                self.assertEqual(delivery.json()["blocked_reason"], "do_not_call")
                self.assertFalse(delivery.json()["sent"])

    def test_dnc_corruption_fails_closed(self):
        (self.runtime / "dnc.jsonl").write_text("{broken-json\n")
        response = self.post_tool("send_lead_leak_snapshot_sms", {"phone": "+12025550100"})
        self.assertEqual(response.status_code, 503)

    def test_dnc_unknown_prospect_is_not_falsely_acknowledged(self):
        result = self.post_tool("log_call_outcome", {"prospect_id": "prospect_unknown", "outcome": "do_not_call"})
        self.assertEqual(result.status_code, 404)

    def test_path_traversal_and_id_aliases_rejected(self):
        for bad_id in ("../../other", "a/b", "a.b", "", "a" * 81):
            with self.subTest(prospect_id=bad_id):
                result = self.post_tool("look_up_audit", {"prospect_id": bad_id})
                self.assertEqual(result.status_code, 422)
                outcome = self.post_tool("log_call_outcome", {"prospect_id": bad_id, "outcome": "booked"})
                self.assertEqual(outcome.status_code, 422)

    def test_unknown_fields_and_bad_phone_rejected(self):
        for body in (
            {"name": "Synthetic Person", "phone": "not-a-phone"},
            {"name": "Synthetic Person", "phone": "+12025550100", "unexpected": "hidden-data"},
            {"name": "", "phone": "+12025550100"},
        ):
            with self.subTest(body=body):
                self.assertEqual(self.post_tool("create_prospect", body).status_code, 422)

    def test_short_configured_secret_fails_closed(self):
        os.environ["VOICE_TOOLS_SHARED_SECRET"] = secrets.token_urlsafe(4)
        response = self.client.post("/tools/check_calendar", json={"date_range": "next week"})
        self.assertEqual(response.status_code, 503)

    def test_real_local_workflow_and_placeholder_boundaries(self):
        prospect_id = self.create_synthetic_prospect()
        result = self.post_tool("check_calendar", {"date_range": "next week", "attendee": "operator"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(result.json()["slots"]), 3)
        self.assertEqual(result.json()["source"], "deterministic_example")
        transfer = self.post_tool("transfer_to_operator", {"reason": "Synthetic human review request"})
        self.assertTrue(transfer.json()["escalated"])
        self.assertFalse(transfer.json()["actual_transfer"])
        logged = self.post_tool("log_call_outcome", {"prospect_id": prospect_id, "outcome": "escalated"})
        self.assertEqual(logged.json()["path"], f"outcomes/{prospect_id}.jsonl")
        lookup = self.post_tool("look_up_audit", {"prospect_id": prospect_id})
        self.assertIsNone(lookup.json()["audit_summary"])
        audits = self.runtime / "audits"
        audits.mkdir()
        (audits / f"{prospect_id}.json").write_text(json.dumps({"synthetic": True, "observations": ["Example observation"]}))
        self.assertTrue(self.post_tool("look_up_audit", {"prospect_id": prospect_id}).json()["audit_summary"]["synthetic"])

    def test_unsigned_events_are_metadata_only_and_never_actions(self):
        os.environ.update({"VOICE_SMS_DELIVERY_ENABLED": "true", "VOICE_EMAIL_DELIVERY_ENABLED": "true", "VOICE_DEMO_MODE": "false"})
        payload = {"event": "call_analyzed", "call": {"call_id": "synthetic-private-id", "transcript": "synthetic-transcript-marker", "recording_url": "https://example.invalid/private-audio", "from_number": "+12025550100", "custom_analysis_data": {"send_sms": True}}}
        result = self.client.post("/retell/webhook", json=payload)
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.json()["trusted"])
        records = (self.runtime / "retell_events.jsonl").read_text()
        for private in ("synthetic-private-id", "synthetic-transcript-marker", "private-audio", "+12025550100", "send_sms"):
            self.assertNotIn(private, records)
        record = json.loads(records)
        self.assertEqual(set(record), {"at", "event_type", "payload_bytes", "trusted"})
        self.assertEqual(record["event_type"], "call_analyzed")
        self.assertEqual([p.name for p in self.runtime.iterdir()], ["retell_events.jsonl"])

    def test_event_name_is_allowlisted_not_arbitrary_log_content(self):
        result = self.client.post("/retell/webhook", json={"event": "synthetic-sensitive-marker"})
        self.assertEqual(result.status_code, 200)
        record = (self.runtime / "retell_events.jsonl").read_text()
        self.assertNotIn("synthetic-sensitive-marker", record)
        self.assertEqual(json.loads(record)["event_type"], "unknown")

    def test_invalid_and_oversized_events_do_not_log_raw_body(self):
        self.assertEqual(self.client.post("/retell/webhook", content="not-json-private-marker").status_code, 400)
        self.assertEqual(self.client.post("/retell/webhook", json=[]).status_code, 400)
        self.assertEqual(self.client.post("/retell/webhook", content="x" * 65537).status_code, 413)
        self.assertFalse(list(self.runtime.iterdir()))

    def test_escalation_logs_no_free_text(self):
        result = self.post_tool("transfer_to_operator", {"reason": "synthetic-private-reason-marker", "context": "synthetic-private-context-marker"})
        self.assertEqual(result.status_code, 200)
        contents = (self.runtime / "escalations.jsonl").read_text()
        self.assertNotIn("synthetic-private-reason-marker", contents)
        self.assertNotIn("synthetic-private-context-marker", contents)

    def enable_mock_adapter(self, channel="sms"):
        os.environ.update({"VOICE_DEMO_MODE": "false", f"VOICE_{channel.upper()}_DELIVERY_ENABLED": "true", f"VOICE_{channel.upper()}_PROVIDER": "ghl", "VOICE_GHL_API_TOKEN": secrets.token_urlsafe(32), "VOICE_GHL_LOCATION_ID": "synthetic_location", "VOICE_GHL_API_BASE_URL": "https://api.example.invalid", "VOICE_GHL_ALLOWED_API_HOSTS": "api.example.invalid"})

    def mock_opener(self, *, existing=False, wrong_recipient=False, status=201, malformed=False):
        captured = []
        class FixtureResponse:
            def __init__(self, body, code=200):
                self.status = code
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self, _limit=-1):
                return b"invalid-json" if malformed else json.dumps(self.body).encode()
        def open_fixture(request, timeout=20):
            body = json.loads(request.data) if request.data else None
            captured.append({"url": request.full_url, "method": request.get_method(), "body": body, "headers": dict(request.header_items()), "timeout": timeout})
            if "/contacts/?" in request.full_url:
                return FixtureResponse({"contacts": [{"id": "synthetic_wrong_contact", "phone": "+12025550109", "email": "different@example.com"}] if existing else []})
            if request.get_method() == "GET" and "/contacts/" in request.full_url:
                return FixtureResponse({"contact": {"id": "synthetic_contact", "locationId": "synthetic_location", "phone": "+12025550109" if wrong_recipient else "+12025550100", "email": "different@example.com" if wrong_recipient else "synthetic@example.com"}})
            if request.full_url.endswith("/contacts/"):
                return FixtureResponse({"contact": {"id": "synthetic_contact"}}, 201)
            if request.full_url.endswith("/conversations/messages"):
                return FixtureResponse({"messageId": "synthetic_message", "message": "synthetic-provider-private-error"}, status)
            raise AssertionError("Unexpected mocked adapter operation")
        from unittest.mock import Mock
        opener = Mock()
        opener.open.side_effect = open_fixture
        return patch.object(voice.urllib.request, "build_opener", return_value=opener), captured

    def test_mocked_sms_adapter_creates_contact_and_accepts_message(self):
        self.enable_mock_adapter()
        fixture, captured = self.mock_opener()
        with fixture:
            result = self.post_tool("send_lead_leak_snapshot_sms", {"phone": "+12025550100", "email": "synthetic@example.com", "permission_evidence": "Synthetic caller requested SMS.", "permission_confirmed": True})
        self.assertTrue(result.json()["sent"])
        self.assertEqual(result.json()["provider_message_id"], "synthetic_message")
        self.assertEqual(result.json()["contact_id"], "synthetic_contact")
        self.assertEqual(captured[-1]["body"]["type"], "SMS")
        self.assertEqual(captured[-1]["headers"]["Authorization"], "Bearer " + os.environ["VOICE_GHL_API_TOKEN"])
        self.assertTrue((self.runtime / "lead_leak_sms_sent.jsonl").exists())

    def test_mocked_email_adapter_and_html_escaping(self):
        self.enable_mock_adapter("email")
        fixture, captured = self.mock_opener()
        with fixture:
            result = self.post_tool("send_lead_leak_snapshot_email", {"email": "synthetic@example.com", "snapshot_summary": "<script>synthetic</script>", "permission_evidence": "Synthetic caller requested email.", "permission_confirmed": True})
        self.assertTrue(result.json()["sent"])
        self.assertEqual(captured[-1]["body"]["type"], "Email")
        self.assertIn("&lt;script&gt;", captured[-1]["body"]["html"])
        self.assertNotIn("<script>", captured[-1]["body"]["html"])

    def test_mocked_close_packet_adapter(self):
        self.enable_mock_adapter()
        fixture, captured = self.mock_opener()
        with fixture:
            result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contact_id": "synthetic_contact", "contract_url": "https://example.com/agreement", "payment_url": "https://example.com/payment", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True})
        self.assertTrue(result.json()["sent"])
        self.assertEqual(captured[-1]["body"]["contactId"], "synthetic_contact")
        self.assertIn("Agreement:", captured[-1]["body"]["message"])
        self.assertIn("Secure payment:", captured[-1]["body"]["message"])

    def test_explicit_contact_cannot_send_to_different_recipient(self):
        self.enable_mock_adapter()
        fixture, captured = self.mock_opener(wrong_recipient=True)
        with fixture:
            result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contact_id": "synthetic_contact", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True})
        self.assertEqual(result.json()["blocked_reason"], "ghl_contact_recipient_mismatch")
        self.assertFalse(result.json()["sent"])
        self.assertFalse(any(x["url"].endswith("/conversations/messages") for x in captured))

    def test_contact_search_does_not_accept_first_unmatched_contact(self):
        self.enable_mock_adapter()
        fixture, captured = self.mock_opener(existing=True)
        with fixture:
            result = self.post_tool("send_lead_leak_snapshot_sms", {"phone": "+12025550100", "permission_evidence": "Synthetic caller requested SMS.", "permission_confirmed": True})
        self.assertTrue(result.json()["sent"])
        self.assertEqual(result.json()["contact_id"], "synthetic_contact")
        self.assertTrue(any(x["url"].endswith("/contacts/") and x["method"] == "POST" for x in captured))

    def test_provider_failure_redacts_response_body(self):
        self.enable_mock_adapter()
        fixture, captured = self.mock_opener(status=429)
        with fixture:
            result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contact_id": "synthetic_contact", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True})
        self.assertFalse(result.json()["sent"])
        self.assertEqual(result.json()["blocked_reason"], "ghl_http_429")
        self.assertNotIn("synthetic-provider-private-error", json.dumps(result.json()))
        self.assertNotIn(os.environ["VOICE_GHL_API_TOKEN"], (self.runtime / "close_packet_sms_intents.jsonl").read_text())

    def test_malformed_provider_response_is_not_success(self):
        self.enable_mock_adapter()
        fixture, _ = self.mock_opener(malformed=True)
        with fixture:
            result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contact_id": "synthetic_contact", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True})
        self.assertFalse(result.json()["sent"])
        self.assertIsNotNone(result.json()["blocked_reason"])

    def test_adapter_configuration_is_explicit_and_validated(self):
        self.enable_mock_adapter()
        body = {"phone": "+12025550100", "contact_id": "synthetic_contact", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True}
        for variable, value, expected in (
            ("VOICE_GHL_API_TOKEN", "", "missing_ghl_api_token"),
            ("VOICE_GHL_LOCATION_ID", "", "missing_ghl_location_id"),
            ("VOICE_GHL_API_BASE_URL", "", "missing_ghl_api_base_url"),
            ("VOICE_GHL_API_BASE_URL", "https://localhost", "invalid_ghl_api_base_url_host"),
            ("VOICE_GHL_API_BASE_URL", "https://api.example.invalid@127.0.0.1", "invalid_ghl_api_base_url_authority"),
            ("VOICE_GHL_ALLOWED_API_HOSTS", "", "invalid_ghl_api_base_url_host"),
        ):
            with self.subTest(variable=variable, value=value), patch.dict(os.environ, {variable: value}):
                result = self.post_tool("send_sms_close_packet", body)
                self.assertEqual(result.json()["blocked_reason"], expected)
                self.assertFalse(result.json()["sent"])

    def exporter(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("voice_exporter", ROOT / "scripts" / "export_retell_manifest.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_contracts_match_backend_models_and_routes(self):
        contracts = json.loads((ROOT / "schemas/tools.json").read_text())
        self.assertEqual(len(contracts["tools"]), 9)
        for name, tool in contracts["tools"].items():
            with self.subTest(tool=name):
                self.assertEqual(tool["path"], "/tools/" + name)
                self.assertEqual(tool["method"], "POST")
                for side in ("request", "response"):
                    model_name = tool[side]["$ref"].split("/")[-1]
                    self.assertEqual(contracts["$defs"][model_name], getattr(voice, model_name).model_json_schema())
        self.assertEqual(contracts["$defs"]["CalendarRequest"]["properties"]["attendee"]["enum"], ["operator", "team"])

    def test_contracts_enforce_runtime_phone_and_id_constraints(self):
        from jsonschema import Draft202012Validator
        contracts = json.loads((ROOT / "schemas/tools.json").read_text())
        for schema in contracts["$defs"].values():
            Draft202012Validator.check_schema(schema)
        for name, body in (("CreateProspectRequest", {"name": "Synthetic Person", "phone": "not-a-phone"}), ("AuditLookupRequest", {"prospect_id": "../../a"})):
            with self.subTest(model=name):
                self.assertTrue(list(Draft202012Validator(contracts["$defs"][name]).iter_errors(body)))

    def test_generated_openapi_declares_fail_closed_security(self):
        runtime = voice.app.openapi()
        self.assertEqual(runtime["components"]["securitySchemes"]["VoiceWebhookSecret"]["name"], "X-Voice-Webhook-Secret")
        self.assertEqual(runtime["paths"]["/tools/create_prospect"]["post"]["security"], [{"VoiceWebhookSecret": []}])
        self.assertNotIn("security", runtime["paths"]["/retell/webhook"]["post"])

    def test_manifest_export_is_offline_and_secret_free(self):
        os.environ["VOICE_TOOLS_SHARED_SECRET"] = self.secret
        result = self.exporter().export_manifests(ROOT / "schemas/tools.json", self.runtime / "export", "https://voice.example.invalid")
        openapi = json.loads(Path(result["openapi"]).read_text())
        manifest = json.loads(Path(result["retell_tools"]).read_text())
        self.assertEqual(openapi["openapi"], "3.1.0")
        self.assertEqual(len(openapi["paths"]), 9)
        self.assertEqual(len(manifest["tools"]), 9)
        self.assertNotIn(self.secret, json.dumps([openapi, manifest]))
        for tool in manifest["tools"]:
            with self.subTest(tool=tool["name"]):
                self.assertFalse(tool["safety"]["external_side_effects_enabled"])
                self.assertEqual(tool["safety"]["authentication"]["value_source"], "VOICE_TOOLS_SHARED_SECRET")
                self.assertEqual(tool["safety"]["authentication"]["header"], "X-Voice-Webhook-Secret")
        operation = openapi["paths"]["/tools/create_prospect"]["post"]
        self.assertTrue({"200", "401", "422", "503"}.issubset(operation["responses"]))
        self.assertEqual(operation["operationId"], "voice_create_prospect")

    def test_export_rejects_bad_base_urls_before_writing(self):
        for base in ("http://example.com", "https://localhost", "https://127.0.0.1", "https://[::1]", "https://someone@example.com", "https://example.com:8443", "https://example.com?token=synthetic", "https://example.com/#fragment"):
            with self.subTest(base=base):
                destination = self.runtime / "rejected"
                with self.assertRaises(ValueError):
                    self.exporter().export_manifests(ROOT / "schemas/tools.json", destination, base)
                self.assertFalse(destination.exists())

    def test_every_tool_route_requires_configuration(self):
        contracts = json.loads((ROOT / "schemas/tools.json").read_text())
        for tool in contracts["tools"].values():
            with self.subTest(path=tool["path"]):
                self.assertEqual(self.client.post(tool["path"], json={}).status_code, 503)
        self.assertEqual(self.client.get("/tools/look_up_audit/prospect_synthetic").status_code, 503)
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_provider_helpers_cannot_bypass_disabled_delivery(self):
        request = voice.ClosePacketSmsRequest(phone="+12025550100", contact_id="synthetic_contact", permission_evidence="Synthetic caller requested packet.", permission_confirmed=True)
        sent, provider_id, reason = voice._send_ghl_close_packet_sms(request, message="Synthetic message")
        self.assertFalse(sent)
        self.assertIsNone(provider_id)
        self.assertEqual(reason, "sms_delivery_disabled")

    def test_sms_and_email_default_delivery_disabled(self):
        for tool, body, reason in (
            ("send_lead_leak_snapshot_sms", {"phone": "+12025550100"}, "sms_delivery_disabled"),
            ("send_lead_leak_snapshot_email", {"email": "synthetic@example.com"}, "email_delivery_disabled"),
        ):
            with self.subTest(tool=tool):
                result = self.post_tool(tool, {**body, "permission_evidence": "Synthetic caller requested follow-up.", "permission_confirmed": True})
                self.assertEqual(result.json()["blocked_reason"], reason)
                self.assertFalse(result.json()["sent"])

    def test_unsupported_provider_is_blocked(self):
        for provider, expected in (("", "missing_sms_provider"), ("unimplemented", "unsupported_sms_provider")):
            with self.subTest(provider=provider):
                os.environ.update({"VOICE_DEMO_MODE": "false", "VOICE_SMS_DELIVERY_ENABLED": "true", "VOICE_SMS_PROVIDER": provider})
                result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True})
                self.assertEqual(result.json()["blocked_reason"], expected)

    def test_dnc_semantically_invalid_record_fails_closed(self):
        (self.runtime / "dnc.jsonl").write_text("{}\n")
        self.assertEqual(self.post_tool("send_lead_leak_snapshot_sms", {"phone": "+12025550100"}).status_code, 503)

    def test_provider_dns_rejects_private_and_mixed_answers(self):
        for addresses in (["127.0.0.1"], ["10.0.0.1"], ["169.254.169.254"], ["::1"], ["203.0.113.10", "192.168.0.1"]):
            with self.subTest(addresses=addresses):
                answers = [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses]
                with patch("socket.getaddrinfo", return_value=answers), patch("socket.socket") as sockets:
                    with self.assertRaises(OSError):
                        voice._public_connect(("api.example.invalid", 443))
                    sockets.assert_not_called()

    def test_provider_dns_connects_to_the_checked_address(self):
        from types import SimpleNamespace
        # Reserved documentation address; classification is a local test fixture.
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 443))]
        public_fixture = SimpleNamespace(is_global=True, is_multicast=False, is_reserved=False, is_unspecified=False)
        with patch("socket.getaddrinfo", return_value=answers) as dns, patch("socket.socket") as sockets, patch.object(voice.ipaddress, "ip_address", return_value=public_fixture):
            result = voice._public_connect(("api.example.invalid", 443))
        dns.assert_called_once()
        sockets.return_value.connect.assert_called_once_with(("203.0.113.10", 443))
        self.assertIs(result, sockets.return_value)

    def test_redirects_never_forward_credentials(self):
        self.assertIsNone(voice._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.com/other"))

    def test_example_agent_config_is_not_a_deployment_claim(self):
        config = json.loads((ROOT / "config/agent.example.json").read_text())
        self.assertTrue(config["template_only"])
        self.assertEqual(config["deployment_status"], "not_deployed_or_provider_tested")
        self.assertFalse(config["provider_boundary"]["streaming_speech_engine_in_repository"])
        self.assertFalse(config["safety_defaults"]["sms_delivery_enabled"])
        self.assertFalse(config["safety_defaults"]["email_delivery_enabled"])
        self.assertFalse(config["safety_defaults"]["outbound_calls_enabled"])
        self.assertEqual(set(config["tools"]), set(json.loads((ROOT / "schemas/tools.json").read_text())["tools"]))

    def test_smoke_script_reports_synthetic_offline_results(self):
        script = ROOT / "scripts/smoke_demo.py"
        self.assertTrue(script.exists(), "Meaningful offline smoke script must exist")
        import importlib.util
        spec = importlib.util.spec_from_file_location("voice_smoke", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.run_smoke(self.runtime / "smoke")
        self.assertTrue(result["ok"])
        self.assertEqual(result["fixture_classification"], "synthetic_local_only")
        self.assertEqual(result["tool_count"], 9)
        self.assertEqual(result["exported_tool_count"], 9)
        self.assertEqual(result["network_attempts"], 0)
        self.assertFalse(result["email_sent"])
        self.assertFalse(result["sms_sent"])

    def test_provider_contact_account_and_id_are_not_assumed(self):
        self.enable_mock_adapter()
        for contact, expected in (
            ({"id": "synthetic_contact", "phone": "+12025550100"}, "ghl_contact_location_mismatch"),
            ({"id": "synthetic_contact", "phone": "+12025550100", "locationId": "synthetic_other_location"}, "ghl_contact_location_mismatch"),
            ({"id": "synthetic_other_contact", "phone": "+12025550100", "locationId": "synthetic_location"}, "ghl_contact_id_mismatch"),
        ):
            with self.subTest(expected=expected), patch.object(voice, "_get_json", return_value=(200, {"contact": contact})):
                result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contact_id": "synthetic_contact", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True})
                self.assertEqual(result.json()["blocked_reason"], expected)
                self.assertFalse(result.json()["sent"])

    def test_provider_dnd_prevents_submission(self):
        self.enable_mock_adapter()
        for flags in ({"dnd": True}, {"dndSettings": {"SMS": {"status": "active"}}}):
            with self.subTest(flags=flags), patch.object(voice, "_get_json", return_value=(200, {"contact": {"id": "synthetic_contact", "phone": "+12025550100", "locationId": "synthetic_location", **flags}})):
                result = self.post_tool("send_sms_close_packet", {"phone": "+12025550100", "contact_id": "synthetic_contact", "permission_evidence": "Synthetic caller requested packet.", "permission_confirmed": True})
                self.assertEqual(result.json()["blocked_reason"], "provider_do_not_contact")
                self.assertFalse(result.json()["sent"])

    def test_excessively_nested_unsigned_event_rejected(self):
        body = '{"event":' + '[' * 2000 + '0' + ']' * 2000 + '}'
        self.assertEqual(self.client.post("/retell/webhook", content=body).status_code, 400)
        self.assertFalse(list(self.runtime.iterdir()))

    def test_invalid_contact_ids_are_not_reflected(self):
        self.assertIsNone(voice._extract_contact_id({"contact": {"id": {"synthetic_sensitive": True}}}))
        self.assertIsNone(voice._extract_contact_id({"id": "../synthetic-sensitive"}))

    def test_message_acceptance_requires_identifier(self):
        self.assertEqual(voice._message_result(201, {}), (False, None, "provider_missing_or_invalid_message_id"))

    def test_no_configured_secret_fails_closed(self):
        response = self.client.post("/tools/create_prospect", json={"name": "Synthetic Person", "phone": "+12025550100"})
        self.assertEqual(response.status_code, 503)
        self.assertFalse(list(self.runtime.iterdir()))

    def test_missing_wrong_and_correct_secret(self):
        os.environ["VOICE_TOOLS_SHARED_SECRET"] = self.secret
        body = {"name": "Synthetic Person", "phone": "+12025550100"}
        self.assertEqual(self.client.post("/tools/create_prospect", json=body).status_code, 401)
        self.assertEqual(self.client.post("/tools/create_prospect", json=body, headers={"X-Voice-Webhook-Secret": secrets.token_urlsafe(32)}).status_code, 401)
        result = self.client.post("/tools/create_prospect", json=body, headers={"X-Voice-Webhook-Secret": self.secret})
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json()["prospect_id"].startswith("prospect_"))


if __name__ == "__main__":
    unittest.main()
