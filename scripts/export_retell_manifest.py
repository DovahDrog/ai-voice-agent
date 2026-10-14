#!/usr/bin/env python3
"""Export Retell-oriented import aids from standalone voice tool contracts.

Outputs:
- openapi.json: OpenAPI 3.1 webhook surface for the local FastAPI tool server.
- retell-tools.json: compact Retell-dashboard/API import aid with URLs, request schemas,
  response schemas, and safety metadata.

No network calls are made. This script only transforms local JSON contracts.
"""
from __future__ import annotations

import argparse
import json
import os
import ipaddress
import re
import urllib.parse
from copy import deepcopy
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = os.environ.get("VOICE_TOOLS_BASE_URL", "https://voice.example.invalid")

TOOL_DESCRIPTIONS: dict[str, str] = {
    "check_calendar": "Return three deterministic example slots, not live availability. date_range is not parsed.",
    "create_prospect": "Persist a caller-provided local prospect record and return its opaque prospect_id; no CRM sync.",
    "send_sms_booking_link": "Log a permission-gated booking SMS intent. No booking SMS adapter exists; sent is always false.",
    "send_sms_close_packet": "Permission-gated contract/payment/onboarding SMS via optional GHL/LeadConnector adapter. Disabled by default; no card collection.",
    "send_lead_leak_snapshot_email": "Permission-gated follow-up snapshot email via optional GHL/LeadConnector adapter. Disabled by default; honor suppression.",
    "send_lead_leak_snapshot_sms": "Permission-gated follow-up snapshot text/SMS via optional GHL/LeadConnector adapter. Disabled by default; honor suppression.",
    "transfer_to_operator": "Record an operator escalation request only; actual_transfer is false. No live telephone transfer.",
    "log_call_outcome": "Record a local call decision. do_not_call suppresses the known prospect across phone, email and contact id.",
    "look_up_audit": "Look up an explicitly supplied local JSON audit, if present. No scraping, scoring, or online analysis."
}


def _load_contracts(path: Path) -> dict[str, Any]:
    contracts = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(contracts, dict) or not isinstance(contracts.get("tools"), dict) or not isinstance(contracts.get("$defs"), dict):
        raise ValueError("Expected tool contracts and definitions")
    for name, tool in contracts["tools"].items():
        if not isinstance(tool, dict) or tool.get("method") != "POST" or tool.get("path") != f"/tools/{name}":
            raise ValueError("Invalid tool route contract")
        for side in ("request", "response"):
            ref = tool.get(side, {}).get("$ref", "")
            if not ref.startswith("#/$defs/") or ref.split("/")[-1] not in contracts["$defs"]:
                raise ValueError("Unresolved tool schema reference")
    return contracts


def validate_base_url(base_url: str) -> str:
    if not base_url or re.search(r"[\x00-\x20\x7f\\]", base_url):
        raise ValueError("Base URL must be a public HTTPS origin")
    try:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443):
            raise ValueError("Base URL must be a public HTTPS origin")
        if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Base URL must not contain a path, query or fragment")
        host = parsed.hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("IP-literal base URLs are not accepted")
        labels = host.split(".")
        if len(labels) < 2 or labels[-1].isdigit() or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".test")):
            raise ValueError("Base URL must have a public hostname")
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("Invalid base URL hostname")
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid public HTTPS base URL") from exc
    return base_url.rstrip("/")

def _dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _component_ref(ref: str) -> str:
    if not ref.startswith("#/$defs/"):
        return ref
    return ref.replace("#/$defs/", "#/components/schemas/")


def _rewrite_refs(value: Any) -> Any:
    if isinstance(value, dict):
        rewritten: dict[str, Any] = {}
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str):
                rewritten[key] = _component_ref(item)
            else:
                rewritten[key] = _rewrite_refs(item)
        return rewritten
    if isinstance(value, list):
        return [_rewrite_refs(item) for item in value]
    return value


def _schema_name(ref: str) -> str:
    return ref.rstrip("/").split("/")[-1]


def _tool_operation_id(tool_name: str) -> str:
    return f"voice_{tool_name}"


def build_openapi(contracts: dict[str, Any], base_url: str) -> dict[str, Any]:
    base_url = validate_base_url(base_url)
    components = {name: _rewrite_refs(schema) for name, schema in contracts.get("$defs", {}).items()}
    paths: dict[str, Any] = {}

    for tool_name, tool in contracts["tools"].items():
        method = tool["method"].lower()
        path = tool["path"]
        request_ref = tool["request"]["$ref"]
        response_ref = tool["response"]["$ref"]
        request_schema_ref = _component_ref(request_ref)
        response_schema_ref = _component_ref(response_ref)
        request_schema_name = _schema_name(request_ref)
        request_schema = contracts["$defs"].get(request_schema_name, {})

        operation: dict[str, Any] = {
            "operationId": _tool_operation_id(tool_name),
            "summary": tool_name.replace("_", " ").title(),
            "description": TOOL_DESCRIPTIONS.get(tool_name, contracts.get("description", "")),
            "security": [{"VoiceWebhookSecret": []}],
            "responses": {
                "200": {
                    "description": "Tool result; sent=false is a meaningful blocked/log-only outcome",
                    "content": {"application/json": {"schema": {"$ref": response_schema_ref}}},
                }
            },
            "x-voice-tool-name": tool_name,
        }

        operation["responses"].update({
            "401": {"description": "Missing or wrong tool secret"},
            "422": {"description": "Invalid tool arguments"},
            "503": {"description": "Authentication not configured or local storage unavailable"},
        })

        path_parameters = [segment[1:-1] for segment in path.split("/") if segment.startswith("{") and segment.endswith("}")]
        if path_parameters:
            properties = request_schema.get("properties", {}) if isinstance(request_schema, dict) else {}
            operation["parameters"] = [
                {
                    "name": parameter,
                    "in": "path",
                    "required": True,
                    "schema": _rewrite_refs(properties.get(parameter, {"type": "string"})),
                }
                for parameter in path_parameters
            ]

        if method != "get":
            operation["requestBody"] = {
                "required": True,
                "content": {"application/json": {"schema": {"$ref": request_schema_ref}}},
            }

        paths.setdefault(path, {})[method] = operation

    return {
        "openapi": "3.1.0",
        "info": {
            "title": contracts.get("title", "AI Voice Agent Tool Backend"),
            "version": contracts.get("version", "0.0.0"),
            "description": contracts.get("description", ""),
        },
        "servers": [{"url": base_url.rstrip("/")}],
        "paths": paths,
        "components": {
            "schemas": components,
            "securitySchemes": {
                "VoiceWebhookSecret": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Voice-Webhook-Secret",
                    "description": "Required secret from VOICE_TOOLS_SHARED_SECRET. Tools fail with 503 when unconfigured and 401 for missing/wrong headers. Never put a value in manifests.",
                }
            },
        },
    }


def build_retell_tools(contracts: dict[str, Any], base_url: str) -> dict[str, Any]:
    base = validate_base_url(base_url)
    tools: list[dict[str, Any]] = []
    for tool_name, tool in contracts["tools"].items():
        request_name = _schema_name(tool["request"]["$ref"])
        response_name = _schema_name(tool["response"]["$ref"])
        tools.append(
            {
                "name": tool_name,
                "description": TOOL_DESCRIPTIONS.get(tool_name, contracts.get("description", "")),
                "type": "custom",
                "method": tool["method"],
                "path": tool["path"],
                "url": f"{base}{tool['path']}",
                "request_schema": deepcopy(contracts["$defs"][request_name]),
                "response_schema": deepcopy(contracts["$defs"][response_name]),
                "safety": {
                    "external_side_effects_enabled": False,
                    "external_side_effects_supported": tool_name in {"send_sms_close_packet", "send_lead_leak_snapshot_email", "send_lead_leak_snapshot_sms"},
                    "may_create_remote_contact": tool_name in {"send_lead_leak_snapshot_email", "send_lead_leak_snapshot_sms"},
                    "authentication": {
                        "header": "X-Voice-Webhook-Secret",
                        "value_source": "VOICE_TOOLS_SHARED_SECRET",
                        "secret_in_manifest": False,
                    },
                    "notes": "Delivery requires explicit demo-mode opt-out, channel enablement, caller permission confirmation/evidence, DNC checks and fresh provider configuration. Booking and transfer remain local placeholders.",
                },
            }
        )

    return {
        "schema_version": "voice-retell-tools-manifest/v1",
        "contract_version": contracts.get("version"),
        "base_url": base,
        "requires_public_https_base_url_for_retell": True,
        "prior_contact_and_consent_gate_required_upstream": True,
        "provider_validation": "not_deployed_or_provider_tested",
        "request_body_mapping": "Root-level JSON arguments; configure provider tool argument mapping explicitly.",
        "tools": tools,
    }


def export_manifests(contracts_path: Path, out_dir: Path, base_url: str) -> dict[str, str]:
    base_url = validate_base_url(base_url)
    contracts = _load_contracts(contracts_path)
    openapi = build_openapi(contracts, base_url)
    retell_tools = build_retell_tools(contracts, base_url)

    openapi_path = out_dir / "openapi.json"
    retell_path = out_dir / "retell-tools.json"
    _dump_json(openapi_path, openapi)
    _dump_json(retell_path, retell_tools)
    return {"openapi": str(openapi_path), "retell_tools": str(retell_path)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts", type=Path, default=Path(__file__).resolve().parents[1] / "schemas" / "tools.json")
    parser.add_argument("--out-dir", type=Path, default=Path("build/retell"))
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--json", action="store_true", help="Print machine-readable output.")
    args = parser.parse_args()

    try:
        result = export_manifests(args.contracts, args.out_dir, args.base_url)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps({"ok": True, **result}, sort_keys=True))
    else:
        print(f"exported OpenAPI manifest: {result['openapi']}")
        print(f"exported Retell tool manifest: {result['retell_tools']}")


if __name__ == "__main__":
    main()
