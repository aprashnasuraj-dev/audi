#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

EXACT_WEB_HOST = "minly.com"
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
OBJECT_KEY_HINTS = {
    "id", "user_id", "userid", "userId", "account_id", "accountId", "order_id", "orderId",
    "request_id", "requestId", "booking_id", "bookingId", "message_id", "messageId",
    "thread_id", "threadId", "event_id", "eventId", "media_id", "mediaId", "creator_id", "creatorId",
}
BUSINESS_KEY_HINTS = {
    "amount", "price", "currency", "discount", "coupon", "status", "role", "type", "owner",
    "owner_id", "ownerId", "recipient", "recipient_id", "recipientId", "public", "private",
    "entitlement", "permission", "callback", "redirect", "return_url", "returnUrl",
}
STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ID_SEGMENT = re.compile(r"(?i)^(?:[0-9]{2,}|[0-9a-f]{8,}|[A-Za-z0-9_-]{20,})$")


def redact_headers(headers):
    output = []
    sensitive_present = []
    for item in headers or []:
        name = str(item.get("name", ""))
        value = str(item.get("value", ""))
        if name.lower() in SENSITIVE_HEADERS:
            sensitive_present.append(name.lower())
            value = "<redacted>"
        output.append({"name": name, "value": value})
    return output, sorted(set(sensitive_present))


def json_keys(text: str, mime_type: str) -> list[str]:
    if "json" not in (mime_type or "").lower() or not text:
        return []
    try:
        payload = json.loads(text)
    except Exception:
        return []
    keys: set[str] = set()

    def walk(value, depth=0):
        if depth > 4:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                keys.add(str(key))
                walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value[:5]:
                walk(child, depth + 1)

    walk(payload)
    return sorted(keys)


def template_path(path: str) -> str:
    parts = []
    for part in path.split("/"):
        if ID_SEGMENT.match(part):
            parts.append("{id}")
        else:
            parts.append(part)
    return "/".join(parts)


def classify_scope(host: str) -> str:
    if host == EXACT_WEB_HOST:
        return "exact_web_scope"
    if host.endswith(".minly.com"):
        return "minly_sibling_boundary_not_authorized_by_web_scope"
    return "external_boundary"


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline analysis of a sanitized researcher HAR")
    parser.add_argument("har")
    parser.add_argument("--output", default="artifacts/minly-adaptive/har-analysis")
    args = parser.parse_args()

    har_path = Path(args.har)
    data = json.loads(har_path.read_text(encoding="utf-8"))
    entries = ((data.get("log") or {}).get("entries") or [])
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    records = []
    host_counts = Counter()
    sensitive_header_names = set()

    for entry in entries:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = str(request.get("url", ""))
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        method = str(request.get("method", "GET")).upper()
        scope_class = classify_scope(host)
        host_counts[scope_class] += 1

        _, sensitive = redact_headers(request.get("headers") or [])
        sensitive_header_names.update(sensitive)

        post = request.get("postData") or {}
        request_keys = json_keys(str(post.get("text", "")), str(post.get("mimeType", "")))
        response_content = response.get("content") or {}
        response_keys = json_keys(str(response_content.get("text", "")), str(response_content.get("mimeType", "")))
        query_keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        all_keys = set(request_keys) | set(response_keys) | set(query_keys)

        object_hints = sorted(key for key in all_keys if key in OBJECT_KEY_HINTS or key.lower().endswith("id"))
        business_hints = sorted(key for key in all_keys if key in BUSINESS_KEY_HINTS)

        risk_cues = []
        if method in STATE_METHODS:
            risk_cues.append("state_changing_operation")
        if object_hints:
            risk_cues.append("object_identifier_present")
        if business_hints:
            risk_cues.append("business_or_authorization_field_present")
        if "graphql" in parsed.path.lower():
            risk_cues.append("graphql_observed")
        if any(token in parsed.path.lower() for token in ("auth", "login", "session", "recover", "reset", "verify")):
            risk_cues.append("authentication_state_surface")
        if any(token in parsed.path.lower() for token in ("order", "book", "request", "payment", "refund", "event", "ticket")):
            risk_cues.append("business_state_surface")
        if any(token in parsed.path.lower() for token in ("message", "thread", "chat", "media", "upload", "video", "voice")):
            risk_cues.append("content_or_messaging_surface")

        records.append({
            "method": method,
            "host": host,
            "scope_class": scope_class,
            "path_template": template_path(parsed.path or "/"),
            "status": response.get("status"),
            "query_keys": query_keys,
            "request_json_keys": request_keys,
            "response_json_keys": response_keys,
            "object_key_hints": object_hints,
            "business_key_hints": business_hints,
            "risk_cues": risk_cues,
            "request_has_sensitive_headers": bool(sensitive),
        })

    # Deduplicate by method/host/template while preserving the richest observed metadata.
    merged = {}
    for record in records:
        key = (record["method"], record["host"], record["path_template"])
        current = merged.setdefault(key, {
            **record,
            "statuses": [],
            "query_keys": [],
            "request_json_keys": [],
            "response_json_keys": [],
            "object_key_hints": [],
            "business_key_hints": [],
            "risk_cues": [],
        })
        if record["status"] is not None and record["status"] not in current["statuses"]:
            current["statuses"].append(record["status"])
        for field in ("query_keys", "request_json_keys", "response_json_keys", "object_key_hints", "business_key_hints", "risk_cues"):
            current[field] = sorted(set(current[field]) | set(record[field]))
        current["request_has_sensitive_headers"] = current["request_has_sensitive_headers"] or record["request_has_sensitive_headers"]

    inventory = sorted(merged.values(), key=lambda item: (item["scope_class"], item["host"], item["path_template"], item["method"]))
    payload = {
        "source": har_path.name,
        "network_requests_analyzed": len(entries),
        "unique_operation_templates": len(inventory),
        "scope_counts": dict(host_counts),
        "sensitive_header_names_detected": sorted(sensitive_header_names),
        "operations": inventory,
        "rules": {
            "live_requests_sent_by_analyzer": 0,
            "credentials_exported": False,
            "sibling_minly_hosts_are_boundaries_not_automatically_authorized": True,
        },
    }
    (out / "operation-inventory.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Minly Offline HAR Operation Inventory",
        "",
        f"Analyzed {len(entries)} captured requests into {len(inventory)} unique operation templates.",
        "",
        "This is offline evidence triage, not a vulnerability report. Raw tokens/cookies are never emitted.",
        "",
        "| Scope | Method | Host | Path template | Status | Risk cues |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in inventory:
        lines.append(
            f"| {item['scope_class']} | {item['method']} | `{item['host']}` | `{item['path_template']}` | {','.join(map(str, item['statuses']))} | {', '.join(item['risk_cues']) or '-'} |"
        )
    (out / "operation-inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"offline HAR analysis complete: {len(inventory)} operation templates; no live traffic sent")


if __name__ == "__main__":
    main()
