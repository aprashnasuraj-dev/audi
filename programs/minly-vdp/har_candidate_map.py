#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

EXACT_HOST = "minly.com"
MAX_ENTRIES = 5000
MAX_JS_FILE = 2 * 1024 * 1024
MAX_JS_TOTAL = 20 * 1024 * 1024

IDENTIFIER_KEYS = {
    "id", "user_id", "userid", "account_id", "accountid", "profile_id", "profileid",
    "creator_id", "creatorid", "booking_id", "bookingid", "order_id", "orderid",
    "payment_id", "paymentid", "wallet_id", "walletid", "message_id", "messageid",
    "media_id", "mediaid", "file_id", "fileid", "resource_id", "resourceid",
}
AUTHZ_HINTS = (
    "/account", "/profile", "/user", "/users", "/creator", "/booking", "/order",
    "/payment", "/wallet", "/message", "/media", "/upload", "/download", "/invoice",
)
BUSINESS_HINTS = (
    "/booking", "/order", "/payment", "/wallet", "/refund", "/withdraw", "/coupon",
    "/promo", "/discount", "/price", "/checkout", "/cart", "/subscription",
)
AUTH_HINTS = (
    "/login", "/signin", "/register", "/signup", "/password", "/reset", "/otp",
    "/verify", "/token", "/refresh", "/session", "/oauth",
)


def load_har(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("log"), dict):
        raise ValueError("invalid HAR: missing log object")
    entries = raw["log"].get("entries")
    if not isinstance(entries, list):
        raise ValueError("invalid HAR: log.entries must be a list")
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"HAR exceeds {MAX_ENTRIES} entry safety limit")
    return raw


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    path = re.sub(r"/[0-9]{2,}(?=/|$)", "/{id}", path)
    path = re.sub(r"/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}(?=/|$)", "/{uuid}", path)
    path = re.sub(r"/[A-Za-z0-9_-]{24,}(?=/|$)", "/{opaque}", path)
    return path


def header_names(items: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, dict) and item.get("name"):
            name = str(item["name"]).strip().lower()
            if name not in out:
                out.append(name)
    return out


def parameter_names(request: dict[str, Any], split) -> list[str]:
    names = {k.lower() for k, _ in parse_qsl(split.query, keep_blank_values=True)}
    post = request.get("postData") or {}
    for item in post.get("params") or []:
        if isinstance(item, dict) and item.get("name"):
            names.add(str(item["name"]).lower())
    mime = str(post.get("mimeType") or "").lower()
    text = post.get("text")
    if text and "json" in mime:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                names.update(str(k).lower() for k in obj.keys())
        except Exception:
            pass
    return sorted(names)


def response_json_keys(response: dict[str, Any]) -> list[str]:
    content = response.get("content") or {}
    mime = str(content.get("mimeType") or "").lower()
    text = content.get("text")
    if not text or "json" not in mime:
        return []
    if content.get("encoding"):
        return []
    try:
        obj = json.loads(text)
    except Exception:
        return []
    if isinstance(obj, dict):
        return sorted(str(k) for k in obj.keys())[:50]
    return []


def candidate_kind(path: str, params: list[str], method: str) -> list[str]:
    p = path.lower()
    kinds: list[str] = []
    if any(h in p for h in AUTHZ_HINTS) or any(k in IDENTIFIER_KEYS for k in params):
        kinds.append("authorization-object-boundary")
    if any(h in p for h in BUSINESS_HINTS):
        kinds.append("business-logic")
    if any(h in p for h in AUTH_HINTS):
        kinds.append("authentication-session")
    if method in {"PUT", "PATCH", "DELETE"} and "authorization-object-boundary" not in kinds:
        kinds.append("state-changing-authorization")
    return kinds


def maybe_extract_js(entry: dict[str, Any], target_dir: Path, index: int, total: list[int]) -> dict[str, Any] | None:
    response = entry.get("response") or {}
    content = response.get("content") or {}
    mime = str(content.get("mimeType") or "").lower()
    text = content.get("text")
    if not text or content.get("encoding") or ("javascript" not in mime and "ecmascript" not in mime):
        return None
    data = text.encode("utf-8", errors="ignore")
    if len(data) > MAX_JS_FILE or total[0] + len(data) > MAX_JS_TOTAL:
        return None
    target_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()
    p = target_dir / f"har-js-{index:04d}-{digest[:12]}.js"
    p.write_bytes(data)
    total[0] += len(data)
    return {"sha256": digest, "bytes": len(data), "temp_file": p.name}


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline exact-host HAR mapper for Minly researcher-owned sessions")
    ap.add_argument("--har", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--temp-js-dir", type=Path)
    args = ap.parse_args()

    raw = load_har(args.har)
    entries = raw["log"]["entries"]
    args.output.mkdir(parents=True, exist_ok=True)

    routes: dict[tuple[str, str], dict[str, Any]] = {}
    candidates: list[dict[str, Any]] = []
    third_party_count = 0
    exact_host_count = 0
    js_meta: list[dict[str, Any]] = []
    js_total = [0]

    for idx, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = str(request.get("url") or "")
        split = urlsplit(url)
        host = (split.hostname or "").lower()
        if host != EXACT_HOST:
            third_party_count += 1
            continue
        exact_host_count += 1
        method = str(request.get("method") or "GET").upper()
        path = normalize_path(split.path or "/")
        params = parameter_names(request, split)
        route_key = (method, path)
        item = routes.setdefault(route_key, {
            "method": method,
            "path": path,
            "parameter_names": set(),
            "statuses": set(),
            "request_header_names": set(),
            "response_header_names": set(),
            "response_json_keys": set(),
            "observations": 0,
        })
        item["parameter_names"].update(params)
        status = int(response.get("status") or 0)
        if status:
            item["statuses"].add(status)
        item["request_header_names"].update(header_names(request.get("headers")))
        item["response_header_names"].update(header_names(response.get("headers")))
        item["response_json_keys"].update(response_json_keys(response))
        item["observations"] += 1

        kinds = candidate_kind(path, params, method)
        if kinds:
            candidates.append({
                "entry_index": idx,
                "method": method,
                "path": path,
                "parameter_names": params,
                "response_status": status or None,
                "candidate_types": kinds,
                "verification_status": "Unverified",
                "next_step": "Manually reproduce using only researcher-controlled account data; do not test another user's objects.",
            })

        if args.temp_js_dir:
            meta = maybe_extract_js(entry, args.temp_js_dir, idx, js_total)
            if meta:
                js_meta.append(meta)

    route_list = []
    for item in routes.values():
        route_list.append({
            "method": item["method"],
            "path": item["path"],
            "parameter_names": sorted(item["parameter_names"]),
            "statuses": sorted(item["statuses"]),
            "request_header_names": sorted(item["request_header_names"]),
            "response_header_names": sorted(item["response_header_names"]),
            "response_json_keys": sorted(item["response_json_keys"]),
            "observations": item["observations"],
        })
    route_list.sort(key=lambda x: (x["path"], x["method"]))

    dedup: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for c in candidates:
        key = (c["method"], c["path"], tuple(c["candidate_types"]))
        if key not in dedup:
            dedup[key] = c
    candidate_list = list(dedup.values())

    result = {
        "source": "researcher-supplied authenticated HAR",
        "live_target_traffic_generated": False,
        "scope": {"exact_host": EXACT_HOST},
        "privacy": {
            "request_response_bodies_persisted": False,
            "header_values_persisted": False,
            "cookie_values_persisted": False,
            "authorization_values_persisted": False,
            "query_values_persisted": False,
        },
        "counts": {
            "har_entries": len(entries),
            "exact_host_entries": exact_host_count,
            "third_party_entries_ignored": third_party_count,
            "routes": len(route_list),
            "unverified_candidates": len(candidate_list),
            "same_origin_js_extracted_ephemerally": len(js_meta),
        },
        "routes": route_list,
        "manual_verification_queue": candidate_list,
        "ephemeral_js_metadata": js_meta,
    }
    (args.output / "har-surface-map.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result["counts"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
