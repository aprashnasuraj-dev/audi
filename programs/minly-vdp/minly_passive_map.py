#!/usr/bin/env python3
"""Low-impact, exact-host Minly public-surface mapper.

This script is intentionally conservative for the Minly VDP:
- exact host only (minly.com)
- GET/navigation only
- no form submission
- no brute force/fuzzing
- no subdomain discovery
- no active probing of observed API candidates
- third-party requests are blocked
- query values are redacted from output

It is a candidate-discovery tool, not a vulnerability scanner.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import time
from collections import deque
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from playwright.async_api import async_playwright

ALLOWED_HOST = "minly.com"
SEED = "https://minly.com/"

PATH_RE = re.compile(r"(?P<q>['\"])(?P<path>/(?:api|graphql|v\d+|account|profile|creator|booking|order|payment|wallet|message|upload|media|admin|auth)[A-Za-z0-9_./?&=%:{}\-]*)\1", re.I)
WS_RE = re.compile(r"wss?://[^'\"\s)]+", re.I)
SINKS = {
    "innerHTML": re.compile(r"\.innerHTML\s*=", re.I),
    "outerHTML": re.compile(r"\.outerHTML\s*=", re.I),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML\s*\(", re.I),
    "document.write": re.compile(r"document\.write\s*\(", re.I),
    "eval": re.compile(r"\beval\s*\(", re.I),
    "Function": re.compile(r"\bnew\s+Function\s*\(", re.I),
    "postMessage-listener": re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I),
    "localStorage": re.compile(r"\blocalStorage\b", re.I),
    "sessionStorage": re.compile(r"\bsessionStorage\b", re.I),
}


def sanitize_url(url: str) -> str:
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    redacted = urlencode([(k, "REDACTED") for k, _ in pairs])
    return urlunsplit((p.scheme, p.netloc, p.path or "/", redacted, ""))


def exact_scope(url: str) -> bool:
    try:
        p = urlsplit(url)
    except Exception:
        return False
    return p.scheme in {"http", "https"} and (p.hostname or "").lower() == ALLOWED_HOST


@dataclass
class PageRecord:
    url: str
    status: int | None
    title: str
    links: list[str]
    forms: list[dict]
    scripts: list[str]


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="artifacts/minly-passive")
    ap.add_argument("--max-pages", type=int, default=12)
    ap.add_argument("--request-budget", type=int, default=80)
    ap.add_argument("--delay-ms", type=int, default=1200)
    ap.add_argument("--settle-ms", type=int, default=900)
    args = ap.parse_args()

    if args.max_pages > 20 or args.request_budget > 120 or args.delay_ms < 750:
        raise SystemExit("refusing unsafe limits: max_pages<=20, request_budget<=120, delay_ms>=750")

    out = Path(args.output)
    js_dir = out / "_temp_js"
    out.mkdir(parents=True, exist_ok=True)
    js_dir.mkdir(parents=True, exist_ok=True)

    queue = deque([SEED])
    visited: set[str] = set()
    pages: list[PageRecord] = []
    observed_api: set[str] = set()
    external_hosts: set[str] = set()
    js_urls: set[str] = set()
    request_count = 0
    blocked_count = 0
    response_status: dict[str, int] = {}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=False)

        async def route_handler(route):
            nonlocal request_count, blocked_count
            req = route.request
            url = req.url
            host = (urlsplit(url).hostname or "").lower()
            if host != ALLOWED_HOST:
                if host:
                    external_hosts.add(host)
                blocked_count += 1
                await route.abort()
                return
            if request_count >= args.request_budget:
                blocked_count += 1
                await route.abort()
                return
            request_count += 1
            await asyncio.sleep(args.delay_ms / 1000)
            await route.continue_()

        await context.route("**/*", route_handler)

        def on_response(resp):
            if exact_scope(resp.url):
                response_status[sanitize_url(resp.url)] = resp.status
                rt = resp.request.resource_type
                if rt in {"xhr", "fetch", "websocket"}:
                    observed_api.add(sanitize_url(resp.url))
                if rt == "script":
                    js_urls.add(resp.url)

        context.on("response", on_response)

        while queue and len(pages) < args.max_pages and request_count < args.request_budget:
            target = queue.popleft()
            clean = sanitize_url(target)
            if clean in visited or not exact_scope(target):
                continue
            visited.add(clean)
            page = await context.new_page()
            try:
                resp = await page.goto(target, wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(args.settle_ms)
                current = page.url
                if not exact_scope(current):
                    host = (urlsplit(current).hostname or "").lower()
                    if host:
                        external_hosts.add(host)
                    continue
                title = await page.title()
                raw_links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                links = []
                for href in raw_links:
                    if exact_scope(href):
                        s = sanitize_url(href)
                        links.append(s)
                        if s not in visited and s not in queue:
                            queue.append(href)
                    else:
                        host = (urlsplit(href).hostname or "").lower()
                        if host:
                            external_hosts.add(host)
                forms = await page.eval_on_selector_all(
                    "form",
                    "els => els.map(f => ({method:(f.method||'get').toUpperCase(), action:f.action||location.href, inputs:[...f.querySelectorAll('input,select,textarea')].map(i => ({name:i.name||'', type:i.type||i.tagName.toLowerCase()}))}))",
                )
                safe_forms = []
                for form in forms:
                    action = form.get("action") or current
                    safe_forms.append({
                        "method": form.get("method", "GET"),
                        "action": sanitize_url(action) if exact_scope(action) else "OUT_OF_SCOPE",
                        "inputs": form.get("inputs", []),
                    })
                scripts = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                scoped_scripts = [sanitize_url(s) for s in scripts if exact_scope(s)]
                for s in scripts:
                    if exact_scope(s):
                        js_urls.add(s)
                pages.append(PageRecord(
                    url=sanitize_url(current),
                    status=resp.status if resp else response_status.get(sanitize_url(current)),
                    title=title[:200],
                    links=sorted(set(links)),
                    forms=safe_forms,
                    scripts=sorted(set(scoped_scripts)),
                ))
            except Exception as exc:
                pages.append(PageRecord(clean, None, f"ERROR: {type(exc).__name__}", [], [], []))
            finally:
                await page.close()

        # Reuse the already-authorized exact-host context to fetch only JS URLs that
        # were naturally observed. No guessed endpoints are requested.
        js_findings = []
        for idx, js_url in enumerate(sorted(js_urls)):
            if request_count >= args.request_budget or not exact_scope(js_url):
                break
            try:
                resp = await context.request.get(js_url, timeout=15000)
                request_count += 1
                if not resp.ok:
                    continue
                body = await resp.text()
                digest = hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()
                tmp = js_dir / f"bundle-{idx:03d}-{digest[:12]}.js"
                tmp.write_text(body, encoding="utf-8", errors="ignore")
                paths = sorted({m.group("path") for m in PATH_RE.finditer(body)})[:200]
                ws = sorted(set(WS_RE.findall(body)))[:50]
                sink_counts = {name: len(rx.findall(body)) for name, rx in SINKS.items()}
                js_findings.append({
                    "source_url": sanitize_url(js_url),
                    "sha256": digest,
                    "candidate_paths": paths,
                    "websocket_candidates": [sanitize_url(u) if exact_scope(u) else "OUT_OF_SCOPE_HOST" for u in ws],
                    "pattern_counts": sink_counts,
                })
            except Exception:
                continue

        await context.close()
        await browser.close()

    queue_items = []
    for p in pages:
        for form in p.forms:
            method = (form.get("method") or "GET").upper()
            if method not in {"GET", "HEAD"}:
                queue_items.append({"priority": "high", "type": "state-changing-form", "page": p.url, "action": form.get("action"), "method": method})
    for api in sorted(observed_api):
        queue_items.append({"priority": "high", "type": "observed-api", "url": api, "instruction": "Manually test only with researcher-controlled account/data; do not replay automatically."})
    for j in js_findings:
        for path in j["candidate_paths"][:50]:
            queue_items.append({"priority": "medium", "type": "client-route-candidate", "path": path, "instruction": "Validate through normal UI first; do not blindly request guessed paths."})

    summary = {
        "scope": {"seed": SEED, "exact_host": ALLOWED_HOST, "third_party_requests": "blocked"},
        "limits": {"max_pages": args.max_pages, "request_budget": args.request_budget, "delay_ms": args.delay_ms},
        "counts": {
            "requests_allowed": request_count,
            "requests_blocked": blocked_count,
            "pages": len(pages),
            "observed_api_candidates": len(observed_api),
            "same_origin_js": len(js_findings),
            "external_hosts_observed_not_tested": len(external_hosts),
            "manual_queue": len(queue_items),
        },
        "pages": [asdict(p) for p in pages],
        "observed_api_candidates": sorted(observed_api),
        "external_hosts_observed_not_tested": sorted(external_hosts),
        "javascript_analysis": js_findings,
        "manual_verification_queue": queue_items,
    }
    (out / "surface-map.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    md = [
        "# Minly public-surface research map",
        "",
        "> Candidate-discovery output only. Nothing in this file is a confirmed vulnerability.",
        "",
        f"- Exact host tested: `{ALLOWED_HOST}`",
        f"- Pages mapped: **{len(pages)}**",
        f"- Requests allowed: **{request_count}** / {args.request_budget}",
        f"- Third-party/out-of-scope requests blocked: **{blocked_count}**",
        f"- Observed API candidates: **{len(observed_api)}**",
        f"- Same-origin JS bundles analyzed: **{len(js_findings)}**",
        f"- Manual verification queue: **{len(queue_items)}**",
        "",
        "## Manual authorization-first queue",
    ]
    for item in queue_items[:200]:
        md.append(f"- **{item['priority']}** `{item['type']}` — `{item.get('url') or item.get('action') or item.get('path') or item.get('page')}`")
    md += ["", "## External hosts observed but not tested"]
    for host in sorted(external_hosts):
        md.append(f"- `{host}`")
    (out / "surface-map.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    # Raw JS is temporary and must never be uploaded as an artifact by default.
    print(json.dumps(summary["counts"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
