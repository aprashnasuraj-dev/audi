#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

ROOT = "https://minly.com/"
HOST = "minly.com"
SKIP_PATH_TOKENS = {
    "logout",
    "delete",
    "remove",
    "unsubscribe",
    "cancel",
    "confirm",
    "purchase",
    "checkout",
    "payment",
    "pay/",
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, str]] = []
        self.title_parts: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs):
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "form":
            self.forms.append({
                "action": values.get("action", ""),
                "method": values.get("method", "GET").upper(),
            })
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str):
        if self._in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part)[:200]


def normalize(url: str, base: str) -> str | None:
    absolute = urljoin(base, url)
    parsed = urlparse(absolute)
    if parsed.scheme != "https" or parsed.hostname != HOST:
        return None
    if parsed.username or parsed.password:
        return None
    path_lower = (parsed.path or "/").lower()
    if any(token in path_lower for token in SKIP_PATH_TOKENS):
        return None
    # Do not expand query-space. Preserve a query only on the seed page supplied by the researcher.
    cleaned = parsed._replace(fragment="", query="")
    return urlunparse(cleaned)


def main() -> None:
    parser = argparse.ArgumentParser(description="Low-volume public mapper for the exact Minly website scope")
    parser.add_argument("--max-pages", type=int, default=12)
    parser.add_argument("--delay-seconds", type=float, default=2.6)
    parser.add_argument("--output", default="artifacts/minly-adaptive/public-map.json")
    args = parser.parse_args()

    if args.max_pages < 1 or args.max_pages > 12:
        raise SystemExit("max-pages must be between 1 and 12")
    if args.delay_seconds < 2.5:
        raise SystemExit("delay-seconds must be at least 2.5 (<=0.4 requests/second)")

    queue = deque([ROOT])
    queued = {ROOT}
    visited: set[str] = set()
    pages: list[dict] = []
    cross_host_redirects: list[dict] = []

    headers = {
        "User-Agent": "Minly-VDP-Research-Mapping/1.0 (low-volume; GET-only)",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
    }

    with httpx.Client(headers=headers, timeout=10.0, follow_redirects=False) as client:
        while queue and len(visited) < args.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            if visited:
                time.sleep(args.delay_seconds)
            visited.add(url)

            record = {"url": url, "method": "GET", "status": None, "title": "", "forms": [], "same_host_links": [], "error": None}
            try:
                response = client.get(url)
                record["status"] = response.status_code

                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if location:
                        destination = urljoin(url, location)
                        parsed = urlparse(destination)
                        if parsed.hostname == HOST and parsed.scheme == "https":
                            normalized = normalize(destination, url)
                            if normalized and normalized not in queued and normalized not in visited:
                                queue.append(normalized)
                                queued.add(normalized)
                        else:
                            cross_host_redirects.append({"source": url, "destination_host": parsed.hostname, "followed": False})
                    pages.append(record)
                    continue

                ctype = response.headers.get("content-type", "")
                if "text/html" not in ctype.lower():
                    pages.append(record)
                    continue

                parser_ = PageParser()
                parser_.feed(response.text[:2_000_000])
                record["title"] = parser_.title

                forms = []
                for form in parser_.forms:
                    action = urljoin(url, form["action"] or url)
                    p = urlparse(action)
                    forms.append({
                        "method": form["method"],
                        "action_host": p.hostname,
                        "action_path": p.path,
                        "same_host": p.hostname == HOST,
                    })
                record["forms"] = forms

                discovered: list[str] = []
                for href in parser_.links:
                    normalized = normalize(href, url)
                    if not normalized:
                        continue
                    if normalized not in discovered:
                        discovered.append(normalized)
                    if normalized not in queued and normalized not in visited and len(queued) < 40:
                        queue.append(normalized)
                        queued.add(normalized)
                record["same_host_links"] = discovered[:60]
            except Exception as exc:  # evidence collection should preserve the failure, not hide it
                record["error"] = f"{type(exc).__name__}: {exc}"
            pages.append(record)

    payload = {
        "scope": ROOT,
        "exact_host": HOST,
        "mode": "public_surface",
        "state_mutation": False,
        "cross_host_redirects_followed": False,
        "request_count": len(visited),
        "max_pages": args.max_pages,
        "delay_seconds": args.delay_seconds,
        "pages": pages,
        "cross_host_redirects": cross_host_redirects,
        "disclaimer": "Mapping evidence only. It is not a vulnerability finding and must be manually reviewed before any report.",
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"mapped {len(visited)} exact-host public pages with GET-only low-volume requests")


if __name__ == "__main__":
    main()
