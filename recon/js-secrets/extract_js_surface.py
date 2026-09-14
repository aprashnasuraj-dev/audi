#!/usr/bin/env python3
"""Local JavaScript surface extractor for sanitized Minly artifacts.

Inputs are local files only: surface maps, HAR metadata exports, or text files.
The script extracts same-origin JS URLs/endpoints and redacted secret-pattern
candidates. It never fetches live JavaScript by itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

EXACT_HOST = "minly.com"
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:api|v[0-9]|auth|user|users|account|profile|booking|order|payment|wallet|message|media|graphql)[A-Za-z0-9_./{}:-]*")
SECRET_HINT_RE = re.compile(r"(?i)(api[_-]?key|secret|token|bearer|authorization|client[_-]?id|client[_-]?secret)")


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except TypeError:
        return path.read_text(encoding="utf-8")


def iter_inputs(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    for path in paths:
        if path.is_dir():
            result.extend(p for p in path.rglob("*") if p.is_file() and p.stat().st_size <= 2_000_000)
        elif path.is_file():
            result.append(path)
    return result


def sanitize_url(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.hostname and parsed.hostname.lower() != EXACT_HOST:
        return None
    if parsed.hostname:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return value.split("?", 1)[0].split("#", 1)[0]


def scan_file(path: Path) -> dict[str, Any]:
    text = load_text(path)
    urls = sorted({u for u in (sanitize_url(m.group(0)) for m in URL_RE.finditer(text)) if u})
    paths = sorted({m.group(0) for m in PATH_RE.finditer(text)})
    secret_lines = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if SECRET_HINT_RE.search(line):
            secret_lines.append({
                "line": lineno,
                "hint": SECRET_HINT_RE.search(line).group(0),  # type: ignore[union-attr]
                "sha256_16": hashlib.sha256(line.strip().encode()).hexdigest()[:16],
                "redacted": True,
            })
    return {"file": str(path), "same_origin_urls": urls[:500], "endpoint_paths": paths[:500], "secret_hints": secret_lines[:100]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract sanitized JS/API/secret hints from local artifacts")
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = [scan_file(p) for p in iter_inputs(args.inputs)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "policy": {
            "local_input_only": True,
            "live_fetching": False,
            "exact_host": EXACT_HOST,
            "secret_values_redacted": True,
            "manual_validation_required": True,
        },
        "files_scanned": len(rows),
        "results": rows,
    }, indent=2), encoding="utf-8")
    print(json.dumps({"files_scanned": len(rows), "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
