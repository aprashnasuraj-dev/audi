#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


SEED = "https://minly.com/"
EXPECTED_HOST = "minly.com"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Locally capture a researcher-owned Minly Playwright session without storing credentials in Git."
    )
    parser.add_argument("--account", choices=["a", "b"], default="a")
    parser.add_argument("--output-dir", type=Path, default=Path(".halo-auth/minly"))
    return parser.parse_args()


async def main_async(args: argparse.Namespace) -> int:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise SystemExit("Playwright is required. Install with: pip install -e '.[browser]' && python -m playwright install chromium") from exc

    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    state_path = out / f"minly-user-{args.account}-storage-state.json"
    har_path = out / f"minly-user-{args.account}.har"
    metadata_path = out / f"minly-user-{args.account}-capture.json"

    print("Opening Minly in a local Chromium window.")
    print("Log in manually with your own researcher-controlled account.")
    print("Do not test third-party sites or another user's data during this capture.")
    print("When you are visibly logged in on minly.com, return here and press Enter.")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False)
        context = await browser.new_context(
            record_har_path=str(har_path),
            record_har_mode="minimal",
            record_har_content="omit",
        )
        page = await context.new_page()
        await page.goto(SEED, wait_until="domcontentloaded", timeout=30_000)
        await asyncio.to_thread(input, "Press Enter after login is complete: ")

        host = (urlsplit(page.url).hostname or "").lower().rstrip(".")
        if host != EXPECTED_HOST:
            print(f"Refusing to export session while top-level page is outside exact scope: {host!r}")
            await context.close()
            await browser.close()
            return 2

        await context.storage_state(path=str(state_path))
        metadata = {
            "account_label": args.account.upper(),
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "seed": SEED,
            "final_url": page.url,
            "final_title": await page.title(),
            "storage_state_path": str(state_path),
            "har_path": str(har_path),
            "note": "Local sensitive research material. Do not commit.",
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        await context.close()
        await browser.close()

    print(f"Storage state: {state_path}")
    print(f"Minimal HAR:   {har_path}")
    print(f"Metadata:      {metadata_path}")
    print("Keep all three files private. The storage-state file contains live session material.")
    return 0


def main() -> int:
    return asyncio.run(main_async(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
