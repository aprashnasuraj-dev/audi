#!/usr/bin/env python3
"""Local mobile decompiled-source secret-scan planner.

This wrapper records commands that should be run locally/CI on already obtained
artifacts. It does not download apps or expose secret values.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

COMMANDS = [
    "gitleaks detect --no-git --redact --source <decompiled_dir> --report-format json --report-path <out>/gitleaks.json",
    "trufflehog filesystem <decompiled_dir> --json --no-update > <out>/trufflehog.json",
    "python recon/js-secrets/extract_js_surface.py <decompiled_dir> --output <out>/local-surface.json",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit safe local mobile secret scan plan")
    parser.add_argument("--decompiled-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not args.decompiled_dir.exists():
        raise SystemExit(f"missing decompiled dir: {args.decompiled_dir}")
    result = {
        "policy": {"local_files_only": True, "redact_secret_values": True, "manual_validation_required": True},
        "commands": [c.replace("<decompiled_dir>", str(args.decompiled_dir)).replace("<out>", str(args.output.parent)) for c in COMMANDS],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"commands": len(result["commands"]), "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
