#!/usr/bin/env python3
"""Thin wrapper around existing Minly mobile static analysis phases."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Minly static mobile phases with existing safe runner")
    parser.add_argument("--platform", choices=["android-public", "ios-public"], required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/minly-final"))
    parser.add_argument("--workdir", type=Path, default=None)
    args = parser.parse_args()

    runner = Path("programs/minly-vdp/final_audit_runner.py")
    cmd = [sys.executable, str(runner), "--phase", args.platform, "--output", str(args.output)]
    if args.workdir is not None:
        cmd.extend(["--workdir", str(args.workdir)])
    print("+", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
