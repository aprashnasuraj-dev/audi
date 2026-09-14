#!/usr/bin/env python3
"""Create a low-impact rate-limit analysis plan without running traffic."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit non-executing low-impact rate-limit plan")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = {
        "policy": {
            "execute_automatically": False,
            "non_critical_endpoints_only": True,
            "max_requests_per_second": 1,
            "stop_on_429": True,
            "no_bruteforce": True,
        },
        "endpoint": args.endpoint,
        "method": args.method.upper(),
        "manual_steps": [
            "Confirm endpoint is exact Minly scope and non-critical.",
            "Use researcher-controlled account only.",
            "Send a tiny number of normal requests at <=1 request/second.",
            "Stop on first 429, lockout warning, or degraded behavior.",
            "Do not submit non-critical rate limiting unless concrete security impact is demonstrated.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "execute_automatically": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
