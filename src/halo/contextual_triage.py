from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .applicability import TechnologyProfile


class TriageDisposition(StrEnum):
    APPLICABLE = "APPLICABLE"
    EXCLUDED = "EXCLUDED"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class TriageDecision:
    disposition: TriageDisposition
    reason: str


def evaluate_contextual_signal(signal: dict[str, Any], technologies: TechnologyProfile) -> TriageDecision:
    """Contextual regression policy distilled from the prior human review.

    These rules are deliberately narrow: they encode only dispositions supported
    by the reviewed evidence and serve as regression guards for future adapters.
    """
    kind = str(signal.get("kind") or "").strip().lower()
    context = signal.get("context") or {}

    if kind == "electron_global_warning":
        if not technologies.has("electron"):
            return TriageDecision(TriageDisposition.EXCLUDED, "not applicable: no Electron evidence")
        if not context.get("file_level_evidence", False):
            return TriageDecision(TriageDisposition.EXCLUDED, "global Electron warning lacks file-level evidence")

    if kind == "technology_identifying_header":
        return TriageDecision(TriageDisposition.INFORMATIONAL, "technology disclosure alone has no demonstrated security impact")

    if kind == "dynamic_urllib":
        if context.get("https_only_validation") and context.get("redirect_revalidation"):
            return TriageDecision(TriageDisposition.EXCLUDED, "HTTPS-only validation and redirect revalidation block the flagged file-scheme path")

    if kind == "subprocess_popen":
        if context.get("argv_array") and not context.get("shell", False):
            return TriageDecision(TriageDisposition.EXCLUDED, "argument-array execution without a shell did not establish command injection")
        if context.get("local_os_open_helper"):
            return TriageDecision(TriageDisposition.EXCLUDED, "local OS open helper did not establish command injection")

    if kind == "python_compatibility":
        warned = tuple(int(part) for part in str(context.get("warned_version", "0")).split(".") if part.isdigit())
        supported = tuple(int(part) for part in str(context.get("supported_min_version", "0")).split(".") if part.isdigit())
        if warned and supported and warned < supported:
            return TriageDecision(TriageDisposition.EXCLUDED, "warning targets a Python version below the supported runtime")

    if kind == "assert_usage":
        if context.get("test_code"):
            return TriageDecision(TriageDisposition.EXCLUDED, "assertion is in test code")
        if context.get("no_exploitable_path"):
            return TriageDecision(TriageDisposition.EXCLUDED, "source review did not establish an exploitable production path")

    if kind == "yaml_load":
        if str(context.get("loader") or "").lower() == "baseloader":
            return TriageDecision(TriageDisposition.EXCLUDED, "BaseLoader does not establish the arbitrary-object construction described by the signal")

    return TriageDecision(TriageDisposition.APPLICABLE, "no reviewed exclusion rule applies")
