from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


@dataclass
class TechnologyProfile:
    technologies: set[str] = field(default_factory=set)
    evidence: dict[str, list[str]] = field(default_factory=dict)

    def add(self, technology: str, evidence: str) -> None:
        key = technology.strip().lower()
        self.technologies.add(key)
        self.evidence.setdefault(key, []).append(evidence)

    def has(self, technology: str) -> bool:
        return technology.strip().lower() in self.technologies

    def to_dict(self) -> dict[str, Any]:
        return {
            "technologies": sorted(self.technologies),
            "evidence": {key: sorted(values) for key, values in sorted(self.evidence.items())},
        }


def resolve_technologies(repo_root: Path, target: dict[str, Any]) -> TechnologyProfile:
    """Resolve target technologies without mistaking the auditor repo for the target.

    Repository metadata is inspected only when the target explicitly declares a
    source_root. Otherwise technology evidence comes from target configuration
    and target-specific inputs.
    """
    profile = TechnologyProfile()
    for item in target.get("technologies") or []:
        profile.add(str(item), "declared in target configuration")

    target_url = str(target.get("url") or "")
    if urlsplit(target_url).scheme in {"http", "https"}:
        profile.add("web", "HTTP(S) target URL")

    source_root_value = target.get("source_root")
    source_root = None
    if source_root_value:
        candidate = (repo_root / str(source_root_value)).resolve()
        if candidate.exists():
            source_root = candidate

    if source_root is not None:
        pyproject = source_root / "pyproject.toml"
        if pyproject.is_file():
            profile.add("python", "target source pyproject.toml present")
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
                deps = [str(value).lower() for value in data.get("project", {}).get("dependencies", [])]
                if any("graphql" in dep for dep in deps):
                    profile.add("graphql", "target Python dependency metadata")
            except Exception:
                pass

        package = source_root / "package.json"
        if package.is_file():
            profile.add("node", "target source package.json present")
            try:
                data = json.loads(package.read_text(encoding="utf-8"))
                deps = {
                    str(name).lower()
                    for section in ("dependencies", "devDependencies", "peerDependencies")
                    for name in (data.get(section) or {})
                }
                if "electron" in deps:
                    profile.add("electron", "target package.json Electron dependency")
            except Exception:
                pass

    if target.get("openapi"):
        profile.add("openapi", "OpenAPI input declared")
    if target.get("graphql_schema"):
        profile.add("graphql", "GraphQL schema input declared")
    if target.get("container_image"):
        profile.add("container", "container image input declared")

    matched_iac = []
    for pattern in target.get("iac_globs") or []:
        matched_iac.extend(repo_root.glob(str(pattern)))
    if matched_iac:
        profile.add("iac", "IaC files matched configured globs")
    return profile


def family_applicability(
    family: str,
    target: dict[str, Any],
    profile: TechnologyProfile,
) -> tuple[bool, str]:
    family = family.strip().lower()
    if family in {"browser-discovery", "runtime-verification", "web-hardening"}:
        return (profile.has("web"), "requires an HTTP(S) web target")
    if family == "api-contract":
        return (profile.has("openapi"), "requires declared OpenAPI input")
    if family == "graphql-schema":
        return (profile.has("graphql"), "requires GraphQL evidence or declared schema")
    if family == "container":
        return (profile.has("container"), "requires declared container image")
    if family == "iac":
        return (profile.has("iac"), "requires matched IaC files")
    if family == "electron":
        return (profile.has("electron"), "requires Electron dependency/import evidence")
    return True, "no technology prerequisite registered"
