from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from .models import Finding


_SEVERITY_RANK = {
    "unknown": 0,
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


@dataclass(frozen=True)
class EvidenceSource:
    tool: str
    family: str
    rule_id: str
    severity: str
    title: str
    identity: str | None
    compared_identity: str | None
    evidence_grade: str
    confidence: int
    evidence: dict

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CanonicalIssue:
    canonical_id: str
    canonical_key: str
    weakness: str
    title: str
    severity: str
    url: str
    confidence: int
    families: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    evidence_sources: list[EvidenceSource] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "canonical_id": self.canonical_id,
            "canonical_key": self.canonical_key,
            "weakness": self.weakness,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "confidence": self.confidence,
            "families": self.families,
            "tools": self.tools,
            "identities": self.identities,
            "source_count": len(self.evidence_sources),
            "evidence_sources": [source.to_dict() for source in self.evidence_sources],
        }


def normalized_weakness(finding: Finding) -> str:
    rule = finding.rule_id.strip().lower()
    aliases = {
        "halo.missing-hsts": "web.missing-hsts",
        "halo.missing-csp": "web.missing-csp",
        "strict-transport-security-missing": "web.missing-hsts",
        "content-security-policy-missing": "web.missing-csp",
    }
    return aliases.get(rule, rule)


def _endpoint_parts(url: str, weakness: str) -> tuple[str, str, str]:
    split = urlsplit(url)
    scheme = (split.scheme or "artifact").lower()
    host = (split.hostname or "-").lower()
    path = split.path or url or "/"
    # HSTS is an origin policy; observations on multiple paths are one issue.
    if weakness == "web.missing-hsts":
        path = "/"
    return scheme, host, path


def _key(target: str, finding: Finding) -> str:
    weakness = normalized_weakness(finding)
    scheme, host, path = _endpoint_parts(finding.url, weakness)
    parts = [target, scheme, host, path, weakness]
    # Authorization differentials are identity-sensitive; ordinary hardening and
    # contract observations are not, so corroborating identities merge as evidence.
    if finding.family == "runtime-verification":
        parts.extend([finding.identity or "-", finding.compared_identity or "-"])
    return "|".join(parts)


def canonicalize_findings(findings: list[Finding], target: str) -> list[CanonicalIssue]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(_key(target, finding), []).append(finding)

    issues: list[CanonicalIssue] = []
    for key, items in sorted(grouped.items()):
        ranked = sorted(items, key=lambda item: _SEVERITY_RANK.get(item.severity.lower(), 0), reverse=True)
        leader = ranked[0]
        weakness = normalized_weakness(leader)
        sources = [
            EvidenceSource(
                tool=item.tool,
                family=item.family,
                rule_id=item.rule_id,
                severity=item.severity,
                title=item.title,
                identity=item.identity,
                compared_identity=item.compared_identity,
                evidence_grade=item.evidence_grade,
                confidence=item.confidence,
                evidence=item.evidence,
            )
            for item in items
        ]
        identities = sorted({
            name for item in items for name in (item.identity, item.compared_identity) if name
        })
        issues.append(CanonicalIssue(
            canonical_id=hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
            canonical_key=key,
            weakness=weakness,
            title=leader.title,
            severity=leader.severity,
            url=leader.url,
            confidence=max(item.confidence for item in items),
            families=sorted({item.family for item in items}),
            tools=sorted({item.tool for item in items}),
            identities=identities,
            evidence_sources=sources,
        ))
    return issues
