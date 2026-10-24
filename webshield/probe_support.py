"""Shared finding shape for harmless local input indicators."""

from __future__ import annotations

from typing import Any, Callable

from webshield.redaction import redact_text, redact_url

ProbeRequest = Callable[[str, str, str], tuple[int, bytes, str]]


def make_probe_finding(
    identifier: str,
    title: str,
    severity: str,
    status: str,
    confidence: str,
    resource: str,
    evidence: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "title": title,
        "severity": severity,
        "status": status,
        "confidence": confidence,
        "affected_resource": redact_url(resource),
        "evidence": redact_text(evidence),
        "explanation": (
            "This result is a bounded indicator from a harmless test input, not proof "
            "of an exploitable vulnerability."
        ),
        "remediation": remediation,
        "references": [],
    }
