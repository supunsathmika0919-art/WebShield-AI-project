"""Inert reflected-input and HTML-encoding indicator."""

from __future__ import annotations

import html
import secrets
from typing import Any

from webshield.probe_support import ProbeRequest, make_probe_finding


def check_reflected_xss_indicator(
    request: ProbeRequest,
    *,
    path: str,
    field: str,
    resource: str,
    finding_number: int,
) -> list[dict[str, Any]]:
    marker = f"webshield-probe-{secrets.token_hex(6)}<probe>"
    status, body, _ = request(path, field, marker)
    body_text = body.decode("utf-8", errors="replace")
    escaped_marker = html.escape(marker, quote=True)
    if marker in body_text:
        return [make_probe_finding(
            f"XSS-POTENTIAL-{finding_number}",
            "Unencoded reflected test input",
            "Medium",
            "potential",
            "Low; rule-based and not calibrated",
            resource,
            f"A harmless controlled marker was reflected without HTML "
            f"encoding (HTTP {status}); no script or event payload was used.",
            "Contextually encode untrusted output and validate the relevant "
            "template context; manually verify without executing active content.",
        )]
    if escaped_marker in body_text:
        return [make_probe_finding(
            f"XSS-ENCODED-{finding_number}",
            "Reflected test input appears HTML-encoded",
            "Informational",
            "informational",
            "Low; encoding indicator only",
            resource,
            f"The harmless controlled marker appeared HTML-encoded "
            f"(HTTP {status}); this does not prove all output contexts are safe.",
            "Continue context-appropriate output encoding and use a restrictive "
            "Content Security Policy as defense in depth.",
        )]
    return []
