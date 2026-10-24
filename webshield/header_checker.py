"""Deterministic security-header checks and actionable remediation."""

from __future__ import annotations

import re
from typing import Any

HEADER_RULES = (
    (
        "HDR-HSTS",
        "Strict-Transport-Security",
        "Medium",
        "HSTS tells supporting browsers to use HTTPS for future visits.",
        "Serve a suitable Strict-Transport-Security policy over HTTPS. Start with "
        "a reviewed max-age; includeSubDomains and preload require careful planning.",
    ),
    (
        "HDR-CSP",
        "Content-Security-Policy",
        "Medium",
        "A well-designed Content Security Policy can reduce the impact of some "
        "content-injection attacks.",
        "Define a policy for the site's actual scripts, styles, frames, and other "
        "resources. Test with report-only mode before enforcement where appropriate.",
    ),
    (
        "HDR-NOSNIFF",
        "X-Content-Type-Options",
        "Low",
        "This header helps prevent browsers from MIME-sniffing a response.",
        "Set X-Content-Type-Options: nosniff and serve accurate Content-Type values.",
    ),
    (
        "HDR-REFERRER",
        "Referrer-Policy",
        "Low",
        "This header controls referrer information sent with outgoing requests.",
        "Choose a policy appropriate to the site's navigation and privacy needs, "
        "such as strict-origin-when-cross-origin.",
    ),
    (
        "HDR-PERMISSIONS",
        "Permissions-Policy",
        "Low",
        "This header can limit browser features available to the page.",
        "Explicitly allow only the browser features and origins the site requires.",
    ),
)


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    hostname: str,
    evidence: str,
    explanation: str,
    remediation: str,
    references: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "affected_resource": hostname,
        "evidence": evidence,
        "explanation": explanation,
        "remediation": remediation,
        "references": references or [],
    }


def check_headers(hostname: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    normalized = {name.lower(): value.strip() for name, value in headers.items()}
    findings: list[dict[str, Any]] = []
    for finding_id, header, severity, explanation, remediation in HEADER_RULES:
        value = normalized.get(header.lower())
        if value is None:
            findings.append(
                _finding(
                    f"{finding_id}-MISSING",
                    f"Missing security header: {header}",
                    severity,
                    hostname,
                    f"{header} was not present in the homepage response.",
                    explanation,
                    remediation,
                    ["https://owasp.org/www-project-secure-headers/"],
                )
            )
            continue
        if header == "Strict-Transport-Security":
            max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.I)
            if not max_age or int(max_age.group(1)) < 15_552_000:
                findings.append(
                    _finding(
                        "HDR-HSTS-WEAK",
                        "Potentially weak HSTS max-age",
                        "Medium",
                        hostname,
                        f"Strict-Transport-Security: {value}",
                        "The advertised HSTS duration is absent or shorter than six months.",
                        remediation,
                        ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                    )
                )
        elif header == "X-Content-Type-Options" and value.lower() != "nosniff":
            findings.append(
                _finding(
                    "HDR-NOSNIFF-WEAK",
                    "Potentially weak X-Content-Type-Options",
                    "Low",
                    hostname,
                    f"X-Content-Type-Options: {value}",
                    "The recognized value that disables MIME sniffing is nosniff.",
                    "Set X-Content-Type-Options: nosniff.",
                    ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                )
            )
        elif header == "Referrer-Policy" and value.lower() in (
            "unsafe-url",
            "no-referrer-when-downgrade",
        ):
            findings.append(
                _finding(
                    "HDR-REFERRER-WEAK",
                    "Potentially permissive Referrer-Policy",
                    "Low",
                    hostname,
                    f"Referrer-Policy: {value}",
                    "This policy may send more referrer information than necessary.",
                    remediation,
                    ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"],
                )
            )

    csp = normalized.get("content-security-policy", "")
    frame_ancestors = re.search(
        r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I
    )
    framed_by_csp = bool(
        frame_ancestors
        and frame_ancestors.group(1).strip().lower() not in ("*", "http:", "https:")
    )
    x_frame_options = normalized.get("x-frame-options", "").lower()
    valid_x_frame_options = x_frame_options in ("deny", "sameorigin")
    if not framed_by_csp and not valid_x_frame_options:
        findings.append(
            _finding(
                "HDR-FRAMING-MISSING",
                "No recognized clickjacking framing policy",
                "Medium",
                hostname,
                "Neither a restrictive Content-Security-Policy frame-ancestors "
                "directive nor X-Frame-Options: DENY/SAMEORIGIN was observed.",
                "A suitable framing policy can help protect pages from unwanted embedding.",
                "Set an appropriate CSP frame-ancestors directive. Use X-Frame-Options "
                "for compatibility where required; allow trusted framing only when intended.",
                ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"],
            )
        )
    return findings
