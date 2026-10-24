"""Rule-based findings assembly; deliberately independent of external AI services."""

from __future__ import annotations

from typing import Any

from webshield.header_checker import check_headers


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}
STATUS_ORDER = {"confirmed": 0, "potential": 1, "informational": 2}


def prioritize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply a transparent deterministic ordering; no model prediction is involved."""
    normalized: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        status = item.get("status")
        if status not in STATUS_ORDER:
            if item.get("id") in {
                "TLS-CERTIFICATE-INVALID",
                "TLS-CERTIFICATE-EXPIRED",
                "TLS-CERTIFICATE-EXPIRING",
            }:
                item["status"] = "confirmed"
            else:
                item["status"] = (
                    "informational"
                    if item.get("severity") == "Informational"
                    else "potential"
                )
        item.setdefault("confidence", "Not calibrated; deterministic rule")
        item["priority_reason"] = (
            "Rule-based order by severity and finding status; confidence is not calibrated."
        )
        normalized.append(item)
    ordered = sorted(
        normalized,
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity", ""), 5),
            STATUS_ORDER.get(item.get("status", ""), 3),
        ),
    )
    for index, finding in enumerate(ordered, start=1):
        finding["priority_rank"] = index
    return ordered


def analyze(
    hostname: str,
    tls: dict[str, Any],
    headers: dict[str, str],
    http_status: int | None,
    network_error: str | None,
    redirect: bool,
) -> list[dict[str, Any]]:
    findings = check_headers(hostname, headers) if http_status is not None else []
    if tls.get("status") == "Failed":
        error_type = tls.get("error_type", "")
        certificate_error = error_type == "SSLCertVerificationError"
        findings.append(
            {
                "id": "TLS-CERTIFICATE-INVALID" if certificate_error else "TLS-CHECK-FAILED",
                "title": "TLS certificate validation failed" if certificate_error else "TLS check could not complete",
                "severity": "High" if certificate_error else "Informational",
                "affected_resource": hostname,
                "evidence": tls.get("error", "TLS connection failed."),
                "explanation": (
                    "The system trust store rejected the presented certificate."
                    if certificate_error
                    else "A network or protocol error prevented certificate inspection; "
                    "this alone does not establish a certificate vulnerability."
                ),
                "remediation": (
                    "Serve a certificate valid for this hostname and chain it to a "
                    "trusted certificate authority."
                    if certificate_error
                    else "Check network reachability, DNS, and TLS service availability."
                ),
                "references": ["https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security"],
            }
        )
    elif tls.get("status") == "Valid":
        days_remaining = tls.get("expires_in_days")
        if isinstance(days_remaining, int) and days_remaining < 0:
            findings.append(
                {
                    "id": "TLS-CERTIFICATE-EXPIRED",
                    "title": "TLS certificate is expired",
                    "severity": "High",
                    "affected_resource": hostname,
                    "evidence": f"Certificate notAfter: {tls.get('expires_at')}",
                    "explanation": "The inspected certificate's expiration time has passed.",
                    "remediation": "Renew and deploy a valid certificate for this hostname.",
                    "references": ["https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security"],
                }
            )
        elif isinstance(days_remaining, int) and days_remaining <= 30:
            findings.append(
                {
                    "id": "TLS-CERTIFICATE-EXPIRING",
                    "title": "TLS certificate expires soon",
                    "severity": "Low",
                    "affected_resource": hostname,
                    "evidence": f"Certificate expires in {days_remaining} day(s).",
                    "explanation": "The certificate is near its advertised expiration date.",
                    "remediation": "Schedule certificate renewal before the expiration date.",
                    "references": ["https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security"],
                }
            )
        version = tls.get("tls_version")
        if version in ("TLSv1", "TLSv1.1"):
            findings.append(
                {
                    "id": "TLS-PROTOCOL-LEGACY",
                    "title": "Legacy TLS protocol negotiated",
                    "severity": "Medium",
                    "affected_resource": hostname,
                    "evidence": f"Negotiated protocol: {version}",
                    "explanation": "TLS 1.0 and 1.1 are obsolete protocol versions.",
                    "remediation": "Configure the service to support modern TLS (TLS 1.2 or newer).",
                    "references": ["https://www.rfc-editor.org/rfc/rfc8996"],
                }
            )
    if network_error:
        findings.append(
            {
                "id": "HTTP-HOMEPAGE-UNAVAILABLE",
                "title": "Homepage request failed",
                "severity": "Informational",
                "affected_resource": hostname,
                "evidence": network_error,
                "explanation": "The scanner could not retrieve the authorized homepage.",
                "remediation": "Check target availability, DNS, firewall rules, and HTTPS configuration.",
                "references": [],
            }
        )
    if http_status is not None and http_status >= 400:
        findings.append(
            {
                "id": "HTTP-STATUS-ERROR",
                "title": "Homepage returned an error status",
                "severity": "Informational",
                "affected_resource": hostname,
                "evidence": f"HTTP status: {http_status}",
                "explanation": "The homepage request received an HTTP error response.",
                "remediation": "Confirm the response is expected for the authorized homepage.",
                "references": [],
            }
        )
    if redirect:
        findings.append(
            {
                "id": "HTTP-REDIRECT-NOT-FOLLOWED",
                "title": "Homepage redirect was not followed",
                "severity": "Informational",
                "affected_resource": hostname,
                "evidence": f"HTTP {http_status}; Location: {headers.get('Location', '(not provided)')}",
                "explanation": "Redirects are reported for review and are never followed in this release.",
                "remediation": "Manually verify the destination is within your authorized scope.",
                "references": [],
            }
        )
    server_header = next(
        (value for name, value in headers.items() if name.lower() == "server"), None
    )
    if server_header:
        findings.append(
            {
                "id": "HTTP-SERVER-HEADER",
                "title": "Server response header is present",
                "severity": "Informational",
                "affected_resource": hostname,
                "evidence": f"Server: {server_header}",
                "explanation": "The response discloses a server product or configuration string.",
                "remediation": "Consider minimizing unnecessary product/version disclosure.",
                "references": [],
            }
        )
    return prioritize_findings(findings)
