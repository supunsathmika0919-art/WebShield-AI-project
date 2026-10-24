"""Quote-only SQL error and response-change indicators."""

from __future__ import annotations

import re
from typing import Any

from webshield.probe_support import ProbeRequest, make_probe_finding

_DATABASE_ERRORS = re.compile(
    r"(?i)(?:"
    r"sql syntax|syntax error at or near|unclosed quotation mark|"
    r"sqlite(?:3)?(?:\.| )error|mysql server version|"
    r"sqlstate\[[0-9a-z]+\]|pdoexception|odbc sql server|ora-\d{4,5}"
    r")"
)
def check_sqli_indicator(
    request: ProbeRequest,
    *,
    path: str,
    field: str,
    resource: str,
    finding_number: int,
) -> list[dict[str, Any]]:
    baseline_status, baseline_body, _ = request(path, field, "ws-baseline")
    probe_status, probe_body, _ = request(path, field, "'")
    body_text = probe_body.decode("utf-8", errors="replace")
    error_match = _DATABASE_ERRORS.search(body_text)
    changed = (
        baseline_status != probe_status
        or len(baseline_body) != len(probe_body)
    )
    if error_match:
        return [make_probe_finding(
            f"SQLI-POTENTIAL-{finding_number}",
            "Potential SQL injection error indicator",
            "Medium",
            "potential",
            "Low; rule-based and not calibrated",
            resource,
            f"A quote-only input produced a database error indicator "
            f"({error_match.group(0)}); baseline/probe HTTP statuses "
            f"{baseline_status}/{probe_status}.",
            "Review parameterized queries and server-side input handling; "
            "verify manually in the authorized test environment.",
        )]
    if changed:
        return [make_probe_finding(
            f"SQLI-REVIEW-{finding_number}",
            "Response changed for quote-only SQL indicator",
            "Informational",
            "informational",
            "Low; rule-based and not calibrated",
            resource,
            f"Baseline/probe HTTP statuses {baseline_status}/{probe_status}; "
            f"response sizes {len(baseline_body)}/{len(probe_body)} bytes. "
            "No known database error marker was observed.",
            "Review the differing response manually; this change alone does "
            "not indicate SQL injection.",
        )]
    return []
