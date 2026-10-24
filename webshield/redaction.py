"""Redaction helpers for URLs and report content."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|token|access_token|refresh_token|code|state|"
    r"authorization|cookie|set-cookie|session(?:_id)?|csrf(?:_token)?|"
    r"api[_-]?key|client[_-]?secret|private[_-]?key|secret)\b"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_CSP_NONCE_PATTERN = re.compile(r"(?i)\bnonce-([A-Za-z0-9._~+/=-]+)")
_SENSITIVE_PATH_SEGMENTS = frozenset(
    {"session", "sessions", "token", "tokens", "csrf", "reset", "invite", "magic-link"}
)


def redact_url(value: str) -> str:
    """Remove URL userinfo, query values, and fragments."""
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc:
            return value
        hostname = parsed.hostname
        if hostname is None:
            return "[URL REDACTED]"
        host = f"[{hostname}]" if ":" in hostname else hostname
        port = f":{parsed.port}" if parsed.port is not None else ""
        path_segments = parsed.path.split("/")
        for index, segment in enumerate(path_segments[:-1]):
            if segment.lower() in _SENSITIVE_PATH_SEGMENTS:
                path_segments[index + 1] = "%5BREDACTED%5D"
        path = "/".join(path_segments)
        query = urlencode(
            [(name, REDACTED) for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        )
        return urlunsplit((parsed.scheme, f"{host}{port}", path, query, ""))
    except ValueError:
        return "[URL REDACTED]"


def redact_text(value: str) -> str:
    """Redact URL query values, common credential assignments, and auth tokens."""
    value = _URL_PATTERN.sub(lambda match: redact_url(match.group(0)), value)
    value = _BEARER_PATTERN.sub(lambda match: f"{match.group(1)} {REDACTED}", value)
    value = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", value
    )
    value = _CSP_NONCE_PATTERN.sub(f"nonce-{REDACTED}", value)
    return value


def redact_report(value: Any, key: str = "") -> Any:
    """Return a report-safe copy with sensitive fields and values redacted."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for child_key, child_value in value.items():
            normalized_key = str(child_key).lower().replace("-", "_")
            if any(
                marker in normalized_key
                for marker in (
                    "password", "passwd", "credential", "authorization", "cookie",
                    "csrf", "session", "secret", "api_key", "access_token", "refresh_token",
                    "token", "private_key",
                )
            ):
                sanitized[child_key] = REDACTED
            else:
                sanitized[child_key] = redact_report(child_value, normalized_key)
        return sanitized
    if isinstance(value, list):
        return [redact_report(item, key) for item in value]
    if isinstance(value, tuple):
        return [redact_report(item, key) for item in value]
    if isinstance(value, str):
        if key in ("url", "origin") or value.lower().startswith(("http://", "https://")):
            return redact_url(value)
        return redact_text(value)
    return value
