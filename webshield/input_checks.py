"""Bounded, non-destructive SQL error and reflected-input indicators."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import requests

from webshield.auth import _format_host, _new_session, _pinned_url
from webshield.redaction import redact_text, redact_url
from webshield.scanner import MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_SECONDS, ScanTarget
from webshield.scope import normalize_scope_path, path_is_allowed
from webshield.sqli_checker import check_sqli_indicator
from webshield.xss_checker import check_reflected_xss_indicator

MAX_PROBE_ENDPOINTS = 10
MAX_PROBE_FIELDS = 10
PROBE_INTERVAL_SECONDS = 1.0
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SENSITIVE_FIELD = re.compile(
    r"(?i)(?:password|passwd|token|secret|session|csrf|authorization|cookie|api[_-]?key)"
)


class ProbeConfigError(ValueError):
    """Probe configuration is invalid or outside approved scope."""


@dataclass(frozen=True)
class ProbeEndpoint:
    path: str
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class ProbeConfig:
    endpoints: tuple[ProbeEndpoint, ...]

    @classmethod
    def from_mapping(cls, values: Any) -> ProbeConfig:
        if not isinstance(values, dict) or not isinstance(values.get("endpoints"), list):
            raise ProbeConfigError('Probe config must contain an "endpoints" array.')
        if not 1 <= len(values["endpoints"]) <= MAX_PROBE_ENDPOINTS:
            raise ProbeConfigError(f"Configure between 1 and {MAX_PROBE_ENDPOINTS} endpoints.")
        endpoints: list[ProbeEndpoint] = []
        total_fields = 0
        try:
            for item in values["endpoints"]:
                if not isinstance(item, dict):
                    raise ProbeConfigError("Each endpoint must be a JSON object.")
                if not isinstance(item.get("path"), str) or not isinstance(
                    item.get("parameters"), list
                ):
                    raise ProbeConfigError('Each endpoint requires a string "path" and array "parameters".')
                path = normalize_scope_path(item["path"])
                parameters = tuple(dict.fromkeys(item["parameters"]))
                if any(not isinstance(name, str) for name in parameters):
                    raise ProbeConfigError("Endpoint parameter names must be strings.")
                if not parameters or any(
                    not _FIELD_NAME.fullmatch(name) or _SENSITIVE_FIELD.search(name)
                    for name in parameters
                ):
                    raise ProbeConfigError("Endpoint parameters must be safe, named input fields.")
                total_fields += len(parameters)
                endpoints.append(ProbeEndpoint(path, parameters))
        except ProbeConfigError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise ProbeConfigError('Each endpoint requires "path" and "parameters".') from error
        if total_fields > MAX_PROBE_FIELDS:
            raise ProbeConfigError(f"At most {MAX_PROBE_FIELDS} input fields may be tested per scan.")
        return cls(tuple(endpoints))


def load_probe_config(path: Path) -> ProbeConfig:
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProbeConfigError(f"Could not read probe config: {type(error).__name__}.") from error
    return ProbeConfig.from_mapping(values)


def _is_local_target(target: ScanTarget) -> bool:
    try:
        address = ipaddress.ip_address(target.resolved_ip)
    except ValueError:
        return False
    return (
        not address.is_global
        and not address.is_reserved
        and not address.is_unspecified
        and not address.is_multicast
    )


def validate_probe_scope(target: ScanTarget, config: ProbeConfig) -> None:
    if not _is_local_target(target):
        raise ProbeConfigError(
            "Input indicator checks are restricted to validated localhost/private targets."
        )
    for endpoint in config.endpoints:
        if not path_is_allowed(
            endpoint.path, target.approved_paths, target.root_is_recursive
        ):
            raise ProbeConfigError(
                f"Probe endpoint {endpoint.path} is outside the explicitly approved path scope."
            )


def _bounded_get(
    session: requests.Session,
    target: ScanTarget,
    path: str,
    field: str,
    value: str,
    cookie_header: str | None,
) -> tuple[int, bytes, str]:
    host_header = _format_host(target)
    headers = {
        "Host": host_header,
        "User-Agent": "WebShield-AI/1.0 (+authorized safe input indicators)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if cookie_header:
        headers["Cookie"] = cookie_header
    response = session.get(
        _pinned_url(target, path),
        params={field: value},
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
        stream=True,
    )
    with response:
        body = response.raw.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProbeConfigError("Probe response exceeded the configured size limit.")
        location = response.headers.get("Location", "")
        return response.status_code, body, location


def run_input_checks(
    target: ScanTarget,
    config: ProbeConfig,
    *,
    check_sqli: bool = False,
    check_xss: bool = False,
    cookie_header: str | None = None,
) -> dict[str, Any]:
    """Run only configured GET parameter checks against a validated local target."""
    if not (check_sqli or check_xss):
        raise ProbeConfigError("Select at least one safe input check.")
    validate_probe_scope(target, config)
    session = _new_session(target)
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    request_count = 0
    performed: list[str] = []
    last_request_at = 0.0

    def request(path: str, field: str, value: str) -> tuple[int, bytes, str]:
        nonlocal request_count, last_request_at
        elapsed = time.monotonic() - last_request_at
        if last_request_at and elapsed < PROBE_INTERVAL_SECONDS:
            time.sleep(PROBE_INTERVAL_SECONDS - elapsed)
        last_request_at = time.monotonic()
        request_count += 1
        return _bounded_get(session, target, path, field, value, cookie_header)

    try:
        for endpoint in config.endpoints:
            path = endpoint.path
            for field in endpoint.parameters:
                resource = target.origin + path
                if check_sqli:
                    performed.append(f"SQL error indicator: {path} parameter {field}")
                    try:
                        findings.extend(check_sqli_indicator(
                            request,
                            path=path,
                            field=field,
                            resource=resource,
                            finding_number=len(findings) + 1,
                        ))
                    except (requests.RequestException, OSError, TimeoutError, ProbeConfigError) as error:
                        errors.append({
                            "url": redact_url(resource),
                            "error": redact_text(f"SQL indicator check failed: {type(error).__name__}: {error}"),
                        })
                if check_xss:
                    performed.append(f"Reflected-input encoding: {path} parameter {field}")
                    try:
                        findings.extend(check_reflected_xss_indicator(
                            request,
                            path=path,
                            field=field,
                            resource=resource,
                            finding_number=len(findings) + 1,
                        ))
                    except (requests.RequestException, OSError, TimeoutError, ProbeConfigError) as error:
                        errors.append({
                            "url": redact_url(resource),
                            "error": redact_text(f"Reflected-input check failed: {type(error).__name__}: {error}"),
                        })
    finally:
        session.close()

    checks_skipped = ["POST/body inputs and unconfigured fields"]
    if not check_sqli:
        checks_skipped.append("SQL injection indicators (not selected)")
    if not check_xss:
        checks_skipped.append("Reflected XSS indicators (not selected)")
    else:
        checks_skipped.append("Stored XSS (forms are inspected but never submitted)")
    checks_skipped.append("Active script execution and destructive SQL testing")
    return {
        "findings": findings,
        "errors": errors,
        "checks_performed": performed,
        "checks_skipped": checks_skipped,
        "request_count": request_count,
        "limits": {
            "configured_endpoints": len(config.endpoints),
            "configured_fields": sum(len(item.parameters) for item in config.endpoints),
            "maximum_response_bytes": MAX_RESPONSE_BYTES,
            "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
            "minimum_interval_seconds": PROBE_INTERVAL_SECONDS,
        },
    }
