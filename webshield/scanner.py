"""Target validation and bounded, single-homepage HTTP scanning."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence
from urllib.parse import urlsplit
from http.client import HTTPConnection, HTTPSConnection, HTTPException

from webshield import __version__
from webshield.analyzer import analyze, prioritize_findings
from webshield.redaction import redact_text
from webshield.scope import normalize_path, normalize_scope_path, path_is_allowed
from webshield.tls_checker import check_tls

USER_AGENT = "WebShield-AI/1.0 (+authorized, single-homepage security checks)"
REQUEST_TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 64 * 1024
RELEVANT_RESPONSE_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-frame-options",
    "location",
    "server",
    "content-type",
    "cache-control",
}


class TargetValidationError(ValueError):
    """The requested URL is outside the explicitly authorized scan scope."""


class TargetResolutionError(OSError):
    """The authorized target could not be resolved safely."""


@dataclass(frozen=True)
class ScanTarget:
    hostname: str
    scheme: str
    port: int
    path: str
    address_family: int
    sockaddr: tuple[Any, ...]
    resolved_ip: str
    approved_paths: tuple[str, ...] = ("/",)
    root_is_recursive: bool = False

    @property
    def origin(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if self.scheme == "https" else 80
        port = "" if self.port == default_port else f":{self.port}"
        return f"{self.scheme}://{host}{port}"


def _canonical_hostname(hostname: str) -> str:
    return hostname.strip().rstrip(".").lower()


def _is_permitted_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address,
                          allow_local: bool) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        return False
    if allow_local:
        return address.is_loopback or address.is_private or address.is_link_local
    return address.is_global


def validate_target(
    url: str,
    allowed_host: str,
    allow_local: bool = False,
    allowed_paths: Sequence[str] | None = None,
) -> ScanTarget:
    """Validate exact hostname scope and pin the connection to one checked address."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise TargetValidationError(f"Invalid target URL: {error}") from error

    if not hostname:
        raise TargetValidationError("The target URL must contain a hostname.")
    hostname = _canonical_hostname(hostname)
    authorized_hostname = _canonical_hostname(allowed_host)
    if not authorized_hostname or hostname != authorized_hostname:
        raise TargetValidationError("The URL hostname must exactly match --allow-host.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("URLs containing embedded credentials are not allowed.")
    if parsed.query or parsed.fragment:
        raise TargetValidationError("The target URL must not contain a query or fragment.")
    try:
        path = normalize_path(parsed.path)
        approved_paths = (
            tuple(dict.fromkeys(normalize_scope_path(item) for item in allowed_paths))
            if allowed_paths is not None
            else ("/",)
        )
    except ValueError as error:
        raise TargetValidationError(str(error)) from error
    if not approved_paths or not path_is_allowed(
        path,
        approved_paths,
        root_is_recursive=allowed_paths is not None and "/" in approved_paths,
    ):
        raise TargetValidationError("The target path is outside the explicitly approved path scope.")

    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http"):
        raise TargetValidationError("Only HTTP and HTTPS URLs are supported.")

    try:
        literal_address = ipaddress.ip_address(hostname.split("%", 1)[0])
    except ValueError:
        literal_address = None
    is_local_literal = literal_address is not None and not literal_address.is_global
    if (scheme != "https" or is_local_literal) and not allow_local:
        raise TargetValidationError(
            "Public targets require HTTPS. Use --allow-local only for an explicitly "
            "authorized localhost or private-network development target."
        )

    default_port = 443 if scheme == "https" else 80
    port = port or default_port
    if port < 1 or port > 65535:
        raise TargetValidationError("The target port is outside the valid TCP port range.")
    if not allow_local and (scheme != "https" or port != 443):
        raise TargetValidationError("Public scans support HTTPS on port 443 only.")

    try:
        records = socket.getaddrinfo(
            hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except (OSError, socket.gaierror) as error:
        raise TargetResolutionError(f"DNS resolution failed: {error}") from error
    if not records:
        raise TargetResolutionError("DNS resolution returned no usable addresses.")

    # Reject mixed public/private answers rather than choosing a convenient one.
    vetted: list[tuple[int, tuple[Any, ...], str]] = []
    seen: set[tuple[int, str]] = set()
    for family, _socktype, _proto, _canonname, sockaddr in records:
        try:
            address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        except ValueError:
            continue
        if not _is_permitted_address(address, allow_local):
            raise TargetValidationError(
                "The hostname resolves to an address outside the permitted network scope."
            )
        key = (family, str(address))
        if key not in seen:
            vetted.append((family, sockaddr, str(address)))
            seen.add(key)
    if not vetted:
        raise TargetResolutionError("DNS resolution returned no usable IP addresses.")

    family, sockaddr, resolved_ip = vetted[0]
    return ScanTarget(
        hostname=hostname,
        scheme=scheme,
        port=port,
        path=path,
        address_family=family,
        sockaddr=sockaddr,
        resolved_ip=resolved_ip,
        approved_paths=approved_paths,
        root_is_recursive=allowed_paths is not None and "/" in approved_paths,
    )


def _connect_pinned(target: ScanTarget, timeout: float) -> socket.socket:
    connection = socket.socket(target.address_family, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect(target.sockaddr)
    except OSError:
        connection.close()
        raise
    return connection


def _safe_location(value: str) -> str:
    """Keep a redirect's destination origin while discarding path and query data."""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if not hostname:
            return "Relative redirect destination (path withheld)"
        host = f"[{hostname}]" if ":" in hostname else hostname
        port = f":{parsed.port}" if parsed.port else ""
        scheme = f"{parsed.scheme}:" if parsed.scheme else ""
        prefix = "//" if parsed.netloc else ""
        return f"{scheme}{prefix}{host}{port}/"
    except ValueError:
        return "Redirect destination withheld (invalid Location value)"


class _PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, target: ScanTarget, timeout: float):
        super().__init__(target.hostname, target.port, timeout=timeout)
        self._target = target

    def connect(self) -> None:
        raw_socket = _connect_pinned(self._target, self.timeout or REQUEST_TIMEOUT_SECONDS)
        try:
            self.sock = self._context.wrap_socket(
                raw_socket, server_hostname=self._target.hostname
            )
        except Exception:
            raw_socket.close()
            raise


def _fetch_homepage(
    target: ScanTarget,
    cookie_header: str | None = None,
) -> tuple[int, dict[str, str], bool]:
    timeout = REQUEST_TIMEOUT_SECONDS
    if target.scheme == "https":
        connection: HTTPConnection = _PinnedHTTPSConnection(target, timeout)
    else:
        connection = HTTPConnection(target.hostname, target.port, timeout=timeout)
        connection.connect = lambda: setattr(
            connection, "sock", _connect_pinned(target, timeout)
        )

    host_header = target.hostname
    if ":" in host_header:
        host_header = f"[{host_header}]"
    if target.port != (443 if target.scheme == "https" else 80):
        host_header = f"{host_header}:{target.port}"
    request_headers = {
        "Host": host_header,
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Connection": "close",
    }
    if cookie_header:
        request_headers["Cookie"] = cookie_header
    try:
        connection.request(
            "GET",
            target.path,
            headers=request_headers,
        )
        response = connection.getresponse()
        headers = {
            name: _safe_location(value) if name.lower() == "location" else value
            for name, value in response.getheaders()
            if name.lower() in RELEVANT_RESPONSE_HEADERS
        }
        response.read(MAX_RESPONSE_BYTES + 1)
        return response.status, headers, response.status in (301, 302, 303, 307, 308)
    finally:
        connection.close()


def scan(
    target: ScanTarget,
    cookie_header: str | None = None,
    http_result: tuple[int | None, dict[str, str], bool] | None = None,
) -> dict[str, Any]:
    """Inspect TLS and make one bounded GET request, without following redirects."""
    scanned_at = datetime.now(timezone.utc).isoformat()
    tls_result: dict[str, Any]
    if target.scheme == "https":
        tls_result = check_tls(target)
    else:
        tls_result = {"status": "Not checked", "reason": "Local HTTP development target"}

    http_status: int | None = None
    headers: dict[str, str] = {}
    redirect = False
    network_error: str | None = None
    if http_result is not None:
        http_status, headers, redirect = http_result
        if http_status is None:
            network_error = "The crawler could not retrieve the authorized start page."
    else:
        try:
            http_status, headers, redirect = _fetch_homepage(target, cookie_header)
        except (OSError, ssl.SSLError, TimeoutError, ValueError, HTTPException) as error:
            network_error = redact_text(f"{type(error).__name__}: {error}")

    findings = analyze(
        hostname=target.hostname,
        tls=tls_result,
        headers=headers,
        http_status=http_status,
        network_error=network_error,
        redirect=redirect,
    )
    return {
        "tool": "WebShield AI",
        "version": __version__,
        "scanned_at": scanned_at,
        "target": {
            "url": target.origin + target.path,
            "origin": target.origin,
            "hostname": target.hostname,
            "resolved_ip": target.resolved_ip,
            "scope": "authorized path scope",
            "approved_paths": list(target.approved_paths),
            "redirects_followed": False,
        },
        "checks_performed": [
            "TLS certificate validation" if target.scheme == "https" else "HTTP reachability",
        ] + (["HTTP security headers"] if http_status is not None else []),
        "checks_skipped": [
            "Authentication and protected-page checks",
            "Crawling and form inspection",
            "SQL injection and XSS indicators",
        ] + (["HTTP security headers (response unavailable)"] if http_status is None else []),
        "errors": [network_error] if network_error else [],
        "status": "completed" if http_status is not None else "failed",
        "http_status": http_status,
        "response_headers": headers,
        "tls": tls_result,
        "severity_counts": {
            severity: sum(1 for finding in findings if finding["severity"] == severity)
            for severity in ("Critical", "High", "Medium", "Low", "Informational")
        },
        "findings": findings,
        "limitations": (
            "Checks are deterministic rules, not machine learning, and do not prove a "
            "website secure or vulnerable. Optional SQL/XSS tests are harmless indicators "
            "for configured GET parameters only; they cannot find every issue. Stored/DOM "
            "XSS, POST inputs, custom JavaScript login flows, and unconfigured paths are "
            "not tested. Verify potential findings manually."
        ),
    }


def authentication_failure_report(target: ScanTarget, error: str) -> dict[str, Any]:
    """Describe a failed login without attempting a protected-page request."""
    findings = prioritize_findings([{
        "id": "AUTHENTICATION-FAILED",
        "title": "Configured authentication did not succeed",
        "severity": "Informational",
        "status": "informational",
        "confidence": "High; authentication stop condition",
        "affected_resource": target.origin + target.path,
        "evidence": "The configured login flow did not satisfy its success criteria.",
        "explanation": "Protected-page scanning was stopped after authentication failed.",
        "remediation": "Review the login URL, field names, CSRF configuration, and configured indicators.",
        "references": [],
    }])
    return {
        "tool": "WebShield AI",
        "version": __version__,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "url": target.origin + target.path,
            "origin": target.origin,
            "hostname": target.hostname,
            "resolved_ip": target.resolved_ip,
            "scope": "authorized path scope",
            "approved_paths": list(target.approved_paths),
            "redirects_followed": False,
        },
        "status": "failed",
        "http_status": None,
        "response_headers": {},
        "tls": {"status": "Not checked", "reason": "Authentication did not complete"},
        "checks_performed": [],
        "checks_skipped": [
            "TLS and HTTP security-header checks",
            "Protected-page scanning",
            "Crawler and input-indicator checks",
        ],
        "errors": [redact_text(error)],
        "severity_counts": {
            severity: sum(1 for item in findings if item["severity"] == severity)
            for severity in ("Critical", "High", "Medium", "Low", "Informational")
        },
        "findings": findings,
        "limitations": (
            "Authentication failed, so no protected page was requested and no protected "
            "application security conclusions were drawn."
        ),
    }
