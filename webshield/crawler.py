"""Bounded, GET-only same-origin page and form discovery."""

from __future__ import annotations

import ipaddress
import re
import time
from html.parser import HTMLParser
from typing import Any, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit

import requests

from webshield.auth import _format_host, _new_session, _pinned_url, _read_bounded
from webshield.header_checker import check_headers
from webshield.redaction import redact_text, redact_url
from webshield.scanner import (
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    RELEVANT_RESPONSE_HEADERS,
    ScanTarget,
    _safe_location,
)
from webshield.scope import normalize_same_origin_url, normalize_scope_path, path_is_allowed

DEFAULT_EXCLUDED_SEGMENTS = frozenset(
    {
        "logout",
        "log-out",
        "signout",
        "sign-out",
        "delete",
        "remove",
        "payment",
        "payments",
        "checkout",
        "register",
        "registration",
        "settings",
        "change-password",
        "reset-password",
    }
)
SENSITIVE_QUERY_NAME = re.compile(
    r"(?i)(?:password|passwd|token|secret|session|csrf|authorization|cookie|api[_-]?key)"
)
ADMIN_ACTION_SEGMENTS = frozenset(
    {"create", "delete", "edit", "save", "update", "users", "roles", "permissions", "settings"}
)
MAX_LINKS_PER_PAGE = 100
MAX_FORMS_PER_PAGE = 20
MAX_FIELDS_PER_FORM = 50
MAX_RECORDED_LINKS = 5000
MAX_RECORDED_FORMS = 500


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag.lower() == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").upper(),
                "field_names": [],
            }
            self.forms.append(self._form)
        elif tag.lower() in ("input", "select", "textarea", "button"):
            if self._form is not None and attributes.get("name"):
                self._form["field_names"].append(attributes["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


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


def _excluded_path(path: str, excluded_paths: tuple[str, ...]) -> bool:
    lower_path = path.lower()
    segments = {segment for segment in lower_path.split("/") if segment}
    if segments & DEFAULT_EXCLUDED_SEGMENTS:
        return True
    if "admin" in segments:
        admin_index = lower_path.split("/").index("admin")
        later_segments = {
            segment.split(".", 1)[0]
            for segment in lower_path.split("/")[admin_index + 1 :]
            if segment
        }
        if later_segments & ADMIN_ACTION_SEGMENTS:
            return True
    return any(
        path == excluded or (excluded.endswith("/") and path.startswith(excluded))
        for excluded in excluded_paths
    )


def _sensitive_query(url: str) -> bool:
    return any(SENSITIVE_QUERY_NAME.search(name) for name, _ in parse_qsl(urlsplit(url).query))


def _safe_url(target: ScanTarget, value: str, base_url: str) -> str | None:
    absolute = urljoin(base_url, value)
    return normalize_same_origin_url(
        absolute,
        scheme=target.scheme,
        hostname=target.hostname,
        port=target.port,
    )


def crawl(
    target: ScanTarget,
    *,
    allowed_paths: Sequence[str] | None = None,
    max_depth: int = 2,
    max_pages: int = 25,
    request_timeout: float = REQUEST_TIMEOUT_SECONDS,
    min_interval_seconds: float = 1.0,
    excluded_paths: Sequence[str] = (),
    cookie_header: str | None = None,
) -> dict[str, Any]:
    """Discover same-origin pages and forms without submitting forms or following redirects."""
    if not _is_local_target(target):
        raise ValueError("Crawling is restricted to validated localhost/private targets.")
    if not 0 <= max_depth <= 5:
        raise ValueError("max_depth must be between 0 and 5.")
    if not 1 <= max_pages <= 100:
        raise ValueError("max_pages must be between 1 and 100.")
    if not 0 < request_timeout <= 15:
        raise ValueError("request_timeout must be greater than 0 and at most 15 seconds.")
    if not 0.5 <= min_interval_seconds <= 30:
        raise ValueError("min_interval_seconds must be between 0.5 and 30 seconds.")

    paths = tuple(
        dict.fromkeys(normalize_scope_path(path) for path in (allowed_paths or target.approved_paths))
    )
    excluded = tuple(dict.fromkeys(normalize_scope_path(path) for path in excluded_paths))
    root = target.origin + target.path
    root_url = _safe_url(target, root, root)
    if root_url is None:
        raise ValueError("The crawl start URL is outside the validated target origin.")
    root_path = urlsplit(root_url).path
    if not path_is_allowed(root_path, paths, target.root_is_recursive):
        raise ValueError("The crawl start path is outside the explicitly approved path scope.")

    queue: list[tuple[str, int]] = [(root_url, 0)]
    scheduled = {root_url}
    visited: set[str] = set()
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    links_seen: set[str] = set()
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    excluded_count = 0
    request_count = 0
    root_response: tuple[int, dict[str, str], bool] | None = None
    session = _new_session(target)
    headers = {
        "Host": _format_host(target),
        "User-Agent": "WebShield-AI/1.0 (+authorized bounded crawler)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if cookie_header:
        headers["Cookie"] = cookie_header
    last_request_at = 0.0
    try:
        while queue and len(pages) < max_pages:
            page_url, depth = queue.pop(0)
            if page_url in visited:
                continue
            visited.add(page_url)
            parsed_url = urlsplit(page_url)
            if _excluded_path(parsed_url.path, excluded) or _sensitive_query(page_url):
                if page_url == root_url:
                    raise ValueError("The explicitly selected crawl start path is excluded.")
                excluded_count += 1
                continue
            elapsed = time.monotonic() - last_request_at
            if last_request_at and elapsed < min_interval_seconds:
                time.sleep(min_interval_seconds - elapsed)
            last_request_at = time.monotonic()
            request_count += 1
            request_path = parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
            try:
                response = session.get(
                    _pinned_url(target, request_path),
                    headers=headers,
                    timeout=request_timeout,
                    allow_redirects=False,
                    stream=True,
                )
                with response:
                    page_status = response.status_code
                    content_type = response.headers.get("Content-Type", "").lower()
                    location = response.headers.get("Location", "")
                    safe_headers = {
                        name: _safe_location(value) if name.lower() == "location" else value
                        for name, value in response.headers.items()
                        if name.lower() in RELEVANT_RESPONSE_HEADERS
                    }
                    if page_url == root_url:
                        root_response = (
                            page_status,
                            safe_headers,
                            300 <= page_status < 400,
                        )
                    body = _read_bounded(response) if "html" in content_type else ""
                page_record: dict[str, Any] = {
                    "url": redact_url(page_url),
                    "status": page_status,
                    "depth": depth,
                    "query_parameters": sorted({
                        name for name, _ in parse_qsl(parsed_url.query, keep_blank_values=True)
                    }),
                    "links": [],
                    "forms": [],
                    "redirect_not_followed": 300 <= page_status < 400,
                }
                pages.append(page_record)
                if "html" in content_type:
                    findings.extend(check_headers(redact_url(page_url), safe_headers))
                if page_status in (301, 302, 303, 307, 308) and location:
                    if _safe_url(target, location, page_url) is None:
                        errors.append({
                            "url": redact_url(page_url),
                            "error": "Redirect to an unapproved origin was not followed.",
                        })
                    continue
                if not body or depth >= max_depth:
                    continue
                parser = _PageParser()
                parser.feed(body)
                for form in parser.forms[:MAX_FORMS_PER_PAGE]:
                    action = _safe_url(target, form["action"] or page_url, page_url)
                    normalized_form = {
                        "page_url": redact_url(page_url),
                        "action": redact_url(action) if action else "Out-of-origin action withheld",
                        "method": form["method"],
                        "field_names": sorted(set(form["field_names"][:MAX_FIELDS_PER_FORM])),
                        "submitted": False,
                    }
                    page_record["forms"].append(normalized_form)
                    if len(forms) < MAX_RECORDED_FORMS:
                        forms.append(normalized_form)
                for href in parser.links[:MAX_LINKS_PER_PAGE]:
                    link = _safe_url(target, href, page_url)
                    if link is None:
                        continue
                    link_path = urlsplit(link).path
                    if (
                        not path_is_allowed(link_path, paths, target.root_is_recursive)
                        or _excluded_path(link_path, excluded)
                        or _sensitive_query(link)
                    ):
                        excluded_count += 1
                        continue
                    safe_link = redact_url(link)
                    page_record["links"].append(safe_link)
                    if len(links_seen) < MAX_RECORDED_LINKS:
                        links_seen.add(safe_link)
                    if link not in scheduled and len(scheduled) < max_pages and link not in visited:
                        scheduled.add(link)
                        queue.append((link, depth + 1))
            except (requests.RequestException, OSError, TimeoutError, ValueError, RuntimeError) as error:
                if page_url == root_url and root_response is None:
                    root_response = (None, {}, False)
                errors.append({
                    "url": redact_url(page_url),
                    "error": redact_text(f"{type(error).__name__}: {error}"),
                })
    finally:
        session.close()

    return {
        "pages": pages,
        "forms": forms,
        "links": sorted(links_seen),
        "request_count": request_count,
        "excluded_count": excluded_count,
        "errors": errors,
        "findings": findings,
        "root_response": root_response,
        "limits": {
            "max_depth": max_depth,
            "max_pages": max_pages,
            "request_timeout_seconds": request_timeout,
            "minimum_request_interval_seconds": min_interval_seconds,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "max_links_per_page": MAX_LINKS_PER_PAGE,
            "max_forms_per_page": MAX_FORMS_PER_PAGE,
        },
    }
