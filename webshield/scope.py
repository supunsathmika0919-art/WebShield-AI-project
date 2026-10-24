"""Canonical URL and path-scope checks shared by scanner modules."""

from __future__ import annotations

import posixpath
from urllib.parse import quote, unquote, urlsplit, urlunsplit


def normalize_path(path: str) -> str:
    decoded = unquote(path or "/")
    if (
        not decoded.startswith("/")
        or "\\" in decoded
        or any(ord(character) < 32 for character in decoded)
        or any(segment == ".." for segment in decoded.split("/"))
    ):
        raise ValueError("Path is malformed or escapes the authorized path scope.")
    normalized = posixpath.normpath(decoded)
    if path.endswith("/") and normalized != "/":
        normalized += "/"
    return quote(normalized, safe="/:@-._~!$&'()*+,;=%")


def normalize_scope_path(path: str) -> str:
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("Approved paths must be absolute URL paths without query or fragment.")
    return normalize_path(parsed.path)


def path_is_allowed(path: str, allowed_paths: tuple[str, ...], root_is_recursive: bool) -> bool:
    normalized = normalize_path(path)
    for allowed in allowed_paths:
        if allowed == "/":
            if root_is_recursive or normalized == "/":
                return True
            continue
        if normalized == allowed:
            return True
        if allowed.endswith("/") and normalized.startswith(allowed):
            return True
    return False


def normalize_same_origin_url(
    url: str,
    *,
    scheme: str,
    hostname: str,
    port: int,
) -> str | None:
    try:
        parsed = urlsplit(url)
        parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != scheme
        or not parsed.hostname
        or parsed.hostname.lower().rstrip(".") != hostname
        or parsed_port != port
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    try:
        path = normalize_path(parsed.path)
    except ValueError:
        return None
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))
