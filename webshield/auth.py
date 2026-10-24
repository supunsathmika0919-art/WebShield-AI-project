"""Safe, same-origin HTML form authentication for explicitly authorized targets."""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import socket
import ssl
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

from webshield.scanner import MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_SECONDS, ScanTarget
from webshield.scope import normalize_path, path_is_allowed

AUTH_MIN_INTERVAL_SECONDS = 0.5


class AuthenticationError(RuntimeError):
    """Authentication could not be completed safely or was rejected."""


@dataclass(frozen=True)
class AuthConfig:
    login_url: str
    username_field: str
    password_field: str
    success_indicator: str
    failure_indicator: str | None = None
    csrf_field: str | None = None
    username_env: str = "WEBSHIELD_USERNAME"
    password_env: str = "WEBSHIELD_PASSWORD"

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> AuthConfig:
        forbidden = {
            "username",
            "password",
            "credentials",
            "session_cookie",
            "csrf_token",
            "token",
            "api_key",
            "authorization",
        } & {str(key).lower() for key in values}
        if forbidden:
            raise AuthenticationError(
                "Auth config must name credential environment variables, not store credentials."
            )
        try:
            config = cls(
                login_url=str(values["login_url"]),
                username_field=str(values["username_field"]),
                password_field=str(values["password_field"]),
                success_indicator=str(values["success_indicator"]),
                failure_indicator=(
                    str(values["failure_indicator"]) if values.get("failure_indicator") else None
                ),
                csrf_field=str(values["csrf_field"]) if values.get("csrf_field") else None,
                username_env=str(values.get("username_env", "WEBSHIELD_USERNAME")),
                password_env=str(values.get("password_env", "WEBSHIELD_PASSWORD")),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AuthenticationError(
                "Auth config requires login_url, username_field, password_field, "
                "and success_indicator."
            ) from error
        if not all(
            (
                config.login_url,
                config.username_field,
                config.password_field,
                config.success_indicator,
                config.username_env,
                config.password_env,
            )
        ):
            raise AuthenticationError("Auth config fields must not be empty.")
        if config.username_field == config.password_field:
            raise AuthenticationError("Username and password form fields must be different.")
        return config


def load_auth_config(path: Path) -> AuthConfig:
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuthenticationError(f"Could not read auth config: {type(error).__name__}.") from error
    if not isinstance(values, dict):
        raise AuthenticationError("Auth config must be a JSON object.")
    return AuthConfig.from_mapping(values)


def resolve_credentials(
    config: AuthConfig,
    *,
    interactive: bool,
) -> tuple[str, str]:
    username = os.environ.get(config.username_env, "")
    password = os.environ.get(config.password_env, "")
    if not username and interactive:
        username = input(f"Username ({config.username_env}): ")
    if not password and interactive:
        password = getpass.getpass(f"Password ({config.password_env}): ")
    if not username or not password:
        raise AuthenticationError(
            f"Set {config.username_env} and {config.password_env}, or run interactively "
            "to enter credentials securely."
        )
    return username, password


def _validate_endpoint(target: ScanTarget, endpoint: str) -> str:
    try:
        address = ipaddress.ip_address(target.resolved_ip)
    except ValueError as error:
        raise AuthenticationError("Authentication is limited to a validated local/private target.") from error
    if address.is_global or address.is_reserved or address.is_unspecified or address.is_multicast:
        raise AuthenticationError("Authentication is limited to a validated local/private target.")
    parsed = urlsplit(endpoint)
    try:
        endpoint_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise AuthenticationError("The configured login URL is invalid.") from error
    target_port = target.port
    if (
        parsed.scheme.lower() != target.scheme
        or not parsed.hostname
        or parsed.hostname.lower().rstrip(".") != target.hostname
        or endpoint_port != target_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AuthenticationError("The login URL must be on the exact authorized origin.")
    try:
        return normalize_path(parsed.path)
    except ValueError as error:
        raise AuthenticationError("The configured login path is invalid.") from error


def _format_host(target: ScanTarget) -> str:
    host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    default_port = 443 if target.scheme == "https" else 80
    return f"{host}:{target.port}" if target.port != default_port else host


def _pinned_url(target: ScanTarget, path: str) -> str:
    host = f"[{target.resolved_ip}]" if ":" in target.resolved_ip else target.resolved_ip
    default_port = 443 if target.scheme == "https" else 80
    port = "" if target.port == default_port else f":{target.port}"
    return f"{target.scheme}://{host}{port}{path}"


class _PinnedRequestsAdapter(HTTPAdapter):
    def __init__(self, target: ScanTarget) -> None:
        self._target = target
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs["assert_hostname"] = self._target.hostname
        pool_kwargs["server_hostname"] = self._target.hostname
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


class _HiddenInputParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_inputs: dict[str, str] = {}
        self.form_action: str | None = None
        self.form_method = "get"
        self._inside_first_form = False
        self._found_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "form" and not self._found_form:
            self._found_form = True
            self._inside_first_form = True
            self.form_action = attributes.get("action")
            self.form_method = attributes.get("method", "get").lower()
        elif tag.lower() == "input" and self._inside_first_form:
            if attributes.get("type", "").lower() == "hidden" and attributes.get("name"):
                self.hidden_inputs[attributes["name"]] = attributes.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._inside_first_form:
            self._inside_first_form = False


def _read_bounded(response: requests.Response) -> str:
    content = response.raw.read(MAX_RESPONSE_BYTES + 1)
    if len(content) > MAX_RESPONSE_BYTES:
        raise AuthenticationError("Authentication response exceeded the configured size limit.")
    return content.decode(response.encoding or "utf-8", errors="replace")


def _new_session(target: ScanTarget) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.verify = True
    adapter = _PinnedRequestsAdapter(target)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def authenticate(
    target: ScanTarget,
    config: AuthConfig,
    username: str,
    password: str,
) -> requests.Session:
    """Log in through a bounded same-origin form and return its in-memory cookie session."""
    login_path = _validate_endpoint(target, config.login_url)
    session = _new_session(target)
    headers = {
        "Host": _format_host(target),
        "User-Agent": "WebShield-AI/1.0 (+authorized security checks)",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    login_url = _pinned_url(target, login_path)
    try:
        response = session.get(
            login_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
            stream=True,
        )
        with response:
            if response.status_code >= 300:
                raise AuthenticationError("Login page returned a non-success status.")
            parser = _HiddenInputParser()
            parser.feed(_read_bounded(response))
        if parser.form_method != "post":
            raise AuthenticationError(
                "Only POST-based login forms are supported; credential-bearing GET forms are refused."
            )
        form_url = urljoin(config.login_url, parser.form_action or "")
        form_path = _validate_endpoint(target, form_url)
        if form_path != login_path and not path_is_allowed(
            form_path, target.approved_paths, target.root_is_recursive
        ):
            raise AuthenticationError(
                "The login form action is outside the explicitly authorized path scope."
            )
        if config.csrf_field and config.csrf_field not in parser.hidden_inputs:
            raise AuthenticationError("The configured CSRF field was not present in the login form.")
        form_values = dict(parser.hidden_inputs)
        form_values[config.username_field] = username
        form_values[config.password_field] = password
        time.sleep(AUTH_MIN_INTERVAL_SECONDS)
        response = session.post(
            _pinned_url(target, form_path),
            data=form_values,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
            stream=True,
        )
        with response:
            location = response.headers.get("Location", "")
            if response.status_code >= 400:
                raise AuthenticationError("Login was rejected; protected scan stopped.")
            if 300 <= response.status_code < 400:
                if not location:
                    raise AuthenticationError(
                        "Login redirect had no destination; protected scan stopped."
                    )
                redirect_url = urljoin(config.login_url, location)
                _validate_endpoint(target, redirect_url)
            body = _read_bounded(response)
            if config.failure_indicator and config.failure_indicator in body:
                raise AuthenticationError("Login failure indicator was detected; protected scan stopped.")
            if (
                config.success_indicator not in body
                and config.success_indicator not in location
            ):
                raise AuthenticationError("Login success indicator was not found; protected scan stopped.")
        return session
    except AuthenticationError:
        session.close()
        raise
    except (requests.RequestException, OSError, socket.error, ssl.SSLError, TimeoutError) as error:
        session.close()
        raise AuthenticationError(
            f"Authentication request failed ({type(error).__name__}); protected scan stopped."
        ) from error


def session_cookie_header(session: requests.Session, target: ScanTarget) -> str | None:
    """Prepare an in-memory request to obtain only cookies applicable to the target origin."""
    request = requests.Request(
        "GET",
        _pinned_url(target, target.path),
        headers={"Host": _format_host(target)},
    )
    prepared = session.prepare_request(request)
    return prepared.headers.get("Cookie")
