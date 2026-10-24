from __future__ import annotations

import threading
import json
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

from webshield.auth import (
    AuthenticationError,
    AuthConfig,
    _new_session,
    authenticate,
    resolve_credentials,
    session_cookie_header,
)
from webshield.scanner import scan, validate_target


class _AuthHandler(BaseHTTPRequestHandler):
    submitted: dict[str, str] = {}
    login_body = "<form method='post'><input type='hidden' name='csrf' value='csrf-value'></form>"

    def do_GET(self) -> None:
        if self.path == "/login":
            body = self.login_body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/" and "session=valid" in self.headers.get("Cookie", ""):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"Protected page")
            return
        self.send_response(401)
        self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.submitted = parse_qs(self.rfile.read(length).decode())
        type(self).submitted = self.submitted
        if (
            self.submitted.get("username") == ["test-user"]
            and self.submitted.get("password") == ["test-password"]
            and self.submitted.get("csrf") == ["csrf-value"]
        ):
            self.send_response(200)
            self.send_header("Set-Cookie", "session=valid; Path=/; HttpOnly")
            body = b"Welcome"
        else:
            self.send_response(200)
            body = b"Invalid credentials"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setUp(self) -> None:
        _AuthHandler.login_body = (
            "<form method='post'><input type='hidden' name='csrf' value='csrf-value'></form>"
        )
        _AuthHandler.submitted = {}
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.target = validate_target(
            self.base_url + "/",
            "127.0.0.1",
            allow_local=True,
        )
        self.config = AuthConfig.from_mapping({
            "login_url": self.base_url + "/login",
            "username_field": "username",
            "password_field": "password",
            "csrf_field": "csrf",
            "success_indicator": "Welcome",
            "failure_indicator": "Invalid credentials",
        })

    def test_login_extracts_csrf_and_authenticated_scan_uses_session_cookie(self) -> None:
        session = authenticate(self.target, self.config, "test-user", "test-password")
        try:
            self.assertEqual(_AuthHandler.submitted["csrf"], ["csrf-value"])
            report = scan(self.target, session_cookie_header(session, self.target))
            self.assertEqual(report["http_status"], 200)
        finally:
            session.close()
        self.assertNotIn("test-password", str(report))
        self.assertNotIn("csrf-value", str(report))

    def test_failed_login_stops_before_a_cookie_session_is_returned(self) -> None:
        with self.assertRaisesRegex(AuthenticationError, "failure indicator"):
            authenticate(self.target, self.config, "wrong-user", "wrong-password")
        self.assertEqual(_AuthHandler.submitted["password"], ["wrong-password"])

    def test_missing_configured_csrf_field_stops_before_post(self) -> None:
        _AuthHandler.login_body = "<form method='post'></form>"
        with self.assertRaisesRegex(AuthenticationError, "CSRF field"):
            authenticate(self.target, self.config, "test-user", "test-password")
        self.assertEqual(_AuthHandler.submitted, {})

    def test_get_login_forms_are_refused_to_prevent_credentials_in_urls(self) -> None:
        _AuthHandler.login_body = (
            "<form method='get'><input type='hidden' name='csrf' value='csrf-value'></form>"
        )
        with self.assertRaisesRegex(AuthenticationError, "POST-based"):
            authenticate(self.target, self.config, "test-user", "test-password")
        self.assertEqual(_AuthHandler.submitted, {})

    def test_off_origin_login_url_is_rejected(self) -> None:
        config = AuthConfig.from_mapping({
            "login_url": "http://example.invalid/login",
            "username_field": "username",
            "password_field": "password",
            "success_indicator": "Welcome",
        })
        with self.assertRaisesRegex(AuthenticationError, "exact authorized origin"):
            authenticate(self.target, config, "user", "password")

    def test_pinned_session_keeps_tls_verification_enabled_and_ignores_proxy_env(self) -> None:
        session = _new_session(self.target)
        try:
            self.assertIs(session.verify, True)
            self.assertIs(session.trust_env, False)
            adapter = session.get_adapter("https://127.0.0.1/")
            self.assertEqual(
                adapter.poolmanager.connection_pool_kw["assert_hostname"],
                "127.0.0.1",
            )
            self.assertEqual(
                adapter.poolmanager.connection_pool_kw["server_hostname"],
                "127.0.0.1",
            )
        finally:
            session.close()

    def test_config_never_accepts_embedded_credentials(self) -> None:
        with self.assertRaisesRegex(AuthenticationError, "not store credentials"):
            AuthConfig.from_mapping({
                "login_url": self.base_url + "/login",
                "username_field": "username",
                "password_field": "password",
                "success_indicator": "Welcome",
                "password": "do-not-store",
            })

    def test_credentials_resolve_from_environment_without_echo(self) -> None:
        with patch.dict(
            "os.environ",
            {"WEBSHIELD_USERNAME": "test-user", "WEBSHIELD_PASSWORD": "test-password"},
        ):
            credentials = resolve_credentials(self.config, interactive=False)
        self.assertEqual(credentials, ("test-user", "test-password"))

    def test_cli_auth_failure_writes_report_and_never_scans_protected_page(self) -> None:
        from webshield import cli

        with tempfile.TemporaryDirectory() as temporary:
            with (
                patch.object(cli, "load_auth_config", return_value=self.config),
                patch.object(cli, "resolve_credentials", return_value=("test-user", "secret-password")),
                patch.object(
                    cli,
                    "authenticate",
                    side_effect=AuthenticationError("Login failure indicator was detected."),
                ),
                patch.object(cli, "scan") as scan_mock,
            ):
                result = cli.main([
                    "scan",
                    self.base_url + "/",
                    "--allow-host", "127.0.0.1",
                    "--confirm-authorized",
                    "--allow-local",
                    "--auth-config", str(Path(temporary) / "auth.json"),
                    "--output-dir", temporary,
                ])
            self.assertEqual(result, 1)
            scan_mock.assert_not_called()
            report_path = next(Path(temporary).glob("*.json"))
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["http_status"], None)
            self.assertNotIn("secret-password", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
