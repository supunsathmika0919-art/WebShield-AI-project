from __future__ import annotations

import html
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from webshield.input_checks import ProbeConfig, ProbeConfigError, run_input_checks
from webshield.scanner import validate_target


class _TrainingHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        parsed = urlsplit(self.path)
        value = parse_qs(parsed.query).get("q", [""])[0]
        if parsed.path == "/search" and "'" in value:
            status, body = 500, b"SQLite error: near quote: syntax error"
        elif parsed.path == "/echo":
            status, body = 200, value.encode()
        elif parsed.path == "/escaped":
            status, body = 200, html.escape(value, quote=True).encode()
        else:
            status, body = 200, b"Results"
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        raise AssertionError("Input checks must never submit forms.")

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class InputCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _TrainingHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setUp(self) -> None:
        _TrainingHandler.requests = []
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.target = validate_target(
            base_url + "/",
            "127.0.0.1",
            allow_local=True,
            allowed_paths=["/"],
        )

    def test_sql_quote_indicator_is_potential_and_evidence_is_bounded(self) -> None:
        config = ProbeConfig.from_mapping({
            "endpoints": [{"path": "/search", "parameters": ["q"]}],
        })
        with patch("webshield.input_checks.PROBE_INTERVAL_SECONDS", 0):
            result = run_input_checks(self.target, config, check_sqli=True)
        finding = result["findings"][0]
        self.assertEqual(finding["status"], "potential")
        self.assertIn("database error indicator", finding["evidence"])
        self.assertEqual(result["request_count"], 2)
        self.assertTrue(all(path.startswith("/search?") for path in _TrainingHandler.requests))
        self.assertNotIn("'", finding["evidence"])

    def test_reflected_unencoded_and_encoded_markers_are_distinguished(self) -> None:
        config = ProbeConfig.from_mapping({
            "endpoints": [
                {"path": "/echo", "parameters": ["q"]},
                {"path": "/escaped", "parameters": ["q"]},
            ],
        })
        with patch("webshield.input_checks.PROBE_INTERVAL_SECONDS", 0):
            result = run_input_checks(self.target, config, check_xss=True)
        statuses = {finding["status"] for finding in result["findings"]}
        self.assertEqual(statuses, {"potential", "informational"})
        self.assertTrue(any("Unencoded" in finding["title"] for finding in result["findings"]))
        self.assertTrue(any("HTML-encoded" in finding["title"] for finding in result["findings"]))
        self.assertTrue(all("<script" not in path for path in _TrainingHandler.requests))

    def test_non_reflecting_endpoint_produces_no_xss_finding(self) -> None:
        config = ProbeConfig.from_mapping({
            "endpoints": [{"path": "/search", "parameters": ["q"]}],
        })
        with patch("webshield.input_checks.PROBE_INTERVAL_SECONDS", 0):
            result = run_input_checks(self.target, config, check_xss=True)
        self.assertEqual(result["findings"], [])
        self.assertIn("Stored XSS (forms are inspected but never submitted)", result["checks_skipped"])

    def test_probe_rejects_unapproved_endpoint_and_sensitive_field_names(self) -> None:
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        restricted_target = validate_target(
            base_url + "/approved/",
            "127.0.0.1",
            allow_local=True,
            allowed_paths=["/approved/"],
        )
        config = ProbeConfig.from_mapping({
            "endpoints": [{"path": "/outside", "parameters": ["q"]}],
        })
        with self.assertRaisesRegex(ProbeConfigError, "outside the explicitly approved"):
            run_input_checks(restricted_target, config, check_sqli=True)
        with self.assertRaises(ProbeConfigError):
            ProbeConfig.from_mapping({
                "endpoints": [{"path": "/search", "parameters": ["session_token"]}],
            })
        self.assertEqual(_TrainingHandler.requests, [])

    def test_configuration_caps_endpoints_and_fields(self) -> None:
        with self.assertRaisesRegex(ProbeConfigError, "At most"):
            ProbeConfig.from_mapping({
                "endpoints": [
                    {"path": f"/p{index}", "parameters": ["a", "b", "c"]}
                    for index in range(4)
                ],
            })


if __name__ == "__main__":
    unittest.main()
