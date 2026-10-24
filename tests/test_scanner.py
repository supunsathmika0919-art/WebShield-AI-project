from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from webshield.analyzer import analyze
from webshield.analyzer import prioritize_findings
from webshield.header_checker import check_headers
from webshield.reporter import (
    render_html,
    safe_report_stem,
    write_html_report,
    write_json_report,
    write_pdf_report,
)
from webshield.scanner import (
    TargetResolutionError,
    TargetValidationError,
    scan,
    validate_target,
)


class _Handler(BaseHTTPRequestHandler):
    response_status = 200
    response_headers: dict[str, str] = {}
    requests: list[str] = []

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        self.send_response(type(self).response_status)
        for name, value in type(self).response_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(b"local test response")

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setUp(self) -> None:
        _Handler.response_status = 200
        _Handler.response_headers = {}
        _Handler.requests = []
        self.local_url = f"http://127.0.0.1:{self.server.server_port}/"

    def test_target_requires_exact_hostname_authorization(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target("https://example.com/", "sub.example.com")
        with self.assertRaises(TargetValidationError):
            validate_target("https://sub.example.com/", "example.com")

    def test_rejects_invalid_urls_credentials_and_non_homepage(self) -> None:
        invalid = (
            ("ftp://example.com/", "example.com"),
            ("https://user:pass@example.com/", "example.com"),
            ("https://example.com/private", "example.com"),
            ("https://example.com/?q=1", "example.com"),
            ("http://example.com/", "example.com"),
        )
        for url, host in invalid:
            with self.subTest(url=url), self.assertRaises(TargetValidationError):
                validate_target(url, host)

    def test_allows_local_target_only_with_explicit_flag(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target(self.local_url, "127.0.0.1")
        target = validate_target(self.local_url, "127.0.0.1", allow_local=True)
        self.assertEqual(target.hostname, "127.0.0.1")
        self.assertEqual(target.resolved_ip, "127.0.0.1")

    def test_rejects_mixed_or_private_dns_answers_for_public_target(self) -> None:
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with patch("webshield.scanner.socket.getaddrinfo", return_value=records):
            with self.assertRaises(TargetValidationError):
                validate_target("https://example.com/", "example.com")

    def test_local_mode_rejects_unspecified_ip(self) -> None:
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("0.0.0.0", 80))]
        with patch("webshield.scanner.socket.getaddrinfo", return_value=records):
            with self.assertRaises(TargetValidationError):
                validate_target("http://example.test/", "example.test", allow_local=True)

    def test_dns_failure_is_reported_and_does_not_make_a_request(self) -> None:
        with patch("webshield.scanner.socket.getaddrinfo", side_effect=socket.gaierror("no DNS")):
            with self.assertRaises(TargetResolutionError):
                validate_target("https://example.com/", "example.com")

    def test_missing_and_present_headers(self) -> None:
        missing = check_headers("localhost", {})
        missing_ids = {finding["id"] for finding in missing}
        self.assertIn("HDR-HSTS-MISSING", missing_ids)
        self.assertIn("HDR-FRAMING-MISSING", missing_ids)
        present = check_headers(
            "localhost",
            {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=()",
            },
        )
        self.assertEqual(present, [])

    def test_weak_headers_are_reported(self) -> None:
        findings = check_headers(
            "example.com",
            {
                "Strict-Transport-Security": "max-age=60",
                "X-Content-Type-Options": "sniff",
                "Referrer-Policy": "unsafe-url",
                "X-Frame-Options": "ALLOWALL",
            },
        )
        ids = {finding["id"] for finding in findings}
        self.assertTrue({"HDR-HSTS-WEAK", "HDR-NOSNIFF-WEAK", "HDR-REFERRER-WEAK", "HDR-FRAMING-MISSING"} <= ids)

    def test_redirect_is_reported_but_not_followed(self) -> None:
        _Handler.response_status = 302
        _Handler.response_headers = {
            "Location": "http://other-host.invalid/redirect?token=secret",
            "Set-Cookie": "session=secret",
        }
        target = validate_target(self.local_url, "127.0.0.1", allow_local=True)
        report = scan(target)
        self.assertEqual(report["http_status"], 302)
        self.assertEqual(_Handler.requests, ["/"])
        self.assertFalse(report["target"]["redirects_followed"])
        self.assertNotIn("Set-Cookie", report["response_headers"])
        redirect = next(f for f in report["findings"] if f["id"] == "HTTP-REDIRECT-NOT-FOLLOWED")
        self.assertIn("other-host.invalid/", redirect["evidence"])
        self.assertNotIn("secret", redirect["evidence"])
        self.assertNotIn("redirect", redirect["evidence"])

    def test_tls_network_error_is_handled(self) -> None:
        target = validate_target(
            f"https://127.0.0.1:{self.server.server_port}/",
            "127.0.0.1",
            allow_local=True,
        )
        with patch("webshield.scanner.check_tls", return_value={
            "status": "Failed", "error_type": "TimeoutError", "error": "timed out"
        }), patch("webshield.scanner._fetch_homepage", return_value=(200, {}, False)):
            report = scan(target)
        finding = next(f for f in report["findings"] if f["id"] == "TLS-CHECK-FAILED")
        self.assertEqual(finding["severity"], "Informational")
        self.assertEqual(report["status"], "completed")

    def test_scan_reports_origin_approved_paths_and_check_status(self) -> None:
        target = validate_target(self.local_url, "127.0.0.1", allow_local=True)
        with patch("webshield.scanner.check_tls") as check_tls:
            report = scan(target)
        self.assertEqual(report["target"]["origin"], target.origin)
        self.assertEqual(report["target"]["approved_paths"], ["/"])
        self.assertIn("HTTP security headers", report["checks_performed"])
        self.assertTrue(report["checks_skipped"])
        self.assertEqual(report["errors"], [])
        check_tls.assert_not_called()

    def test_analyzer_severity_classification(self) -> None:
        findings = analyze(
            "example.com",
            {"status": "Failed", "error_type": "SSLCertVerificationError", "error": "untrusted"},
            {},
            None,
            "connection failed",
            False,
        )
        certificate = next(f for f in findings if f["id"] == "TLS-CERTIFICATE-INVALID")
        self.assertEqual(certificate["severity"], "High")
        self.assertEqual(findings[-1]["severity"], "Informational")

    def test_rule_based_prioritizer_labels_status_and_discloses_confidence_limits(self) -> None:
        findings = prioritize_findings([
            {"id": "LOW", "severity": "Low"},
            {"id": "HIGH", "severity": "High"},
            {"id": "INFO", "severity": "Informational"},
        ])
        self.assertEqual([item["id"] for item in findings], ["HIGH", "LOW", "INFO"])
        self.assertEqual(findings[0]["status"], "potential")
        self.assertIn("not calibrated", findings[0]["confidence"].lower())
        self.assertEqual([item["priority_rank"] for item in findings], [1, 2, 3])
        self.assertIn("Rule-based", findings[0]["priority_reason"])
        confirmed = prioritize_findings([
            {"id": "TLS-CERTIFICATE-EXPIRED", "severity": "High"},
        ])[0]
        self.assertEqual(confirmed["status"], "confirmed")

    def test_report_generation_json_html_pdf_and_escaping(self) -> None:
        report = {
            "tool": "WebShield AI",
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "target": {"hostname": "example.com", "url": "https://example.com/", "scope": "homepage"},
            "status": "completed",
            "http_status": 200,
            "severity_counts": {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Informational")},
            "findings": [{
                "id": "TEST",
                "title": "<script>alert('x')</script>",
                "severity": "Low",
                "affected_resource": "example.com",
                "evidence": "<img src=x onerror=alert(1)>",
                "explanation": "test",
                "remediation": "fix",
                "references": ["https://docs.example/?q=<b>"],
            }],
            "limitations": "Not a full assessment.",
        }
        self.assertNotIn("<script>", render_html(report))
        self.assertIn("&lt;script&gt;", render_html(report))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            stem = safe_report_stem("example.com", datetime(2026, 1, 1, tzinfo=timezone.utc))
            json_path = write_json_report(report, output, stem)
            html_path = write_html_report(report, output, stem)
            pdf_path = write_pdf_report(report, output, stem)
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["status"], "completed")
            self.assertIn("&lt;img", html_path.read_text(encoding="utf-8"))
            self.assertIn(
                "https://docs.example/?q=%5BREDACTED%5D",
                html_path.read_text(encoding="utf-8"),
            )
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))

    def test_cli_help_and_invalid_arguments(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "webshield.cli", "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("scan", result.stdout)
        result = subprocess.run(
            [sys.executable, "-m", "webshield.cli", "scan", "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--crawl", result.stdout)
        self.assertIn("--check-sqli", result.stdout)
        self.assertIn("--auth-config", result.stdout)
        result = subprocess.run(
            [sys.executable, "-m", "webshield.cli", "scan", "https://example.com/"],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--allow-host", result.stderr)


if __name__ == "__main__":
    unittest.main()
