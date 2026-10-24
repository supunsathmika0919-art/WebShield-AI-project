from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from webshield.redaction import redact_report, redact_text, redact_url
from webshield.reporter import render_html, write_json_report, write_pdf_report


class RedactionTests(unittest.TestCase):
    def test_url_redaction_removes_credentials_query_values_and_fragment(self) -> None:
        safe = redact_url(
            "http://alice:password@localhost/admin?token=topsecret&view=private#session"
        )
        self.assertEqual(
            safe,
            "http://localhost/admin?token=%5BREDACTED%5D&view=%5BREDACTED%5D",
        )
        self.assertNotIn("alice", safe)
        self.assertNotIn("password", safe)
        self.assertNotIn("topsecret", safe)
        self.assertNotIn("private", safe)
        self.assertNotIn("session", safe)
        self.assertNotIn(
            "SESSION123",
            redact_url("https://localhost/session/SESSION123/profile"),
        )

    def test_text_redaction_covers_secrets_outside_url_fields(self) -> None:
        safe = redact_text(
            "https://localhost/path?code=secret-value Authorization: Bearer abc.def "
            "session_id=SESSION123 csrf_token='CSRF123' nonce-dont-report "
            "client_secret=CLIENTSECRET"
        )
        for secret in ("secret-value", "abc.def", "SESSION123", "CSRF123", "dont-report", "CLIENTSECRET"):
            self.assertNotIn(secret, safe)

    def test_report_redaction_applies_to_json_html_and_pdf(self) -> None:
        report = {
            "version": "1.1.0",
            "checks_performed": ["Header check"],
            "checks_skipped": ["Stored XSS"],
            "errors": [],
            "crawl": {
                "request_count": 1,
                "excluded_count": 0,
                "pages": [{
                    "url": "http://localhost/private?session=private-query",
                    "status": 200,
                    "depth": 1,
                    "query_parameters": ["session"],
                }],
                "forms": [{
                    "page_url": "http://localhost/private",
                    "action": "http://localhost/save",
                    "method": "POST",
                    "field_names": ["csrf", "comment"],
                    "submitted": False,
                }],
            },
            "target": {
                "url": "http://localhost/admin?ticket=private-ticket",
                "origin": "http://localhost",
                "approved_paths": ["/admin/"],
            },
            "authorization": "Bearer private-auth",
            "findings": [{
                "title": "Potential issue",
                "evidence": "session=private-session; csrf_token=private-csrf",
                "remediation": "Rotate any exposed token.",
            }],
        }
        sanitized = redact_report(report)
        serialized = json.dumps(sanitized)
        for secret in ("private-ticket", "private-auth", "private-session", "private-csrf"):
            self.assertNotIn(secret, serialized)
        html = render_html(report)
        self.assertNotIn("private-ticket", html)
        self.assertNotIn("private-auth", html)
        self.assertIn("Confidence:", html)
        self.assertIn("Approved paths:", html)
        self.assertIn("Checks skipped", html)
        self.assertIn("Discovered pages", html)
        self.assertIn("Inspected forms (not submitted)", html)
        self.assertNotIn("private-query", html)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            json_path = write_json_report(report, output, "safe")
            pdf_path = write_pdf_report(report, output, "safe")
            json_content = json_path.read_text(encoding="utf-8")
            for secret in ("private-ticket", "private-auth", "private-session", "private-csrf"):
                self.assertNotIn(secret, json_content)
            self.assertNotIn("private-query", json_content)
            data = json.loads(json_content)
            self.assertEqual(data["findings"][0]["status"], "potential")
            self.assertIn("priority_rank", data["findings"][0])
            pdf_bytes = pdf_path.read_bytes()
            self.assertTrue(pdf_bytes.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
