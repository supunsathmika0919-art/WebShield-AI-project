from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from webshield.crawler import crawl
from webshield.scanner import TargetValidationError, validate_target


class _CrawlerHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        if self.path == "/":
            body = (
                '<a href="/a?item=1#section">A</a>'
                '<a href="/a?item=1">Duplicate</a>'
                '<a href="/logout">Logout</a>'
                '<a href="/admin/delete.php">Delete</a>'
                '<a href="/a?session=private-value">Sensitive query</a>'
                '<a href="https://example.com/outside">External</a>'
                '<a href="/redirect">Redirect</a>'
                '<form action="/save?csrf=private-token" method="post">'
                '<input name="comment" value="private-form-value">'
                '<input type="hidden" name="csrf" value="private-csrf"></form>'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/a?item=1":
            body = b'<a href="/">Home</a>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/redirect":
            body = b""
            self.send_response(302)
            self.send_header("Location", "https://example.com/private")
        else:
            body = b"unexpected"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class CrawlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _CrawlerHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setUp(self) -> None:
        _CrawlerHandler.requests = []
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.target = validate_target(
            base_url + "/",
            "127.0.0.1",
            allow_local=True,
            allowed_paths=["/"],
        )

    def test_crawler_deduplicates_loops_and_enforces_origin_and_exclusions(self) -> None:
        result = crawl(
            self.target,
            allowed_paths=["/"],
            max_pages=10,
            max_depth=3,
            min_interval_seconds=0.5,
        )
        self.assertEqual(_CrawlerHandler.requests.count("/"), 1)
        self.assertEqual(_CrawlerHandler.requests.count("/a?item=1"), 1)
        self.assertNotIn("/logout", _CrawlerHandler.requests)
        self.assertNotIn("/admin/delete.php", _CrawlerHandler.requests)
        self.assertFalse(any("example.com" in path for path in _CrawlerHandler.requests))
        self.assertEqual(result["request_count"], 3)
        self.assertTrue(any(page["redirect_not_followed"] for page in result["pages"]))
        self.assertTrue(any("unapproved origin" in item["error"] for item in result["errors"]))

    def test_page_limit_caps_requests_and_forms_are_inspected_not_submitted(self) -> None:
        result = crawl(
            self.target,
            allowed_paths=["/"],
            max_pages=1,
            max_depth=5,
            min_interval_seconds=0.5,
        )
        self.assertEqual(result["request_count"], 1)
        self.assertEqual(len(result["pages"]), 1)
        self.assertEqual(len(result["forms"]), 1)
        self.assertFalse(result["forms"][0]["submitted"])
        self.assertEqual(result["forms"][0]["field_names"], ["comment", "csrf"])
        self.assertNotIn("private-csrf", str(result))
        self.assertNotIn("private-form-value", str(result))

    def test_query_parameter_names_are_recorded_but_values_are_redacted(self) -> None:
        result = crawl(
            self.target,
            allowed_paths=["/"],
            max_pages=5,
            max_depth=2,
            min_interval_seconds=0.5,
        )
        root = result["pages"][0]
        self.assertEqual(root["query_parameters"], [])
        query_page = next(page for page in result["pages"] if page["query_parameters"])
        self.assertEqual(query_page["query_parameters"], ["item"])
        self.assertNotIn("private-value", str(result))
        self.assertNotIn("private-token", str(result))

    def test_target_path_requires_explicit_approval(self) -> None:
        with self.assertRaises(TargetValidationError):
            validate_target(
                f"http://127.0.0.1:{self.server.server_port}/app/page",
                "127.0.0.1",
                allow_local=True,
            )
        target = validate_target(
            f"http://127.0.0.1:{self.server.server_port}/app/page",
            "127.0.0.1",
            allow_local=True,
            allowed_paths=["/app/"],
        )
        self.assertEqual(target.path, "/app/page")

    def test_out_of_scope_links_are_not_scheduled(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the explicitly approved path scope"):
            crawl(
                self.target,
                allowed_paths=["/a/"],
                max_pages=3,
                max_depth=2,
                min_interval_seconds=0.5,
            )


if __name__ == "__main__":
    unittest.main()
