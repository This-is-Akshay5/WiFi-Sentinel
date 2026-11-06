import unittest
from unittest.mock import patch

from core.web_analysis import WebTargetError, analyze_site, analyze_url


class WebSurfaceAnalysisTests(unittest.TestCase):
    def test_site_crawl_is_same_origin_bounded_and_builds_observed_route_inventory(self):
        pages = {
            "https://example.org/": {"status": 200, "headers": [("Content-Type", "text/html")],
                "body": b'<a href="/api/status">API</a><a href="/account">Account</a><a href="https://other.invalid/">Other</a>'},
            "https://example.org/api/status": {"status": 200, "headers": [("Content-Type", "application/json")], "body": b'{"ok":true}'},
            "https://example.org/account": {"status": 404, "headers": [("Content-Type", "text/html")], "body": b"not found"},
        }
        def fetch(url, expected_origin=None, redirect_count=0):
            self.assertEqual(expected_origin, ("https", "example.org", 443))
            return {**pages[url], "truncated": False, "final_url": url}
        with patch("core.web_analysis._fetch_same_origin", side_effect=fetch) as requested:
            result = analyze_site("https://example.org/", max_pages=5)
        self.assertEqual([page["path"] for page in result["pages"]], ["/", "/api/status", "/account"])
        self.assertEqual(result["route_inventory"], ["/", "/account", "/api/status"])
        self.assertEqual(result["api_routes"], ["/api/status"])
        self.assertEqual(requested.call_count, 3)
        self.assertEqual(result["execution"], "read_only_same_origin_get")

    def test_site_crawl_enforces_page_cap_and_rejects_invalid_limit(self):
        with self.assertRaises(WebTargetError):
            analyze_site("https://example.org/", max_pages=21)

    def test_site_crawl_never_follows_cross_origin_link_or_redirect(self):
        response = {"status": 200, "headers": [("Content-Type", "text/html")],
                    "body": b'<a href="http://169.254.169.254/latest/meta-data/">outside</a>',
                    "truncated": False, "final_url": "http://example.org/"}
        with patch("core.web_analysis._fetch_same_origin", return_value=response) as requested:
            result = analyze_site("http://example.org/")
        self.assertEqual(result["pages_scanned"], 1)
        self.assertEqual(requested.call_count, 1)

    def test_site_crawl_runs_against_a_real_local_http_server(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Thread

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = (b'<a href="/api/health">health</a>' if self.path == "/" else b'{"ok":true}')
                self.send_response(200)
                self.send_header("Content-Type", "text/html" if self.path == "/" else "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            result = analyze_site(f"http://127.0.0.1:{server.server_port}/", max_pages=4)
            self.assertEqual(result["pages_scanned"], 2)
            self.assertEqual(result["api_routes"], ["/api/health"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_rejects_non_http_urls_credentials_and_query_strings(self):
        for url in ("file:///etc/passwd", "ftp://example.org/", "https://user:pw@example.org/",
                    "https://example.org/?token=secret"):
            with self.subTest(url=url), self.assertRaises(WebTargetError):
                analyze_url(url)

    def test_captures_same_origin_surface_without_form_submission_or_values(self):
        html = b'''<html><a href="/api/status">status</a><a href="https://outside.invalid/x">outside</a>
        <form method="post" action="/login"><input name="user" value="not-collected"></form></html>'''
        response = {"status": 200, "headers": [("Content-Type", "text/html"),
            ("Set-Cookie", "session=private-cookie; Path=/; SameSite=Lax")], "body": html,
            "final_url": "https://example.org/"}
        with patch("core.web_analysis._fetch_same_origin", return_value=response):
            result = analyze_url("https://example.org/")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["links"], ["https://example.org/api/status"])
        self.assertEqual(result["forms"][0]["method"], "POST")
        self.assertNotIn("not-collected", str(result))
        self.assertNotIn("private-cookie", str(result))
        self.assertEqual(result["cookies"][0]["name"], "session")


    def test_cross_origin_redirect_is_blocked_before_second_request(self):
        class Response:
            status = 302
            def getheaders(self): return [("Location", "http://169.254.169.254/latest/meta-data/")]
            def read(self, size=-1): return b""
        class Connection:
            def __init__(self, *args, **kwargs): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        with patch("core.web_analysis._resolve", return_value="192.0.2.10") as resolver, \
             patch("core.web_analysis._PinnedHTTP", Connection):
            with self.assertRaises(WebTargetError):
                analyze_url("http://example.org/")
        resolver.assert_called_once()

    def test_missing_security_headers_are_observations_not_verified_exploit_claims(self):
        with patch("core.web_analysis._fetch_same_origin", return_value={
            "status": 200, "headers": [("Content-Type", "text/html")], "body": b"<html></html>",
            "final_url": "http://example.org/"}):
            result = analyze_url("http://example.org/")
        self.assertTrue(result["indicators"])
        self.assertTrue(all(item["confidence"] == "Observed" for item in result["indicators"]))
        self.assertIn("read-only", result["method"])


if __name__ == "__main__":
    unittest.main()

class WebSurfaceBridgeTests(unittest.TestCase):
    def test_bridge_requires_confirmation_and_persists_response_evidence(self):
        import tempfile
        from pathlib import Path
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            test_store = Store(Path(temp_dir) / "web.db")
            original_store = app.store
            result = {"target_origin": "http://127.0.0.1:8080", "requested_path": "/",
                      "status_code": 200, "response_truncated": False,
                      "headers": [], "links": [], "forms": [], "cookies": [],
                      "indicator_count": 1, "indicators": [{"title": "Header not observed",
                       "severity": "Low", "confidence": "Observed", "description": "Observed missing header.",
                       "rule_id": "WEB-HEADER-MISSING", "recommendation": "Review header policy."}],
                      "limitations": ["read-only"]}
            try:
                app.store = test_store
                bridge = app.Bridge()
                with self.assertRaises(ValueError):
                    bridge.analyze_web_url("http://127.0.0.1:8080/", authorized=False)
                with patch.object(app, "analyze_url", return_value=result):
                    response = bridge.analyze_web_url("http://127.0.0.1:8080/", authorized=True)
                state = test_store.state(response["assessment_id"])
                self.assertEqual(len(state["evidence"]), 1)
                self.assertEqual(len(state["findings"]), 1)
                self.assertEqual(state["assessment"]["target"], result["target_origin"])
            finally:
                test_store.close()
                app.store = original_store

    def test_bridge_requires_confirmation_and_persists_crawl_routes_indicators_and_evidence(self):
        import tempfile
        from pathlib import Path
        import main as app
        from core.store import Store

        with tempfile.TemporaryDirectory() as temp_dir:
            test_store = Store(Path(temp_dir) / "crawl.db")
            original_store = app.store
            result = {"execution": "read_only_same_origin_get", "target_origin": "http://127.0.0.1:8080",
                      "requested_path": "/", "max_pages": 3, "pages_scanned": 1,
                      "page_limit_reached": False, "response_truncated": False,
                      "pages": [{"path": "/", "status_code": 200, "content_type": "text/html",
                                 "response_truncated": False, "links": [], "forms": [], "indicator_count": 1}],
                      "route_inventory": ["/"], "api_routes": [], "indicator_count": 1,
                      "indicators": [{"title": "CSP missing", "severity": "Low", "confidence": "Observed",
                         "description": "Header not observed.", "rule_id": "WEB-CSP-MISSING", "path": "/",
                         "recommendation": "Review policy."}], "limitations": ["Bounded read-only scan."]}
            try:
                app.store = test_store
                bridge = app.Bridge()
                with self.assertRaises(ValueError):
                    bridge.analyze_web_site("http://127.0.0.1:8080/", 3, authorized=False)
                with patch.object(app, "analyze_site", return_value=result):
                    response = bridge.analyze_web_site("http://127.0.0.1:8080/", 3, authorized=True)
                state = test_store.state(response["assessment_id"])
                self.assertEqual(state["evidence"][0]["test_id"], "web_surface_crawl")
                self.assertEqual(state["findings"][0]["evidence_id"], response["evidence_id"])
                self.assertEqual(state["findings"][0]["asset"], "http://127.0.0.1:8080/")
                self.assertIn("/", state["evidence"][0]["content_preview"])
            finally:
                test_store.close()
                app.store = original_store
