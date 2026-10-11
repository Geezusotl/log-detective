import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from logdetective.ai import explain, listModels, requestJson, validateAnswer
from logdetective.analyzer import analyze


class AITests(unittest.TestCase):
    def valid(self):
        return {"summary": "A service may be unavailable.", "hypotheses": [{"explanation": "Check the local service.", "lines": [1]}], "checks": ["Check its listening port."]}

    def testAcceptsCitedSuggestion(self):
        self.assertEqual(validateAnswer(self.valid(), {1})["hypotheses"][0]["lines"], [1])

    def testRejectsUnsupportedCitations(self):
        for number in [0, 2, True, "1"]:
            answer = self.valid()
            answer["hypotheses"][0]["lines"] = [number]
            with self.subTest(number=number), self.assertRaises(ValueError):
                validateAnswer(answer, {1})

    def testRejectsMalformedOutput(self):
        for answer in [None, [], {}, {"summary": "ok", "hypotheses": "bad", "checks": []}, {"summary": "ok", "hypotheses": [], "checks": [1]}]:
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                validateAnswer(answer, {1})

    def testAllowsInsufficientEvidence(self):
        self.assertEqual(validateAnswer({"summary": "Insufficient evidence.", "hypotheses": [], "checks": []}, {1})["hypotheses"], [])

    @patch("logdetective.ai.requestJson")
    def testCloudEntriesExcluded(self, request):
        request.return_value = {"models": [{"name": "local:latest"}, {"name": "remote:cloud"}, {"name": "remote:20b-cloud"}, {"name": "remote:latest", "remote_host": "https://example.com"}]}
        self.assertEqual(listModels(), ["local:latest"])

    @patch("logdetective.ai.requestJson")
    def testAdapterRedactsAndUsesStructuredOutput(self, request):
        captured = []
        def fake(path, payload=None, timeout=5):
            if path == "/api/tags":
                return {"models": [{"name": "local:latest"}]}
            captured.append(payload)
            return {"message": {"content": json.dumps(self.valid())}}
        request.side_effect = fake
        answer = explain(analyze("ERROR Connection refused\npassword=secretvalue", redact=False), "local:latest")
        self.assertEqual(answer["hypotheses"][0]["lines"], [1])
        self.assertNotIn("secretvalue", json.dumps(captured))
        self.assertFalse(captured[0]["stream"])
        self.assertEqual(captured[0]["format"]["type"], "object")
        self.assertIn("untrusted evidence", captured[0]["messages"][0]["content"])

    @patch("logdetective.ai.listModels", return_value=["local:latest"])
    def testOnlyInstalledModelAllowed(self, models):
        with self.assertRaises(ValueError):
            explain(analyze("ERROR failure"), "other:latest")

    @patch("logdetective.ai.requestJson")
    def testInvalidModelOutputRejected(self, request):
        request.side_effect = [{"models": [{"name": "local:latest"}]}, {"message": {"content": "not JSON"}}]
        with self.assertRaises(ValueError):
            explain(analyze("ERROR failure"), "local:latest")


class AITransportTests(unittest.TestCase):
    """Real local HTTP transport, using a synthetic service, not a real model."""

    def setUp(self):
        class FakeService(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/api/tags")
                    self.end_headers()
                    return
                if self.path == "/invalid":
                    body = b"not JSON"
                else:
                    body = json.dumps({"models": [{"name": "fixture:latest"}]}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert payload["model"] == "fixture:latest"
                body = json.dumps({"message": {"content": json.dumps({"summary": "Synthetic transport fixture.", "hypotheses": [{"explanation": "Possible service failure.", "lines": [1]}], "checks": ["Inspect the service."]})}}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeService)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.patch = patch("logdetective.ai.OLLAMA", "http://127.0.0.1:" + str(self.server.server_address[1]))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def testRealHTTPAdapter(self):
        self.assertEqual(listModels(), ["fixture:latest"])
        answer = explain(analyze("ERROR Connection refused"), "fixture:latest")
        self.assertEqual(answer["summary"], "Synthetic transport fixture.")

    def testRedirectRejected(self):
        with self.assertRaises(ValueError):
            requestJson("/redirect")

    def testNonJsonResponseRejected(self):
        with self.assertRaises(ValueError):
            requestJson("/invalid")
