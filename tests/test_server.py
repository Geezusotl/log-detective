import http.client
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from logdetective.server import makeServer

ROOT = Path(__file__).resolve().parents[1]


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = makeServer(0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, payload=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        base = {"Content-Type": "application/json", "X-LogDetective-Token": self.server.token}
        base.update(headers or {})
        connection.request("GET" if payload is None else "POST", path, body=None if payload is None else json.dumps(payload), headers=base)
        response = connection.getresponse()
        status, mime, body = response.status, response.getheader("Content-Type"), response.read()
        connection.close()
        return status, mime, body

    def testAssetsAndHeaders(self):
        for path in ["/", "/style.css", "/app.js"]:
            self.assertEqual(self.request(path)[0], 200)

    def testConfigAndSamples(self):
        config = json.loads(self.request("/api/config")[2])
        self.assertEqual(config["token"], self.server.token)
        self.assertEqual(len(json.loads(self.request("/api/samples")[2])["samples"]), 5)

    def testAnalyzeEndpoint(self):
        status, _, body = self.request("/api/analyze", {"text": "ERROR Connection refused", "source": "test.log"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["findings"][0]["id"], "refused")

    def testRejectsCrossOrigin(self):
        self.assertEqual(self.request("/api/analyze", {"text": "INFO ok"}, {"Origin": "https://other.example"})[0], 403)

    def testRejectsMissingToken(self):
        self.assertEqual(self.request("/api/analyze", {"text": "INFO ok"}, {"X-LogDetective-Token": ""})[0], 403)

    def testRejectsForeignHost(self):
        self.assertEqual(self.request("/", headers={"Host": "evil.example"})[0], 403)

    def testRejectsWrongContentType(self):
        self.assertEqual(self.request("/api/analyze", {"text": "INFO ok"}, {"Content-Type": "text/plain"})[0], 415)

    def testRejectsInvalidPayloads(self):
        for payload in [{"text": ""}, [], {"text": 1}, {"text": "INFO ok", "redact": "yes"}]:
            self.assertEqual(self.request("/api/analyze", payload)[0], 400)

    def testTraversalDenied(self):
        for path in ["/../README.md", "/%2e%2e/README.md", "/samples/01-python-import.log"]:
            self.assertEqual(self.request(path)[0], 404)

    def testReportExportsCheckedSteps(self):
        status, _, body = self.request("/api/report", {"text": "ERROR Connection refused\npassword=secretvalue", "completed": ["refused:0"]})
        self.assertEqual(status, 200)
        report = json.loads(body)["markdown"]
        self.assertIn("- [x]", report)
        self.assertNotIn("secretvalue", report)

    @patch("logdetective.server.ai.listModels", side_effect=ValueError("Ollama unavailable"))
    def testUnavailableAIHandled(self, models):
        status, _, body = self.request("/api/models", {})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"], "Ollama unavailable")

    def testCLIAndNoOverwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.md"
            command = [sys.executable, "-m", "logdetective", "analyze", "samples/01-python-import.log", "--output", str(output)]
            first = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            before = output.read_text()
            second = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(second.returncode, 1)
            self.assertEqual(output.read_text(), before)

    def testCLIJson(self):
        result = subprocess.run([sys.executable, "-m", "logdetective", "analyze", "samples/05-healthy-session.log", "--format", "json"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["summary"]["counts"]["error"], 0)
