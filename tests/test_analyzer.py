import json
import unittest
from pathlib import Path

from logdetective.analyzer import MAX_BYTES, analyze, markdownReport, redactText

ROOT = Path(__file__).resolve().parents[1]


class AnalyzerTests(unittest.TestCase):
    def testKnownSymptoms(self):
        examples = {
            "missing-module": "ModuleNotFoundError: No module named 'requests'",
            "missing-symbol": "ImportError: cannot import name 'StopFlag' from 'auto_recruit'",
            "missing-file": "FileNotFoundError: [Errno 2] No such file or directory",
            "permission": "PermissionError: Permission denied",
            "refused": "ConnectionRefusedError: connection refused",
            "timeout": "TimeoutError: operation timed out",
            "dns": "socket.gaierror: getaddrinfo failed",
            "tls": "SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED",
            "auth": "ERROR HTTP 403 Forbidden",
            "rate": "WARNING HTTP 429 Too Many Requests",
            "memory": "MemoryError: unable to allocate",
            "disk": "OSError: No space left on device",
            "port": "OSError: Address already in use",
            "json": "JSONDecodeError: Expecting value",
            "syntax": "IndentationError: unexpected indent",
            "database": "OperationalError: database is locked",
        }
        for key, text in examples.items():
            with self.subTest(key=key):
                report = analyze(text)
                self.assertEqual(report["findings"][0]["id"], key)
                self.assertEqual(report["findings"][0]["lines"], [1])
                self.assertIn(report["findings"][0]["severity"], {"error", "warning"})

    def testImportFixture(self):
        report = analyze((ROOT / "samples/01-python-import.log").read_text())
        symptom = next(f for f in report["findings"] if f["id"] == "missing-symbol")
        self.assertEqual(symptom["lines"], [6])
        self.assertEqual(report["summary"]["counts"]["error"], 2)
        self.assertIn("StopFlag", report["text"].splitlines()[5])

    def testRepeatedErrorsGroup(self):
        report = analyze((ROOT / "samples/02-network-retries.log").read_text())
        symptom = next(f for f in report["findings"] if f["id"] == "refused")
        self.assertEqual(symptom["occurrences"], 3)
        self.assertEqual(symptom["lines"], [3, 5, 7])
        self.assertEqual(report["summary"]["counts"]["warning"], 2)

    def testStructuredFixture(self):
        report = analyze((ROOT / "samples/04-structured-events.log").read_text())
        self.assertEqual(report["summary"]["counts"]["error"], 2)
        self.assertEqual(report["events"][1]["timestamp"], "2026-10-10T11:00:01Z")
        self.assertEqual(report["events"][1]["message"], "PermissionError: access denied writing report.csv")

    def testHealthyDoesNotClaimSuccess(self):
        report = analyze((ROOT / "samples/05-healthy-session.log").read_text())
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["counts"]["error"], 0)
        self.assertIn("does not establish", markdownReport(report))

    def testUnknownFailure(self):
        report = analyze("INFO start\nValueError: impossible value\nWARNING unusual condition")
        self.assertEqual({f["id"] for f in report["findings"]}, {"unclassified-error", "unclassified-warning"})

    def testRedactionPreservesLineNumbers(self):
        original = 'INFO account user@example.com\npassword="hello world"\nAuthorization: Bearer abc.def.ghi\nhttps://admin:secret@example.com/path\n'
        clean, count = redactText(original)
        for secret in ["user@example.com", "hello world", "abc.def.ghi", "admin:secret"]:
            self.assertNotIn(secret, clean)
        self.assertEqual(clean.count("\n"), original.count("\n"))
        self.assertGreaterEqual(count, 4)

    def testRedactedJsonStillParses(self):
        text = json.dumps({"level": "error", "message": "Operation timed out", "token": "abc", "api_key": "secret"})
        report = analyze(text)
        item = json.loads(report["text"])
        self.assertEqual(item["token"], "[REDACTED]")
        self.assertEqual(report["events"][0]["message"], "Operation timed out")

    def testPrivateKeysAndUnterminatedKeys(self):
        for ending in ["-----END RSA PRIVATE KEY-----", ""]:
            text = "INFO start\n-----BEGIN RSA PRIVATE KEY-----\nsecretmaterial\n" + ending
            report = analyze(text)
            self.assertNotIn("secretmaterial", report["text"])
            self.assertEqual(report["summary"]["lines"], len(text.splitlines()))

    def testRedactionOptional(self):
        report = analyze("ERROR password=secret", redact=False)
        self.assertIn("secret", report["text"])
        self.assertEqual(report["redactions"], 0)

    def testSourceRedacted(self):
        self.assertNotIn("person@example.com", analyze("INFO ok", "person@example.com.log")["source"])

    def testAnsiAndCrLf(self):
        report = analyze("\x1b[31mERROR Permission denied\x1b[0m\r\nINFO done\r\n")
        self.assertNotIn("\x1b", report["text"])
        self.assertEqual(report["summary"]["lines"], 2)
        self.assertEqual(report["findings"][0]["lines"], [1])

    def testSizeAndInputGuards(self):
        for text in ["", " \n\t", None, 2, "x" * (MAX_BYTES + 1), "x\n" * 20001]:
            with self.subTest(text=str(text)[:30]):
                with self.assertRaises(ValueError):
                    analyze(text)

    def testEvidenceCapKeepsOccurrenceCount(self):
        report = analyze("\n".join(["ERROR Connection refused"] * 250))
        self.assertEqual(report["findings"][0]["occurrences"], 250)
        self.assertEqual(len(report["findings"][0]["lines"]), 100)

    def testMarkdownContainsCompletedChecksAndEvidence(self):
        report = analyze("ERROR Connection refused\npassword=secret")
        markdown = markdownReport(report, ["refused:0"])
        self.assertIn("- [x]", markdown)
        self.assertIn("L1: ERROR Connection refused", markdown)
        self.assertNotIn("password=secret", markdown)

    def testMarkdownCannotEscapeEvidenceFence(self):
        report = analyze("ERROR <script>alert(1)</script>```", "<img src=x>")
        markdown = markdownReport(report)
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("<img", markdown)
        self.assertIn("'''", markdown)

    def testStableFingerprint(self):
        self.assertEqual(analyze("INFO ok")["fingerprint"], analyze("INFO ok")["fingerprint"])
        self.assertNotEqual(analyze("INFO ok")["fingerprint"], analyze("INFO changed")["fingerprint"])

    def testFileOrderPreserved(self):
        report = analyze("2026-10-10T13:00:00Z INFO later\n2026-10-10T12:00:00Z INFO earlier")
        self.assertEqual(report["events"][0]["message"], "2026-10-10T13:00:00Z INFO later")
        self.assertIn("file order", report["limitations"])
