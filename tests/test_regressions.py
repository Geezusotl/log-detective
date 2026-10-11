"""Independent fixtures for false positives, source evidence, and streaming."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from logdetective.analyzer import MAX_BYTES, analyze, analyzeLines, markdownReport
from logdetective.files import analyzeFile

ROOT = Path(__file__).resolve().parents[1]


class RegressionTests(unittest.TestCase):
    def testSeverityWordsInMessagesAreNotMetadata(self):
        for text in [
            'Nov 15 01:02:03 gateway metrics[9]: error budget remaining 97%',
            'Nov 15 01:02:03 gateway metrics[9]: 0 errors, 0 warnings',
            '2026-11-15 01:02:03,429 INFO [metrics] error_rate=0.0',
            'INFO request 429 completed; sample rate 12',
            'INFO exited maintenance mode with code 0',
            'Nov 15 01:02:03 gateway supervisor[9]: service worker exited with code 0',
        ]:
            with self.subTest(text=text):
                report = analyze(text)
                self.assertEqual(report['findings'], [])
                self.assertEqual(report['summary']['counts']['error'], 0)

    def testStatus429RequiresResponseContext(self):
        for text in ['HTTP/1.1 429', 'ERROR status_code=429', 'Too Many Requests', 'WARN rate limit exceeded']:
            with self.subTest(text=text):
                self.assertIn('rate', {f['id'] for f in analyze(text)['findings']})

    def testSyslogFailuresHaveSpecificEvidence(self):
        text = '\n'.join([
            'Dec 02 10:00:01 host sshd[2]: Failed publickey for user alex from 192.0.2.2',
            'Dec 02 10:00:02 host worker[3]: worker exited with status 7',
            'Dec 02 10:00:03 host tls[4]: expired certificate rejected',
        ])
        report = analyze(text)
        self.assertEqual({f['id'] for f in report['findings']}, {'ssh-auth', 'process-exit', 'cert-expired'})
        for f in report['findings']:
            for e in f['evidence']:
                self.assertEqual(e['text'], text.split('\n')[e['line']-1])
        self.assertNotIn('attack', report['findings'][0]['observation'].lower())

    def testDeprecationsRemainVisibleAsNotices(self):
        text = '2026-11-15 01:02:03 WARNING old setting is deprecated'
        report = analyze(text)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['summary']['counts']['warning'], 1)
        self.assertEqual(report['notices'][0]['line'], 1)
        self.assertEqual(report['events'][0]['message'], text)
        self.assertIn('Notices (not incident findings)', markdownReport(report))
        # Deprecation wording must not suppress a real failure on the same line.
        self.assertTrue(analyze('WARNING deprecated endpoint: connection refused')['findings'])

    def testUnclassifiedMessagesDoNotInventAHypothesis(self):
        report = analyze('ERROR an unknown subsystem failed')
        self.assertIsNone(report['findings'][0]['hypothesis'])
        self.assertNotIn('Possible explanation:', markdownReport(report))

    def testJsonTsAndExplicitSeverity(self):
        report = analyze(json.dumps({'ts':'2026-11-15T01:02:03Z', 'level':'info', 'msg':'error budget remaining 97%'}))
        self.assertEqual(report['events'][0]['timestamp'], '2026-11-15T01:02:03Z')
        self.assertEqual(report['findings'], [])

    def testUnicodeSeparatorsDoNotShiftPhysicalLineReferences(self):
        report = analyze('INFO ordinary\u2028text\nERROR connection refused')
        self.assertEqual(report['findings'][0]['lines'], [2])
        self.assertEqual(report['summary']['lines'], 2)

    def testCompactEngineScansAllLinesAndKeepsSecretsPrivate(self):
        def records():
            for i in range(25000):
                if i == 21000:
                    yield 'ERROR connection refused password=private-value'
                elif i in (100, 101, 102):
                    yield ['-----BEGIN PRIVATE KEY-----', 'secret-key-body', '-----END PRIVATE KEY-----'][i-100]
                else:
                    yield 'INFO healthy'
        report = analyzeLines(records(), 'stream.log', compact=True)
        self.assertEqual(report['summary']['lines'], 25000)
        self.assertEqual(len(report['events']), 200)
        self.assertEqual(report['text'], '')
        self.assertEqual(report['findings'][0]['evidence'][0]['line'], 21001)
        self.assertNotIn('private-value', json.dumps(report))
        self.assertNotIn('secret-key-body', json.dumps(report))
        self.assertIn('L21001:', markdownReport(report))

    def testCompactAndFullEnginesAgree(self):
        lines = ['INFO start', 'ERROR connection refused token=secret', 'WARN old setting deprecated', 'INFO done']
        full = analyze('\n'.join(lines))
        compact = analyzeLines(iter(lines), 'Pasted log', compact=True)
        for key in ['summary', 'fingerprint', 'findings', 'redactions', 'notices']:
            self.assertEqual(full[key], compact[key])

    def testLegacyAndBomMarkedTextFiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            for encoding in ['latin-1', 'utf-16', 'utf-8-sig']:
                with self.subTest(encoding=encoding):
                    path = Path(temporary)/'input.log'
                    path.write_bytes('INFO café\nERROR No space left on device'.encode(encoding))
                    report = analyzeFile(path)
                    self.assertEqual(report['findings'][0]['id'], 'disk')
                    self.assertEqual(report['findings'][0]['lines'], [2])
                    self.assertIn('café', report['text'])

    def testExplicitUtf8DoesNotSilentlyFallBack(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'input.log'
            path.write_bytes(b'INFO caf\xe9')
            with self.assertRaises(UnicodeDecodeError):
                analyzeFile(path, encoding='utf-8')

    def testLargeFilesUseBoundedReports(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'input.log'
            path.write_text('INFO '+('x'*(MAX_BYTES+1))+'\nERROR connection refused',encoding='utf-8')
            report = analyzeFile(path)
            self.assertTrue(report['compact'])
            self.assertEqual(report['findings'][0]['lines'], [2])
            self.assertLess(len(json.dumps(report)), 20000)

    def testJsonErrorsAreStructuredAndExitNonzero(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'input.log'
            for data in [b'', b' \n\t', bytes(range(256))*4]:
                path.write_bytes(data)
                run = subprocess.run([sys.executable, '-m', 'logdetective', 'analyze', str(path), '--format', 'json'],
                                     cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(run.returncode, 1)
                native = json.loads(run.stdout)
                self.assertEqual(native['status'], 'error')
                self.assertTrue(native['error'])
                self.assertEqual(native['findings'], [])
                self.assertNotIn('Traceback', run.stderr)


if __name__ == '__main__':
    unittest.main()
