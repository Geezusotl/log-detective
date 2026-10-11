# Validation history

## Version 1.1

Checked on October 11, 2026 after an externally supplied synthetic log test kit exposed false positives, missed syslog symptoms, and CLI input limitations.

- 55 Python tests passed, including 13 new regression checks for message-vs-metadata parsing, HTTP 429 context, syslog patterns, notices, physical line numbers, streaming retention and private-key redaction, encoding handling, and structured CLI errors.
- 20 browser checks passed, including healthy-metric false alarms, navigable deprecation notices, and specific syslog findings.
- The supplied 45-log set and a second 45-log set generated with seed 20261011 each passed all eight categories, scoring 100/100. Each found all 59 planted incidents, raised no findings on its 9 clean logs, and passed evidence, separation, privacy, injection, robustness, and determinism checks.
- The approximately 105 MB streaming case passed within the kit's 120-second and 1 GB limits. This run took approximately 70 seconds and 17 MB of measured peak memory; hardware affects these measurements.

Empty and binary files still return errors. Their JSON errors are now readable by the harness rather than being mistaken for missing output. Latin-1 text is supported by the CLI with a disclosed fallback. The browser retains its smaller input limits. Large CLI reports contain bounded previews and cited excerpts, not a full source export.

The test-kit adapter is included in `tests/testkit_adapter.py`. It maps genuine observations, non-null hypotheses, and native evidence entries; it does not read logs or answer keys. Null hypotheses are absence of a cause, not suppressed speculation. Deprecation notices are available in the browser explorer, a separate findings-panel section, and report exports.

These are synthetic log tests. They do not establish universal diagnostic quality or prompt-injection resistance of an actual Ollama model. AI transport/validation remains tested using synthetic responses.

With your extracted test kit, run from the project root:

```bash
python3 /path/to/log-detective-testkit/run_tests.py --cmd "python3 -m logdetective analyze {file} --format json" --adapter tests/testkit_adapter.py --report-dir report --big
python3 /path/to/log-detective-testkit/generate.py --seed 20261011 --out fresh-cases
python3 /path/to/log-detective-testkit/run_tests.py --cmd "python3 -m logdetective analyze {file} --format json" --adapter tests/testkit_adapter.py --cases fresh-cases --report-dir fresh-report
```

## Version 1.0

Checked during development on October 10, 2026.

## Passed

**42 Python tests**, executed on Linux with Python 3.12.14:

- Recognizing 16 specialized symptom categories.
- Correct findings and line references in the sample fixtures.
- Grouping repeated failures while retaining full occurrence counts.
- Unknown errors, healthy logs, file-order events, JSON Lines parsing, and ANSI/line-ending normalization.
- Redacting common secrets, credential-bearing URLs, email addresses, and complete or unterminated private key blocks.
- Preserving line numbers and valid JSON after supported redaction.
- Empty, invalid, oversized, and excessive-line input rejection.
- Markdown evidence, checked steps, literal evidence fences, and source redaction.
- CLI reports, JSON output, and refusal to overwrite existing files.
- Local HTTP endpoints, session tokens, content types, Host/Origin checks, and asset allowlisting.
- AI structure/citation validation, exclusion of advertised cloud models, and redaction before AI requests.
- Actual HTTP communication with a synthetic local Ollama-compatible fixture, including rejection of redirects and non-JSON responses.

**17 browser workflow checks**, executed with Playwright 1.62.1 and headless Chromium 153 on Linux:

- App initialization and five sample cases.
- Known import failure and correct counts.
- Evidence navigation to the correct source line.
- Timeline severity filtering.
- Checklist state and downloaded Markdown report.
- Redaction and downloaded JSON report.
- UTF-8 uploads and BOM-marked UTF-16 uploads.
- Empty-file handling.
- Healthy logs without an unsupported health claim.
- Literal rendering of log content containing HTML/script text.
- Pagination and message search.
- Invalidation of results when the input changes.
- AI suggestion rendering with a mocked, explicitly synthetic response.
- Unavailable local AI service handling.
- Mobile width at 390 pixels without horizontal page overflow.
- No JavaScript page errors or external app requests in the exercised workflows.

The desktop interface was also visually inspected. Browser binaries were installed separately for verification; they are not bundled or required to use Log Detective in your existing browser.

## GitHub Actions

The [initial upload workflow](https://github.com/Geezusotl/log-detective/actions/runs/38098353953) completed successfully. All five jobs passed: Python tests on Ubuntu and Windows with Python 3.10 and 3.12, and the Chromium browser workflow on Ubuntu. This additionally verifies the committed project in fresh environments. It does not establish that the Windows batch launcher has been used interactively on a physical PC.

## Not yet verified

- Launching the batch files on a physical Windows PC. The app's Python and browser code were tested on Linux; Windows launch instructions and CI checks are included.
- Actual model-generated answer quality or speed. AI transport and validation were tested using synthetic responses; no real model weights were installed in this environment.
- Exhaustive coverage of arbitrary log formats, encodings, secrets, or production failure cases. Rules and redaction are deliberately documented as limited.

## Reproduce

```bash
python3 -m unittest discover -s tests -v
npm install
npx playwright install chromium
npm run test:browser
```

Use `LOGDETECTIVE_PYTHON` to select a Python executable. Developers with an existing Chromium binary can set `LOGDETECTIVE_BROWSER` to its absolute executable path. Standard Playwright installation is the default. A screenshot can be produced for local review by setting `LOGDETECTIVE_SCREENSHOT` to an output path.
