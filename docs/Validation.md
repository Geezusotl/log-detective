# Version 1 validation

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
