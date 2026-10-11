# Log Detective

**Turn application logs into an investigation you can follow.**

Log Detective is a local troubleshooting tool with a browser interface and a command-line mode. It groups recognizable failure symptoms, links every finding to its source lines, offers manual checks, and exports a support-ready report. An optional local AI model can suggest additional explanations.

The core app uses Python's standard library and plain HTML, CSS, and JavaScript. No account, API key, or Python package installation is required.

## Quick start on Windows

1. Extract the entire ZIP. Do not launch from inside the ZIP viewer.
2. Open the extracted `LogDetective` folder.
3. Double-click **StartLogDetective.bat**.
4. Your browser opens the local app. Choose a sample, then click **Analyze log**.

Requires Python 3.10 or newer. If the launcher says Python is missing, install it from [python.org](https://www.python.org/downloads/windows/), enable **Add Python to PATH**, and launch again. Administrator access is not required.

Keep the command window open while using the app. Stop the server with Ctrl+C. The default address is `http://127.0.0.1:8765`.

### macOS, Linux, or manual launch

From this project's root folder:

```bash
python3 -m logdetective serve
```

On Windows, use `py -3` instead of `python3`. If port 8765 is occupied:

```bash
python3 -m logdetective serve --port 8766
```

## What you can do

- Paste logs, drop a text file, or use five included sample cases.
- Investigate Python import failures, missing files, permissions, connection failures, timeouts, DNS, TLS, API authentication, rate limits, memory, storage, port conflicts, JSON parsing, syntax errors, and database locks.
- Group repeated symptoms while preserving occurrence counts and source line references.
- Read observations separately from possible explanations.
- Click evidence references to open the log at the relevant line.
- Search messages, filter severity, and navigate paginated events.
- Mark troubleshooting checks complete and include them in a Markdown report.
- Export the analysis as JSON for further processing.
- Optionally request cited suggestions from an installed local Ollama model.

Supported input: UTF-8 text, BOM-marked UTF-16 text through the browser, and JSON Lines with `message`/`msg`, `level`/`severity`, and `timestamp`/`time` fields. The CLI accepts UTF-8 and UTF-8 with a BOM. Limit: 2 MiB of normalized UTF-8 content and 20000 lines. The browser also checks the uploaded file's byte size. Compressed files and binary Windows Event Log files are not supported.

## A short demo

1. Load **01 Python Import** and analyze it.
2. Find the import failure. Click **L6** to see the exception in context.
3. Return to Findings and mark one check complete.
4. Export a Markdown report. It contains the evidence and checklist state.
5. Load **03 API And Secrets** to inspect redaction and API failure patterns.
6. Load **05 Healthy Session** to see how the app handles logs without recognized issues.

All sample credentials and paths are fictional. The import sample is inspired by a practical startup troubleshooting scenario.

## Optional AI setup

The rule-based app is fully functional without AI. To enable AI explanations:

1. Install [Ollama](https://ollama.com/download) and leave its local service running.
2. Download a local text model suited to your hardware. One possible starting point is [qwen3:4b-instruct](https://ollama.com/library/qwen3:4b-instruct):

   ```bash
   ollama pull qwen3:4b-instruct
   ```

3. Analyze a log in Log Detective.
4. Select **Find local models**, choose the installed model, and select **Explain with AI**.

The adapter contacts only `http://127.0.0.1:11434`, bypasses HTTP proxy configuration, rejects redirects, and excludes model entries advertised as remote/cloud. Use a genuinely local model; custom local Ollama configuration is outside the app's control. Log Detective does not download models automatically.

AI receives a bounded excerpt of relevant log lines, always with the app's best-effort redaction enabled. It requests structured JSON and rejects malformed output or citations outside the supplied excerpt. An available line citation does **not** establish that the explanation is correct. AI output is labeled unverified. Model availability, performance, and answer quality depend on your model and hardware; requests time out after 90 seconds.

## Command-line reports

```bash
python3 -m logdetective analyze samples/01-python-import.log
python3 -m logdetective analyze samples/02-network-retries.log --format json
python3 -m logdetective analyze samples/01-python-import.log --output investigation.md
```

The CLI refuses to overwrite an existing output file. Use `--no-redact` only if you deliberately want an unredacted local report. AI is accessed through the browser in this version.

## Tests

Python checks need no additional dependencies:

```bash
python3 -m unittest discover -s tests -v
```

Optional browser checks for contributors require Node.js and Playwright:

```bash
npm install
npx playwright install chromium
npm run test:browser
```

Set `LOGDETECTIVE_PYTHON` if the test runner should use a particular Python executable. Browser tests start their own server on an available port. They cover uploads, navigation, filters, report downloads, redaction, pagination, literal rendering of untrusted logs, invalidation of stale results, a mocked AI response, and mobile width. See [the validation notes](docs/Validation.md) for exactly what was checked and what remains unverified.

The included GitHub Actions workflow runs Python checks on Linux and Windows with Python 3.10 and 3.12, plus Chromium browser checks on Linux. Those remote jobs have not run until the project is pushed to GitHub and Actions executes.

## Design and limits

- **Evidence first:** deterministic rules identify symptoms. They do not assert proven root causes.
- **Local by default:** logs are held in server/browser memory. No database, telemetry, or automatic log uploads. Files are written only when you explicitly export a report.
- **Best-effort redaction:** common passwords, tokens, bearer/basic credentials, credential-bearing URLs, private keys, and email addresses are masked. It can miss secrets in unusual formats. Review shared reports. Names and other personal information are not comprehensively removed.
- **File order:** timestamps are displayed as found; events are not reordered or normalized across time zones.
- **Grouping:** findings group by symptom category, not by a proven common cause. At most 100 evidence references are retained per finding; occurrence counts include all matches.
- **Browser limits:** analysis supports multiple formats, but unusual encodings or structured fields may need conversion. Multi-line JSON documents are not parsed as one event.
- **Local server:** binds to loopback, restricts Host/Origin, uses a session token for POST requests, and serves only allowlisted assets. It is a personal local app, not an internet-facing production server. Do not expose it through a tunnel or public binding.

## Project map

| Path | Purpose |
| --- | --- |
| `logdetective/analyzer.py` | Rules, redaction, parsing, Markdown report |
| `logdetective/ai.py` | Optional Ollama adapter and output validation |
| `logdetective/server.py` | Local HTTP app and input validation |
| `logdetective/__main__.py` | Browser and CLI entry points |
| `logdetective/web/` | Browser interface |
| `samples/` | Five synthetic log scenarios |
| `tests/` | Python and optional browser checks |
| `docs/` | Walkthrough, validation, and GitHub setup |

## Portfolio notes

This project demonstrates log processing, regular expressions, structured data handling, browser interfaces, an HTTP API, local model integration, input validation, and automated checks. Development used AI assistance. The important distinction is that the deterministic analyzer works independently of the model, while AI is an optional, validated suggestion layer.

Read [the project walkthrough](docs/ProjectWalkthrough.md) to understand the code and tradeoffs. Read [GitHub setup](docs/GitHubSetup.md) when you are ready to publish the repository.

### References

- [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs)
- [Ollama API](https://docs.ollama.com/api)
- [Python local HTTP server documentation](https://docs.python.org/3/library/http.server.html)

MIT licensed.
