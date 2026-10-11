# Understanding Log Detective

## What problem does it solve?

A log often contains many routine messages and a few clues. Log Detective extracts recognizable symptoms, groups repeats, and connects each issue to the source evidence. A checklist turns that evidence into a practical investigation.

## Follow one request

1. The browser reads a file or accepts pasted text. It does not execute log content.
2. JavaScript sends text to the Python server running on the same computer.
3. The analyzer normalizes line endings and terminal color codes, checks limits, and optionally redacts common secrets.
4. It parses severity and timestamps, including common JSON Lines fields.
5. Rules recognize symptom categories. Unmatched error and warning messages remain visible as unclassified findings.
6. The browser renders the findings using text nodes, preventing log text from becoming HTML.
7. Evidence buttons navigate to source lines. Checkboxes record checks attempted during this session.
8. A report export assembles evidence and checklist state into a downloadable file.

## Where does AI fit?

AI is a separate optional request. The app selects a bounded excerpt, redacts it, and sends numbered lines to a local Ollama model. The model returns a summary, hypotheses, line citations, and manual checks.

The server validates the structure and ensures each hypothesis references lines actually supplied to the model. This catches invented line numbers and malformed responses. It does not prove that the model interpreted a real line correctly. That is why AI findings remain explicitly unverified.

The AI prompt treats logs as untrusted data. This reduces instruction-following risk, but prompt instructions alone cannot guarantee model behavior. The model has no tools and cannot execute commands or alter files through this app.

## Why these technical choices?

| Choice | Reason | Tradeoff |
| --- | --- | --- |
| Standard-library Python | Simple launch without dependency installation | Local server is not a public production deployment |
| Plain browser JavaScript | Small project with no frontend build step | Manual state management rather than a framework |
| Deterministic rules | Repeatable, inspectable baseline without AI | Limited to recognizable patterns; false positives are possible |
| Optional local model | AI can run without API credentials | User needs Ollama, a downloaded model, and suitable hardware |
| No database | Minimal setup and no automatic persistence of logs | History and checklist state disappear on reload |
| Markdown and JSON exports | Readable reports and machine-readable results | Users must deliberately export and review reports |

## Explaining it in a conversation

You can describe the project as: “A local log investigation tool that groups failure symptoms and links findings to source lines. It works with deterministic rules and optionally adds local AI suggestions. I used AI assistance during development and included automated checks for the parser, reports, HTTP API, and browser workflow.”

If asked about validation, distinguish three things: a rule matching a known symptom, a model citing a supplied line, and a diagnosis being correct. These are different claims.

## Small improvements to learn from

- Add one symptom rule and a matching test in `test_analyzer.py`.
- Add a new synthetic sample log and verify its expected findings.
- Improve grouping so distinct resources can be separated within a category.
- Add a dedicated evaluation set to measure AI suggestion quality across local models.
- Add opt-in local investigation history with explicit deletion controls.

You do not need to implement these to use version 1. They are possible next steps.
