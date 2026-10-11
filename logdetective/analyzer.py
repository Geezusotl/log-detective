"""Deterministic log analysis. No network access or execution of log content."""

import hashlib
import json
import re
from datetime import datetime, timezone

MAX_BYTES = 2 * 1024 * 1024
MAX_LINES = 20000
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
STAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
LEVEL = re.compile(r"^\s*\[?(CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG)\]?(?=$|[\s:|])")
SYSLOG = re.compile(r"^(?:<\d+>)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[^:]+:\s*(.*)$")
NOTICE = re.compile(r"\bdeprecated\b|\bdeprecation\b|\bwill be removed in\b", re.I)
CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Patterns describe an observed symptom, never an inferred root cause.
RULES = [
    ("missing-module", r"ModuleNotFoundError|No module named", "Python module unavailable", "error",
     "The interpreter could not locate a requested module.",
     "The package may be absent from this interpreter, or the module search path may differ from the intended environment.",
     ["Check which Python interpreter launches the app, including its virtual environment.", "Compare the missing module with the project's documented dependencies.", "Check local module names and the working directory before installing anything."]),
    ("missing-symbol", r"ImportError:.*(?:cannot import name|DLL load failed)", "Import failed", "error",
     "An import failed while loading a symbol or a native dependency.",
     "Files or dependency versions may disagree; a circular import or missing native library is also possible.",
     ["Read the named module and confirm that the requested symbol exists.", "Check for mixed project versions, circular imports, or a local file shadowing a package.", "Compare the active environment with the project's supported dependency versions."]),
    ("missing-file", r"FileNotFoundError|No such file or directory|ENOENT\b", "File or directory unavailable", "error",
     "A referenced path could not be found.", "A relative path, moved file, or incorrect configuration may be involved.",
     ["Verify the referenced path and the application's working directory.", "Check whether setup creates or downloads the required file.", "Confirm the configured path on this operating system."]),
    ("permission", r"PermissionError|Permission denied|EACCES\b|Access is denied", "Access denied", "error",
     "An operation was denied access.", "File permissions, a locked resource, or the account running the process may explain this symptom.",
     ["Identify the exact resource and account involved.", "Check ownership, permissions, and whether another process holds the file.", "Use the least privilege needed; do not assume administrator access is the fix."]),
    ("refused", r"ConnectionRefusedError|connection refused|ECONNREFUSED\b", "Connection refused", "error",
     "A connection attempt was refused.", "The target service may be stopped, listening on another port, or rejecting the connection.",
     ["Confirm the target service is running and listening on the configured port.", "Compare the host and port in the client and service settings.", "Check service logs and local firewall rules."]),
    ("timeout", r"TimeoutError|ReadTimeout|ConnectTimeout|ETIMEDOUT\b|timed out|\btimeout exceeded\b", "Operation timed out", "error",
     "An operation exceeded its allowed wait time.", "A slow or unavailable dependency, network delay, or an overly short timeout may be involved.",
     ["Identify the operation and dependency that exceeded the timeout.", "Check dependency health and latency around the same time.", "Review timeout and retry settings after checking the underlying service."]),
    ("dns", r"getaddrinfo failed|Name or service not known|ENOTFOUND\b|Temporary failure in name resolution", "Hostname resolution failed", "error",
     "A hostname could not be resolved.", "The hostname, DNS configuration, VPN, or network connection may be responsible.",
     ["Check the spelling of the hostname.", "Test name resolution from the same machine and network.", "Check DNS and VPN settings before changing the application."]),
    ("tls", r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLCertVerificationError", "Certificate verification failed", "error",
     "A TLS certificate could not be verified.", "An expired certificate, incorrect system time, or an incomplete trust chain may explain this.",
     ["Verify the system clock and certificate validity dates.", "Inspect the server certificate chain and any corporate proxy certificate.", "Correct the trust configuration rather than disabling certificate verification."]),
    ("auth", r"\b(?:HTTP(?:/\d(?:\.\d)?)?\s*[:=]?\s*|status(?:_code)?[\s:=]+)(?:401|403)\b|\bUnauthorized\b|\bForbidden\b", "Authentication or authorization rejected", "error",
     "A request was rejected for authentication or authorization.", "Credentials may be invalid, expired, or missing a required permission.",
     ["Confirm that the request includes the intended credential.", "Check its expiry, scopes, and the resource's access policy.", "Keep credentials out of shared reports."]),
    ("rate", r"\b(?:HTTP(?:/\d(?:\.\d)?)?\s*[:=]?\s*|status(?:_code)?[\s:=]+)429\b|\bToo Many Requests\b|\brate limit(?:ed| exceeded)\b", "Request rate limited", "warning",
     "A service reported a request rate limit.", "Request volume may exceed the provider's current allowance.",
     ["Check the service's documented limits and any Retry-After value.", "Reduce concurrency and add bounded exponential backoff.", "Avoid retry loops that amplify the request rate."]),
    ("memory", r"MemoryError|OutOfMemoryError|out of memory|OOMKilled", "Memory allocation failed", "error",
     "A process or runtime reported insufficient memory.", "The workload, a memory leak, or a process/container memory limit may be involved.",
     ["Compare memory usage with process or container limits.", "Identify the workload running immediately before the failure.", "Check whether memory use grows over repeated runs."]),
    ("disk", r"No space left on device|ENOSPC\b|disk (?:is )?full", "Storage exhausted", "error",
     "A write failed because storage capacity was unavailable.", "Disk space, inode exhaustion, or a storage quota may be involved.",
     ["Check free space and quotas on the affected volume.", "Check inode usage where applicable.", "Review retention policies and remove only confirmed disposable files."]),
    ("port", r"Address already in use|EADDRINUSE\b|WinError 10048", "Port already in use", "error",
     "A process could not bind an address already in use.", "Another instance or another service may own the configured port.",
     ["Identify the process listening on the port.", "Check for an already running instance of the application.", "Choose an available port or stop only the confirmed conflicting process."]),
    ("json", r"JSONDecodeError|Unexpected token.*JSON|invalid JSON", "JSON parsing failed", "error",
     "Content could not be parsed as JSON.", "A malformed file, truncated response, or non-JSON error page may be involved.",
     ["Inspect the response status and content type, or the source file.", "Check the reported position for malformed or truncated content.", "Validate the input before parsing it."]),
    ("syntax", r"(?:SyntaxError|IndentationError|TabError):", "Python syntax rejected", "error",
     "The Python parser rejected source code.", "Invalid syntax, inconsistent indentation, or an unsupported Python version may be involved.",
     ["Inspect the reported line and the line immediately before it.", "Check indentation and unmatched brackets or quotes.", "Compare the interpreter version with the project's requirements."]),
    ("database", r"database is locked|SQLITE_BUSY\b|deadlock detected", "Database concurrency conflict", "error",
     "A database reported a lock or deadlock.", "Overlapping transactions or long-held locks may be involved.",
     ["Check concurrent writers and transaction duration.", "Confirm transactions close on success and failure.", "Review database-specific concurrency and retry settings."]),
    ("ssh-auth", r"\bFailed (?:password|publickey) for\b|\bssh.*authentication failure\b", "SSH login rejected", "warning",
     "SSH authentication attempts were rejected. The occurrence count shows how often this symptom appears.",
     "Incorrect credentials, outdated client configuration, or automated login attempts may be involved; intent is not established.",
     ["Review the cited users and source addresses.", "Compare the frequency with expected login activity.", "Check authorized clients and authentication policy without assuming an attack."]),
    ("process-exit", r"\bexited with (?:code|status)\s+(?!0\b)\d+\b|\bCrashLoopBackOff\b", "Process failed or restarted", "error",
     "The log reports a nonzero process exit or an explicit crash-loop status.",
     "The exit status alone does not establish a cause; application errors, resource limits, or service configuration may be involved.",
     ["Inspect the preceding application messages.", "Compare repeated exits with restart policy and deployment times.", "Check the platform's meaning for the reported exit status before assigning a cause."]),
    ("cert-expired", r"\bcertificate (?:has |is )?expired\b|\bexpired certificate\b", "Certificate expired", "error",
     "The log explicitly reports an expired certificate.",
     "Certificate validity, the system clock, or selection of an outdated certificate may explain this symptom.",
     ["Inspect the certificate's validity dates and the system clock.", "Check which certificate the endpoint actually serves.", "Review renewal and deployment records; do not disable TLS verification."]),
    ("traceback", r"Traceback \(most recent call last\):|\bKeyError:|\bunhandled exception\b", "Unhandled exception or traceback", "error",
     "The log contains an unhandled-exception message or a Python traceback marker.",
     "An unexpected input or application state may be involved; the exception and surrounding context need review.",
     ["Read the complete traceback and final exception.", "Check the failing operation's inputs.", "Reproduce with a small sanitized example before changing the code."]),
]
COMPILED = [(key, re.compile(pattern, re.I), title, level, fact, hypothesis, steps)
            for key, pattern, title, level, fact, hypothesis, steps in RULES]


def redactText(text):
    """Preserve line numbers while hiding common secrets. Best effort, not DLP."""
    total = 0
    inKey = False
    output = []
    keyValue = re.compile(r'''(?i)((?:["']?(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|token)["']?)\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;}]+)''')
    patterns = [
        (re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
        (re.compile(r"(?i)(\bBasic\s+)[A-Za-z0-9+/=]+"), r"\1[REDACTED]"),
        (re.compile(r"(https?://)[^\s/@:]+:[^\s/@]+@"), r"\1[REDACTED]@"),
        (re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|AKIA[A-Z0-9]{16})\b"), "[REDACTED]"),
        (re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL REDACTED]"),
    ]
    for line in text.split("\n"):
        if re.search(r"-----BEGIN (?:.* )?PRIVATE KEY-----", line):
            inKey = True
        if inKey:
            end = bool(re.search(r"-----END (?:.* )?PRIVATE KEY-----", line))
            output.append("[PRIVATE KEY REDACTED]")
            total += 1
            if end:
                inKey = False
            continue
        def hideValue(match):
            value = match.group(2)
            quote = value[0] if value[0] in {'"', "'"} else ""
            return match.group(1) + quote + "[REDACTED]" + quote
        line, count = keyValue.subn(hideValue, line)
        total += count
        for pattern, replacement in patterns:
            line, count = pattern.subn(replacement, line)
            total += count
        output.append(line)
    return "\n".join(output), total


def parseLine(line, number):
    message = line
    timestamp = None
    level = None
    if line.lstrip().startswith("{"):
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                value = item.get("message", item.get("msg"))
                if isinstance(value, str):
                    message = value
                stamp = item.get("timestamp", item.get("time", item.get("ts")))
                if isinstance(stamp, str):
                    timestamp = stamp[:80]
                rawLevel = item.get("level", item.get("severity"))
                if isinstance(rawLevel, str) and rawLevel.upper() in {"ERROR", "CRITICAL", "FATAL", "WARN", "WARNING", "INFO", "DEBUG"}:
                    level = rawLevel.lower()
        except (ValueError, TypeError):
            pass
    if timestamp is None:
        match = STAMP.search(line)
        timestamp = match.group(0) if match else None
    if level is None:
        # Severity is metadata at the start of a record, not an arbitrary word
        # in its message (e.g. a healthy "error budget remaining" metric).
        prefix = line
        syslog = SYSLOG.match(line)
        if syslog:
            prefix = syslog.group(1)
        else:
            stamp = STAMP.match(line)
            if stamp:
                prefix = line[stamp.end():]
        match = LEVEL.match(prefix)
        level = match.group(1).lower() if match else "unknown"
    level = {"fatal": "error", "critical": "error", "warn": "warning"}.get(level, level)
    return {"line": number, "timestamp": timestamp, "severity": level, "message": message}


def analyze(text, source="Pasted log", redact=True):
    if not isinstance(text, str):
        raise ValueError("Log content must be text.")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("The log exceeds the 2 MiB limit. Upload a smaller excerpt.")
    text = ANSI.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    text = CONTROLS.sub("", text)
    if not text.strip():
        raise ValueError("Paste a log or choose a nonempty text file.")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES:
        raise ValueError("The log exceeds 20000 lines. Upload a smaller excerpt.")
    return analyzeLines(iter(lines), source, redact)


def analyzeLines(lines, source, redact=True, compact=False):
    """Shared engine; compact reports retain cited excerpts and a bounded preview.

    Iterators must yield normalized physical lines without their line endings.
    Streaming never creates a full-file string or one event per source line.
    """
    events = []
    groups = {}
    notices = []
    textLines = []
    redactions = 0
    privateKey = False
    fingerprint = hashlib.sha256()
    counts = {severity: 0 for severity in ["error", "warning", "info", "debug", "unknown"]}
    firstStamp = lastStamp = None
    number = 0
    hasContent = False
    for number, line in enumerate(lines, 1):
        hasContent |= bool(line.strip())
        if redact:
            # Keep private-key state across physical lines in streaming mode.
            starts = "-----BEGIN " in line and "PRIVATE KEY-----" in line
            ends = "-----END " in line and "PRIVATE KEY-----" in line
            if privateKey or starts:
                privateKey = not ends
                line = "[PRIVATE KEY REDACTED]"
                redactions += 1
            else:
                line, count = redactText(line)
                redactions += count
        if number > 1:
            fingerprint.update(b"\n")
        fingerprint.update(line.encode("utf-8"))
        if not compact:
            textLines.append(line)
        event = parseLine(line, number)
        matched = False
        for key, pattern, title, severity, fact, hypothesis, steps in COMPILED:
            if pattern.search(event["message"]):
                matched = True
                if event["severity"] == "unknown":
                    event["severity"] = severity
                if key not in groups:
                    groups[key] = {"id": key, "title": title, "severity": severity,
                                   "observation": fact, "hypothesis": hypothesis,
                                   "steps": steps, "lines": [], "evidence": [], "occurrences": 0, "basis": "Pattern match"}
                groups[key]["occurrences"] += 1
                if len(groups[key]["lines"]) < 100:
                    groups[key]["lines"].append(number)
                    groups[key]["evidence"].append({"line": number, "text": line[:8192] if compact else line})
        notice = not matched and event["severity"] == "warning" and NOTICE.search(event["message"])
        if notice:
            if len(notices) < 100:
                notices.append({"line": number, "message": event["message"][:8192], "kind": "deprecation"})
        elif not matched and (event["severity"] in {"error", "warning"} or re.search(r"\b\w*(?:Error|Exception):", event["message"])):
            severity = event["severity"] if event["severity"] in {"error", "warning"} else "error"
            event["severity"] = severity
            key = "unclassified-" + severity
            if key not in groups:
                groups[key] = {"id": key, "title": "Other " + severity + " messages", "severity": severity,
                               "observation": "The log contains messages without a matching specialized troubleshooting rule.",
                               "hypothesis": None,
                               "steps": ["Inspect the referenced lines and surrounding context.", "Compare with application documentation and earlier log entries.", "Collect the full traceback or relevant service logs if context is missing."],
                               "lines": [], "evidence": [], "occurrences": 0, "basis": "Severity or exception marker"}
            groups[key]["occurrences"] += 1
            if len(groups[key]["lines"]) < 100:
                groups[key]["lines"].append(number)
                groups[key]["evidence"].append({"line": number, "text": line[:8192] if compact else line})
        counts[event["severity"]] += 1
        if event["timestamp"]:
            firstStamp = firstStamp or event["timestamp"]
            lastStamp = event["timestamp"]
        if not compact or len(events) < 200:
            if compact:
                event["message"] = event["message"][:8192]
            events.append(event)
    if not hasContent:
        raise ValueError("Paste a log or choose a nonempty text file.")
    findings = sorted(groups.values(), key=lambda f: (f["severity"] != "error", -f["occurrences"], f["lines"][0]))
    source = redactText(str(source))[0] if redact else str(source)
    return {
        "version": "1.1.0", "source": source[:200],
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "fingerprint": fingerprint.hexdigest()[:12],
        "redacted": bool(redact), "redactions": redactions,
        "summary": {"lines": number, "findings": len(findings), "counts": counts,
                    "firstTimestamp": firstStamp, "lastTimestamp": lastStamp},
        "findings": findings, "events": events, "text": "\n".join(textLines),
        "notices": notices, "compact": compact,
        "limitations": "Rules identify recognizable symptoms, not proven root causes. No recognized issues does not prove the application is healthy. Events remain in file order; timestamps are not normalized across time zones.",
    }


def markdownReport(report, completed=None, ai=None):
    completed = completed or []
    # Logs are untrusted. Make fences impossible to terminate with log content.
    def safe(value):
        return str(value).replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    summary = report["summary"]
    output = ["# Log Detective investigation", "", f"Source: {safe(report['source'])}",
              f"Generated: {report['created']}", f"Content fingerprint: {report['fingerprint']}",
              f"Lines: {summary['lines']} | Errors: {summary['counts']['error']} | Warnings: {summary['counts']['warning']}",
              f"Redaction: {'enabled' if report['redacted'] else 'disabled'} | Replacements: {report['redactions']}", ""]
    if not report["findings"]:
        output += ["No recognized issues found. This does not establish application health.", ""]
    if report.get("inputEncoding"):
        output += ["Input encoding: " + report["inputEncoding"], ""]
    output += ["Input warning: " + safe(item) for item in report.get("inputWarnings", [])]
    for finding in report["findings"]:
        output += [f"## {finding['title']}", f"Severity: {finding['severity']} | Occurrences: {finding['occurrences']}",
                   "", "Observed: " + finding["observation"]]
        if finding["hypothesis"]:
            output.append("Possible explanation: " + finding["hypothesis"])
        else:
            output.append("The cited text does not establish a specific cause.")
        output += ["", "Evidence:", "```text"]
        for entry in finding["evidence"][:10]:
            output.append(f"L{entry['line']}: {safe(entry['text'])}")
        output += ["```", "", "Checks:"]
        for index, step in enumerate(finding["steps"]):
            marker = "x" if f"{finding['id']}:{index}" in completed else " "
            output.append(f"- [{marker}] {step}")
        output.append("")
    if report.get("notices"):
        output += ["## Notices (not incident findings)", ""]
        output += [f"- L{item['line']}: {safe(item['message'])}" for item in report["notices"]]
        output.append("")
    if report.get("compact"):
        output += ["Large-file report: all lines were scanned. The JSON event preview contains at most 200 records; source text is omitted. Each finding retains at most 100 cited excerpts of up to 8192 characters.", ""]
    if ai:
        output += ["## AI suggestions (unverified)", "", safe(ai["summary"]), ""]
        for item in ai["hypotheses"]:
            output.append(f"- {safe(item['explanation'])} (evidence: {', '.join('L' + str(n) for n in item['lines'])})")
        output += ["", "Suggested checks:"] + ["- " + safe(step) for step in ai["checks"]] + [""]
    output += ["## Limits", report["limitations"], "Secret redaction is best effort. Review the report before sharing.", ""]
    return "\n".join(output)
