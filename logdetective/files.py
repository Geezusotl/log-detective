"""Decode text files and stream large CLI reports with bounded retention."""

import codecs
from pathlib import Path

from .analyzer import ANSI, CONTROLS, MAX_BYTES, MAX_LINES, analyze, analyzeLines

MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 8 * 1024 * 1024


def fileEncoding(path, requested="auto"):
    with path.open("rb") as handle:
        sample = handle.read(65536)
    if requested == "auto":
        if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
            return "utf-16"
        requested = "utf-8-sig"
    # Reject binary control-heavy data before attempting a legacy-text fallback.
    if not requested.startswith("utf-16"):
        controls = sum(byte < 32 and byte not in (9, 10, 13) for byte in sample)
        if sample and controls / len(sample) > 0.03:
            raise ValueError("This looks like a binary file. Supply a text log instead.")
    if requested == "utf-8-sig":
        decoder = codecs.getincrementaldecoder("utf-8-sig")("strict")
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    decoder.decode(chunk)
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            return "latin-1"
    return requested


def normalizedLines(handle):
    while True:
        line = handle.readline(MAX_LINE_BYTES + 1)
        if not line:
            break
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ValueError("A single line exceeds the 8 MiB streaming limit.")
        yield CONTROLS.sub("", ANSI.sub("", line.rstrip("\n")))


def analyzeFile(path, redact=True, encoding="auto"):
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError("The CLI file limit is 512 MiB. Supply a smaller log.")
    selected = fileEncoding(path, encoding)
    # Universal newline handling normalizes CRLF/CR to LF, including UTF-16.
    with path.open("r", encoding=selected, newline=None) as handle:
        if size <= MAX_BYTES:
            text = handle.read()
            if len(text.encode("utf-8")) <= MAX_BYTES and text.count("\n") < MAX_LINES:
                report = analyze(text, path.name, redact)
            else:
                handle.seek(0)
                report = analyzeLines(normalizedLines(handle), path.name, redact, compact=True)
        else:
            report = analyzeLines(normalizedLines(handle), path.name, redact, compact=True)
    report["inputEncoding"] = selected
    report["inputWarnings"] = (["UTF-8 decoding failed; interpreted as Latin-1. Verify accented text or select --encoding explicitly."]
                               if selected == "latin-1" and encoding == "auto" else [])
    return report
