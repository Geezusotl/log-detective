"""Browser app and command-line report entry points."""

import argparse
import json
import sys
from pathlib import Path

from .analyzer import markdownReport
from .files import analyzeFile
from .server import serve


def main():
    parser = argparse.ArgumentParser(description="Investigate logs locally with evidence-linked findings.")
    commands = parser.add_subparsers(dest="command")
    web = commands.add_parser("serve", help="Start the local browser app (default).")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically.")
    inspect = commands.add_parser("analyze", help="Generate a Markdown or JSON report from a text log.")
    inspect.add_argument("file", type=Path)
    inspect.add_argument("--format", choices=["markdown", "json"], default="markdown")
    inspect.add_argument("--output", type=Path, help="Write a new report file; existing files are not overwritten.")
    inspect.add_argument("--no-redact", action="store_true", help="Keep secrets in the local report.")
    inspect.add_argument("--encoding", choices=["auto", "utf-8", "utf-16", "latin-1"], default="auto",
                         help="Text encoding; auto accepts UTF-8, BOM-marked UTF-16, or Latin-1 with a warning.")
    args = parser.parse_args()
    try:
        if args.command == "analyze":
            report = analyzeFile(args.file, not args.no_redact, args.encoding)
            output = json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else markdownReport(report)
            if args.output:
                with args.output.open("x", encoding="utf-8") as handle:
                    handle.write(output)
                print(f"Report written to {args.output}")
            else:
                print(output)
        else:
            port = getattr(args, "port", 8765)
            if not 0 <= port <= 65535:
                raise ValueError("Port must be between 0 and 65535.")
            serve(port, not getattr(args, "no_browser", False))
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"Log Detective: {exc}", file=sys.stderr)
        if args.command == "analyze" and args.format == "json":
            # An error object remains an error, not a successful clean analysis.
            print(json.dumps({"status": "error", "error": str(exc), "findings": [], "text": ""}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
