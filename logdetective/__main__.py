"""Browser app and command-line report entry points."""

import argparse
import json
import sys
from pathlib import Path

from .analyzer import MAX_BYTES, analyze, markdownReport
from .server import serve


def main():
    parser = argparse.ArgumentParser(description="Investigate logs locally with evidence-linked findings.")
    commands = parser.add_subparsers(dest="command")
    web = commands.add_parser("serve", help="Start the local browser app (default).")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--no-browser", action="store_true", help="Do not open a browser automatically.")
    inspect = commands.add_parser("analyze", help="Generate a Markdown or JSON report from a UTF-8 log.")
    inspect.add_argument("file", type=Path)
    inspect.add_argument("--format", choices=["markdown", "json"], default="markdown")
    inspect.add_argument("--output", type=Path, help="Write a new report file; existing files are not overwritten.")
    inspect.add_argument("--no-redact", action="store_true", help="Keep secrets in the local report.")
    args = parser.parse_args()
    try:
        if args.command == "analyze":
            if args.file.stat().st_size > MAX_BYTES:
                raise ValueError("The log exceeds the 2 MiB limit.")
            report = analyze(args.file.read_text(encoding="utf-8-sig"), args.file.name, not args.no_redact)
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
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
