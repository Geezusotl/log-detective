"""Loopback-only development application; not a public hosting server."""

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from . import ai
from .analyzer import MAX_BYTES, analyze, markdownReport

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT.parent / "samples"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Avoid printing paths, logs, secrets, or request bodies.
        pass

    def validHost(self):
        port = self.server.server_address[1]
        return self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def send(self, status, body, mime="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.validHost():
            return self.send(403, {"error": "Invalid local host."})
        if self.path in STATIC:
            filename, mime = STATIC[self.path]
            return self.send(200, (ROOT / "web" / filename).read_bytes(), mime)
        if self.path == "/api/config":
            return self.send(200, {"token": self.server.token, "version": __version__, "maxBytes": MAX_BYTES})
        if self.path == "/api/samples":
            samples = [{"name": path.stem.replace("-", " ").title(), "filename": path.name,
                        "text": path.read_text(encoding="utf-8")} for path in sorted(SAMPLES.glob("*.log"))]
            return self.send(200, {"samples": samples})
        return self.send(404, {"error": "Not found."})

    def do_POST(self):
        if not self.validHost():
            return self.send(403, {"error": "Invalid local host."})
        port = self.server.server_address[1]
        origin = self.headers.get("Origin")
        if origin and origin not in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}:
            return self.send(403, {"error": "Cross-origin requests are not allowed."})
        if not secrets.compare_digest(self.headers.get("X-LogDetective-Token", ""), self.server.token):
            return self.send(403, {"error": "Reload the app to start a valid local session."})
        if self.headers.get_content_type() != "application/json":
            return self.send(415, {"error": "Send a JSON request."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_BYTES * 6 + 4096:
                return self.send(413, {"error": "Request is empty or too large."})
            payload = json.loads(self.rfile.read(size))
            if not isinstance(payload, dict):
                raise ValueError("Request must be an object.")
            if self.path == "/api/models":
                return self.send(200, {"models": ai.listModels()})
            text = payload.get("text")
            redact = payload.get("redact", True)
            if type(redact) is not bool:
                raise ValueError("Redaction must be enabled or disabled.")
            source = payload.get("source", "Pasted log")
            if not isinstance(source, str):
                raise ValueError("Source must be text.")
            # Filenames can also contain sensitive information.
            if redact:
                source = aiSource(source)
            report = analyze(text, source, redact)
            if self.path == "/api/analyze":
                return self.send(200, report)
            if self.path == "/api/ai":
                return self.send(200, {"answer": ai.explain(report, payload.get("model"))})
            if self.path == "/api/report":
                completed = payload.get("completed", [])
                if not isinstance(completed, list) or len(completed) > 1000 or any(not isinstance(x, str) for x in completed):
                    raise ValueError("Invalid checklist.")
                answer = payload.get("ai")
                if answer is not None:
                    answer = ai.validateAnswer(answer, set(range(1, report["summary"]["lines"] + 1)))
                return self.send(200, {"markdown": markdownReport(report, completed, answer)})
            return self.send(404, {"error": "Not found."})
        except (ValueError, UnicodeError) as exc:
            return self.send(400, {"error": str(exc)[:400]})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.send(500, {"error": "The request could not be completed. Check the input and try again."})


def aiSource(source):
    from .analyzer import redactText
    return redactText(source)[0]


def makeServer(port=8765):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.token = secrets.token_urlsafe(32)
    server.daemon_threads = True
    return server


def serve(port=8765, openBrowser=True):
    try:
        server = makeServer(port)
    except OSError as exc:
        raise ValueError(f"Could not start on port {port}. Another instance may be running. Try --port 8766.") from exc
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Log Detective {__version__} is running at {url}\nPress Ctrl+C to stop. Logs are not saved by the server.")
    if openBrowser:
        timer = threading.Timer(0.5, webbrowser.open, args=(url,))
        timer.daemon = True
        timer.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
