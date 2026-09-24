
from __future__ import annotations

import csv
import io
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .core import DEFAULTS, analyze, validate_thresholds
from .sources import ldap_inventory, snapshot

# Small standard-library HTTP API

ROOT = Path(__file__).resolve().parent.parent
LOCK = threading.RLock()
SCAN_LOCK = threading.Lock()
STATE = {"thresholds": DEFAULTS.copy(), "report": None, "history": []}
AUDIT = logging.getLogger("radar.audit")


def configure_audit():
    AUDIT.setLevel(logging.INFO)
    if not AUDIT.handlers:
        handler = logging.FileHandler(os.environ.get("RADAR_AUDIT_FILE", str(ROOT / "audit.log")), encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        AUDIT.addHandler(handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "IdentityRadar/0.1"

    def log_message(self, format, *args):
        # Do not write URLs, authorization headers or payloads to the access log
        pass

    def reply(self, status, body, content_type="application/json; charset=utf-8", filename=None):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if not isinstance(body, bytes) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 65536:
            raise ValueError("Размер запроса превышает 64 KiB")
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self.reply(200, (ROOT / "dashboard.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/health":
            self.reply(200, {"status": "ok"})
            return
        with LOCK:
            report = STATE["report"]
            if path == "/api/v1/config":
                self.reply(200, {"thresholds": STATE["thresholds"], "sources": ["ldap", "demo"], "default_source": "ldap"})
            elif path == "/api/v1/report":
                self.reply(200 if report else 404, report or {"error": "Запусти анализ"})
            elif path == "/api/v1/summary":
                self.reply(200 if report else 404, {k: report[k] for k in ("generated_at", "source", "security_score", "counts", "inventory", "categories", "coverage")} if report else {"error": "Запусти анализ"})
            elif path == "/api/v1/findings":
                if not report:
                    self.reply(404, {"error": "Запусти анализ"})
                    return
                query = parse_qs(urlsplit(self.path).query)
                items = report["findings"]
                if query.get("severity"):
                    items = [i for i in items if i["severity"].casefold() == query["severity"][0].casefold()]
                self.reply(200, {"total": len(items), "items": items})
            elif path == "/api/v1/history":
                self.reply(200, {"items": STATE["history"]})
            elif path == "/api/v1/export.csv":
                if not report:
                    self.reply(404, {"error": "Запусти анализ"})
                    return
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(["object_dn", "object_name", "rule", "severity", "score", "description", "evidence", "recommendation"])
                for f in report["findings"]:
                    # Guard CSV formula interpretation in spreadsheet applications.
                    cells = [f[k] for k in ("object_dn", "object_name", "rule", "severity", "score", "description")]
                    cells += [json.dumps(f["evidence"], ensure_ascii=False), f["recommendation"]]
                    writer.writerow(["'" + v if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else v for v in cells])
                self.reply(200, b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8", "identity-risks.csv")
            else:
                self.reply(404, {"error": "Неизвестный endpoint"})
        AUDIT.info("read path=%s", path)

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            data = self.payload()
            if not isinstance(data, dict):
                raise ValueError("Ожидается объект JSON")
            if path == "/api/v1/config":
                updated = validate_thresholds(data.get("thresholds", {}))
                with LOCK:
                    STATE["thresholds"] = updated
                AUDIT.info("config_updated")
                self.reply(200, {"thresholds": updated})
            elif path == "/api/v1/scans":
                if set(data) - {"source"}:
                    raise ValueError("Запрос запуска принимает только source; учётные записи читаются сервером из AD DS")
                source = data.get("source", "ldap")
                if source not in ("demo", "ldap"):
                    raise ValueError("Допустимые источники: demo, ldap")
                if not SCAN_LOCK.acquire(blocking=False):
                    self.reply(409, {"error": "Анализ уже выполняется"})
                    return
                try:
                    inventory = snapshot(ROOT / "examples" / "demo.json") if source == "demo" else ldap_inventory()
                    with LOCK:
                        report = analyze(inventory, STATE["thresholds"])
                        STATE["report"] = report
                        STATE["history"].append({"generated_at": report["generated_at"], "security_score": report["security_score"], "counts": report["counts"]})
                        STATE["history"] = STATE["history"][-100:]
                finally:
                    SCAN_LOCK.release()
                AUDIT.info("scan_complete source=%s accounts=%d findings=%d", source, len(report["accounts"]), len(report["findings"]))
                self.reply(200, {k: report[k] for k in ("generated_at", "source", "security_score", "counts", "inventory")})
            else:
                self.reply(404, {"error": "Неизвестный endpoint"})
        except (ValueError, json.JSONDecodeError) as exc:
            AUDIT.warning("invalid_request path=%s", path)
            self.reply(400, {"error": str(exc)})
        except Exception as exc:
            AUDIT.error("scan_failed path=%s error_type=%s", path, type(exc).__name__)
            self.reply(503, {"error": "Источник недоступен; подробности в локальном журнале"})


def serve():
    configure_audit()
    host = "127.0.0.1"
    port = int(os.environ.get("RADAR_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    AUDIT.info("service_started host=%s port=%d", host, port)
    print(f"Identity Risk Analyzer: http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        AUDIT.info("service_stopped")
