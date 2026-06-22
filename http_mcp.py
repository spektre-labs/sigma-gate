#!/usr/bin/env python3
"""
σ-gate HTTP MCP server — the guard as a REMOTE MCP server (streamable-HTTP transport) for hosting on
Cloud Run / any container host. Zero dependencies: pure-stdlib http.server + JSON-RPC. Scales to zero.

Endpoints:
  POST /mcp   -> MCP JSON-RPC (initialize, tools/list, tools/call: guard, guard_selftest)
  GET  /health -> {"ok": true}
  GET  /       -> a one-line banner

Run:  PORT=8080 python3 http_mcp.py
"""
from __future__ import annotations
import os, sys, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard import guard, selftest  # noqa: E402
from guard.guard import BLOCK_AT  # noqa: E402

PROTOCOL = "2024-11-05"
TOOLS = [
    {"name": "guard",
     "description": "ONE deterministic pre-ship trust gate for AI/agent output. Leaked-secret (20+ "
                    "providers), prompt-injection/jailbreak, and PII detection in one call -> safe_to_ship "
                    "+ block_reasons. No model, no API key, same verdict every time.",
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string", "description": "text to gate"},
                                    "context": {"type": "string"},
                                    "block_at": {"type": "string", "enum": ["low", "medium", "high", "critical"]}},
                     "required": ["text"]}},
    {"name": "guard_selftest",
     "description": "Prove every threat class fires + a clean input passes. No arguments.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _call_tool(name, args):
    if name == "guard":
        text = args.get("text", "")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text is required (non-empty string)")
        return guard(text, args.get("context", "") or "", block_at=args.get("block_at") or BLOCK_AT)
    if name == "guard_selftest":
        return selftest()
    raise ValueError(f"unknown tool: {name}")


def handle(req):
    m = req.get("method")
    id_ = req.get("id")
    if m == "initialize":
        return {"jsonrpc": "2.0", "id": id_,
                "result": {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                           "serverInfo": {"name": "sigma-gate", "version": "1.0.0"}}}
    if m == "notifications/initialized":
        return None
    if m == "tools/list":
        return {"jsonrpc": "2.0", "id": id_, "result": {"tools": TOOLS}}
    if m == "tools/call":
        p = req.get("params", {})
        try:
            out = _call_tool(p.get("name", ""), p.get("arguments", {}) or {})
            return {"jsonrpc": "2.0", "id": id_,
                    "result": {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}]}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": id_, "error": {"code": -32603, "message": str(e)[:200]}}
    if m == "ping":
        return {"jsonrpc": "2.0", "id": id_, "result": {}}
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": -32601, "message": f"method not found: {m}"}}


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj, ctype="application/json"):
        body = (json.dumps(obj) if not isinstance(obj, str) else obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(200, "sigma-gate MCP server - POST /mcp\n", "text/plain")

    def do_POST(self):
        if self.path.rstrip("/") not in ("/mcp", ""):
            self._send(404, {"error": "not found"}); return
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}}); return
        resp = handle(req)
        if resp is None:
            self._send(202, {})
        else:
            self._send(200, resp)

    def log_message(self, *a):
        pass


def main():
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    print(f"sigma-gate MCP on :{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
