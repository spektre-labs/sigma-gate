#!/usr/bin/env python3
"""
σ-gate MCP server — packaged edition.

Same zero-dependency stdlib stdio JSON-RPC server as the repo-root mcp_server.py,
re-exported from inside the installed package so users get it via the console
script 'guard-mcp' after 'pip install guard-trustgate'.

Run:
  guard-mcp          # console-script (after install)
  python -m guard.mcp

Add to Claude Code (installed):
  claude mcp add guard -- guard-mcp
Add to Claude Desktop (claude_desktop_config.json):
  {"mcpServers": {"guard": {"command": "guard-mcp"}}}

Protocol: 2024-11-05
Tools:
  guard(text, context?, block_at?)  -> {safe_to_ship, severity, block_reasons[], dimensions}
  guard_selftest()                  -> proves every threat class fires + clean passes
"""
from __future__ import annotations
import sys
import json

from .guard import guard, selftest, BLOCK_AT

PROTOCOL = "2024-11-05"
TOOLS = [
    {
        "name": "guard",
        "description": (
            "ONE deterministic pre-ship trust gate for AI/agent output. "
            "Runs leaked-secret detection (20+ providers), prompt-injection / jailbreak "
            "detection, and PII / compliance detection together -> returns safe_to_ship "
            "(bool) + block_reasons. No model, no API key, no token cost; same input gives "
            "the same verdict every time. Use before sending model output to a user, "
            "committing generated code, or forwarding untrusted text into another prompt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "the text/output to gate before shipping",
                },
                "context": {
                    "type": "string",
                    "description": "optional ground-truth context (reserved)",
                },
                "block_at": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "severity at which to mark unsafe (default medium)",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "guard_selftest",
        "description": (
            "Prove the gate works: runs a known secret, injection, PII, combined, "
            "and clean input and returns which classes fired. No arguments."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _call_tool(name: str, args: dict):
    if name == "guard":
        text = args.get("text", "")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text is required (non-empty string)")
        return guard(
            text,
            args.get("context", "") or "",
            block_at=args.get("block_at") or BLOCK_AT,
        )
    if name == "guard_selftest":
        return selftest()
    raise ValueError(f"unknown tool: {name}")


def _result(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _error(id_, code, msg):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}}


def handle(req: dict):
    m = req.get("method")
    id_ = req.get("id")
    if m == "initialize":
        return _result(
            id_,
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sigma-gate", "version": "1.0.0"},
            },
        )
    if m == "notifications/initialized":
        return None
    if m == "tools/list":
        return _result(id_, {"tools": TOOLS})
    if m == "tools/call":
        p = req.get("params", {})
        try:
            out = _call_tool(p.get("name", ""), p.get("arguments", {}) or {})
            return _result(
                id_,
                {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}]},
            )
        except Exception as e:
            return _error(id_, -32603, str(e)[:200])
    if m == "ping":
        return _result(id_, {})
    return _error(id_, -32601, f"method not found: {m}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
