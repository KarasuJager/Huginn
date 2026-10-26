#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Manuel Miguel Fernandez-Gallego Olivares (AEGIR Security)
# Huginn — LLM red-team payload harness. Dual-licensed: AGPL-3.0 or commercial (see COMMERCIAL.md).
"""
Huginn MCP server (stdio).

Exposes the harness as Model Context Protocol tools so an MCP client (e.g. the
Claude desktop app) can drive it conversationally: send one probe, read the
reply, decide the next move — or fire a whole phase and review the hits. Every
send is still logged to history.jsonl, exactly like the CLI.

Config block (claude_desktop_config.json):

    "huginn": {
      "command": "python",
      "args": ["C:\\\\path\\\\to\\\\huginn\\\\server.py"]
    }

Tools:
    chat_send(target, message, conversation_id, reset)
                                          -> send one turn in a multi-turn thread, return reply + hits
    reset_conversation(conversation_id)   -> drop a thread's turns + session
    run_phase(target, phase, max)         -> fire a phase battery, return triage
    review(history, only_interesting)     -> read a history file back
    list_payloads(phase)                  -> list available probes
    add_payload(phase, text, title, ...)  -> add a probe to the library

Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout. Diagnostics go to
stderr so they never corrupt the protocol channel.
"""

from __future__ import annotations

import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.target import Target, ScopeViolation
from core.sender import Sender, mint_canary, CANARY_TOKEN
from core import library

SERVER_NAME = "huginn"
SERVER_VERSION = "0.1.0"
DEFAULT_HISTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.jsonl")

# Live multi-turn state, keyed by conversation_id. Each conversation keeps its own
# running message history and its own HTTP session (so cookies / auth persist across
# turns), which is what makes interactive, multi-step probing actually multi-turn.
_CONVOS: dict[str, list[dict]] = {}
_SESSIONS: dict[str, requests.Session] = {}


def log(*a):
    print("[huginn]", *a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Tool definitions
# --------------------------------------------------------------------------- #

TOOLS = [
    {
        "name": "chat_send",
        "description": "Send ONE message to the target chatbot within a running multi-turn conversation and return its raw reply plus any detector hits. Prior turns in the same conversation_id are resent as context, so multi-step attacks (build trust, then escalate) work. The primitive for live, interactive probing. Logs to history.jsonl.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Path to the target profile JSON."},
                "message": {"type": "string", "description": "The exact message to send. Use the literal {{CANARY}} to have a unique token minted and detected automatically."},
                "conversation_id": {"type": "string", "description": "Thread to append this turn to; prior turns are resent as context. Defaults to 'default'.", "default": "default"},
                "reset": {"type": "boolean", "description": "Start this conversation fresh (drop prior turns and session) before sending.", "default": False},
            },
            "required": ["target", "message"],
        },
    },
    {
        "name": "reset_conversation",
        "description": "Forget a live conversation's accumulated turns and HTTP session so the next chat_send starts clean.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "conversation_id": {"type": "string", "default": "default"},
            },
        },
    },
    {
        "name": "run_phase",
        "description": "Fire a whole phase of library probes at the target and return a triage (which probes looked interesting and why). Phases: all, direct_injection, system_prompt_leak, indirect_injection, output_handling, cross_tenant.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Path to the target profile JSON."},
                "phase": {"type": "string", "default": "all"},
                "max": {"type": "integer", "description": "Max payloads for this phase (0 = all).", "default": 0},
            },
            "required": ["target"],
        },
    },
    {
        "name": "review",
        "description": "Read a history.jsonl back and return the logged request/response records, interesting ones first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "history": {"type": "string", "description": "Path to history.jsonl (defaults to the server's own)."},
                "only_interesting": {"type": "boolean", "default": True},
            },
        },
    },
    {
        "name": "list_payloads",
        "description": "List the probes available in the library, optionally for one phase.",
        "inputSchema": {
            "type": "object",
            "properties": {"phase": {"type": "string", "description": "Phase to list, or omit for all."}},
        },
    },
    {
        "name": "add_payload",
        "description": "Add a new probe to a phase's library file (persisted). Use {{CANARY}} in the text for auto-detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "phase": {"type": "string"},
                "text": {"type": "string"},
                "title": {"type": "string", "default": ""},
                "detect": {"type": "array", "description": "Optional extra regex patterns.", "default": []},
            },
            "required": ["phase", "text"],
        },
    },
]


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #

def _sender(target_path: str, history: str | None = None) -> Sender:
    target = Target.load(target_path)
    return Sender(target, history_path=history or DEFAULT_HISTORY)


def t_chat_send(args: dict) -> dict:
    cid = args.get("conversation_id") or "default"
    if args.get("reset"):
        _CONVOS.pop(cid, None)
        _SESSIONS.pop(cid, None)

    target = Target.load(args["target"])
    session = _SESSIONS.setdefault(cid, requests.Session())
    sender = Sender(target, history_path=DEFAULT_HISTORY, session=session)

    message = args["message"]
    canary = None
    if CANARY_TOKEN in message:
        canary = mint_canary()
        message = message.replace(CANARY_TOKEN, canary)

    history = _CONVOS.setdefault(cid, [])
    history.append({"role": "user", "content": message})
    res = sender.send_messages(history, phase="manual", payload_id="manual", canary=canary)
    history.append({"role": "assistant", "content": res.reply})

    out = res.to_dict()
    out["conversation_id"] = cid
    out["turn"] = sum(1 for m in history if m["role"] == "user")
    return out


def t_reset_conversation(args: dict) -> dict:
    cid = args.get("conversation_id") or "default"
    existed = cid in _CONVOS or cid in _SESSIONS
    _CONVOS.pop(cid, None)
    _SESSIONS.pop(cid, None)
    return {"conversation_id": cid, "reset": True, "existed": existed}


def t_run_phase(args: dict) -> dict:
    target = Target.load(args["target"])
    target.check_scope()
    sender = Sender(target, history_path=DEFAULT_HISTORY)
    payloads = library.load(args.get("phase", "all"))
    cap = int(args.get("max", 0) or 0)
    if cap:
        seen, capped = {}, []
        for p in payloads:
            seen[p.phase] = seen.get(p.phase, 0) + 1
            if seen[p.phase] <= cap:
                capped.append(p)
        payloads = capped
    results, interesting = [], []
    for p in payloads:
        r = sender.send_payload(p)
        row = {
            "payload_id": r.payload_id, "phase": r.phase,
            "status_code": r.status_code, "interesting": r.interesting,
            "error": r.error,
            "hits": [h.to_dict() for h in r.hits],
            "reply_preview": (r.reply or "")[:200],
        }
        results.append(row)
        if r.interesting:
            interesting.append(row)
    return {
        "target": target.name, "phase": args.get("phase", "all"),
        "sent": len(results), "interesting_count": len(interesting),
        "interesting": interesting, "all": results,
        "history": DEFAULT_HISTORY,
    }


def t_review(args: dict) -> dict:
    path = args.get("history") or DEFAULT_HISTORY
    only = args.get("only_interesting", True)
    rows = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rows.append(json.loads(line))
    hot = [r for r in rows if r.get("interesting")]
    chosen = hot if only else sorted(rows, key=lambda r: not r.get("interesting"))
    return {"history": path, "total": len(rows), "interesting": len(hot),
            "records": chosen[:100]}


def t_list_payloads(args: dict) -> dict:
    phase = args.get("phase")
    payloads = library.load(phase if phase else "all")
    return {"count": len(payloads), "payloads": [p.to_dict() for p in payloads]}


def t_add_payload(args: dict) -> dict:
    p = library.add_payload(
        args["phase"], args["text"], title=args.get("title", ""),
        detect=args.get("detect", []))
    return {"added": p.to_dict()}


DISPATCH = {
    "chat_send": t_chat_send,
    "reset_conversation": t_reset_conversation,
    "run_phase": t_run_phase,
    "review": t_review,
    "list_payloads": t_list_payloads,
    "add_payload": t_add_payload,
}


# --------------------------------------------------------------------------- #
# JSON-RPC plumbing
# --------------------------------------------------------------------------- #

def send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle(msg: dict):
    method = msg.get("method", "")
    mid = msg.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name", "")
        arguments = params.get("arguments", {}) or {}
        fn = DISPATCH.get(name)
        if not fn:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
        try:
            result = fn(arguments)
            text = json.dumps(result, ensure_ascii=False, indent=2)
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": text}]}}
        except ScopeViolation as exc:
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"SCOPE REFUSED: {exc}"}],
                "isError": True}}
        except Exception as exc:  # noqa
            log("tool error:", type(exc).__name__, exc)
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"ERROR {type(exc).__name__}: {exc}"}],
                "isError": True}}

    if method in ("notifications/initialized", "notifications/cancelled"):
        return None  # notifications get no response

    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return None


def main() -> None:
    log(f"{SERVER_NAME} {SERVER_VERSION} ready (stdio)")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            send(resp)


if __name__ == "__main__":
    main()
