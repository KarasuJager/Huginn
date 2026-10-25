# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Manuel Miguel Fernandez-Gallego Olivares (AEGIR Security)
# Huginn — LLM red-team payload harness. Dual-licensed: AGPL-3.0 or commercial (see COMMERCIAL.md).
"""
Sender: fire one payload at a target, log everything, run detectors.

Design goals (the "Burp for chatbots" feel):
- Every request/response pair is appended to history.jsonl — one JSON object per
  line — so you can review exactly what was sent and what came back, forever.
- Rate limiting is enforced between sends (per the target profile).
- Scope is enforced before every send.
- A unique canary is minted per send so {{CANARY}} payloads are detectable
  without ambiguity.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

from .target import Target, ScopeViolation
from .detectors import analyze, is_interesting, Hit
from .library import Payload

CANARY_TOKEN = "{{CANARY}}"


def mint_canary() -> str:
    return "HGN-" + secrets.token_hex(4).upper()


@dataclass
class SendResult:
    ts: str
    phase: str
    payload_id: str
    canary: str | None
    url: str
    status_code: int | None
    latency_ms: int | None
    sent_text: str
    reply: str
    hits: list = field(default_factory=list)
    interesting: bool = False
    error: str | None = None

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["hits"] = [h.to_dict() if isinstance(h, Hit) else h for h in self.hits]
        return d


class Sender:
    def __init__(self, target: Target, history_path: str = "history.jsonl",
                 session: requests.Session | None = None, log: bool = True):
        self.target = target
        self.history_path = history_path
        self.session = session or requests.Session()
        self.log = log
        self._last_send = 0.0

    def _respect_rate_limit(self) -> None:
        wait = self.target.rate_limit_seconds - (time.time() - self._last_send)
        if wait > 0:
            time.sleep(wait)

    def _append_history(self, result: SendResult) -> None:
        if not self.log:
            return
        with open(self.history_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")

    def send_raw(self, text: str, phase: str = "manual",
                 payload_id: str = "manual", canary: str | None = None,
                 detect: list | None = None) -> SendResult:
        """Send one arbitrary message. The primitive behind every higher tool."""
        self.target.check_scope()  # raises ScopeViolation if out of scope
        self._respect_rate_limit()

        headers = self.target.build_headers()
        body = self.target.build_body(text)
        ts = datetime.now(timezone.utc).isoformat()
        t0 = time.time()
        result = SendResult(
            ts=ts, phase=phase, payload_id=payload_id, canary=canary,
            url=self.target.url, status_code=None, latency_ms=None,
            sent_text=text, reply="",
        )
        try:
            if isinstance(body, (dict, list)):
                resp = self.session.request(
                    self.target.method, self.target.url, headers=headers,
                    json=body, timeout=self.target.timeout)
            else:
                resp = self.session.request(
                    self.target.method, self.target.url, headers=headers,
                    data=str(body), timeout=self.target.timeout)
            self._last_send = time.time()
            result.status_code = resp.status_code
            result.latency_ms = int((time.time() - t0) * 1000)
            raw_text = resp.text
            try:
                resp_json = resp.json()
            except ValueError:
                resp_json = None
            result.reply = self.target.extract_reply(resp_json, raw_text)
        except ScopeViolation:
            raise
        except Exception as exc:  # network, timeout, etc.
            self._last_send = time.time()
            result.error = f"{type(exc).__name__}: {exc}"
            self._append_history(result)
            return result

        hits = analyze(result.reply, text, canary, extra_patterns=detect)
        result.hits = hits
        result.interesting = is_interesting(hits)
        self._append_history(result)
        return result

    def send_payload(self, payload: Payload) -> SendResult:
        """Send a library payload, minting a canary if it needs one."""
        canary = None
        text = payload.text
        if payload.needs_canary or CANARY_TOKEN in text:
            canary = mint_canary()
            text = text.replace(CANARY_TOKEN, canary)
        return self.send_raw(
            text, phase=payload.phase, payload_id=payload.id,
            canary=canary, detect=payload.detect)
