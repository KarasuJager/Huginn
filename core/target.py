# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Manuel Miguel Fernandez-Gallego Olivares (AEGIR Security)
# Huginn — LLM red-team payload harness. Dual-licensed: AGPL-3.0 or commercial (see COMMERCIAL.md).
"""
Target profile loading and request shaping.

A *target profile* is a small JSON file that describes how to talk to a chatbot
endpoint, so the same engine works against any bot by swapping one file:

    {
      "name": "example-bot",
      "url": "https://api.example.com/chat",
      "method": "POST",
      "headers": {
        "Content-Type": "application/json",
        "Authorization": "Bearer ${BOT_TOKEN}",
        "X-Bug-Bounty": "Manuel_Miguel"
      },
      "body_template": {"messages": [{"role": "user", "content": "{{PAYLOAD}}"}]},
      "response_path": "choices.0.message.content",
      "rate_limit_seconds": 2.0,
      "scope_host": "api.example.com"
    }

- `{{PAYLOAD}}` is replaced (anywhere in the body) with the test string.
- `${ENV_VAR}` in any header/value is expanded from the environment, so tokens
  never get hard-coded into the repo.
- `response_path` is a dotted path (supports list indices) used to pull the
  bot's reply out of a JSON response; if it does not resolve, the raw body text
  is used instead.
- `scope_host` is enforced before every request: if the URL host does not match,
  the request is refused. This is a safety rail, not decoration.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
PAYLOAD_TOKEN = "{{PAYLOAD}}"


def _expand_env(value: Any) -> Any:
    """Recursively expand ${VAR} placeholders from the environment."""
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _inject_payload(obj: Any, payload: str) -> Any:
    """Replace every {{PAYLOAD}} occurrence inside a JSON-ish structure."""
    if isinstance(obj, str):
        return obj.replace(PAYLOAD_TOKEN, payload)
    if isinstance(obj, dict):
        return {k: _inject_payload(v, payload) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_inject_payload(v, payload) for v in obj]
    return obj


@dataclass
class Target:
    name: str
    url: str
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    body_template: Any = None
    response_path: str | None = None
    rate_limit_seconds: float = 2.0
    scope_host: str | None = None
    timeout: float = 30.0

    @classmethod
    def load(cls, path: str) -> "Target":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        scope_host = raw.get("scope_host")
        if not scope_host:
            # Default the scope lock to the configured URL's host.
            scope_host = urlparse(raw["url"]).hostname
        return cls(
            name=raw.get("name", "unnamed-target"),
            url=raw["url"],
            method=raw.get("method", "POST").upper(),
            headers=raw.get("headers", {}),
            body_template=raw.get("body_template"),
            response_path=raw.get("response_path"),
            rate_limit_seconds=float(raw.get("rate_limit_seconds", 2.0)),
            scope_host=scope_host,
            timeout=float(raw.get("timeout", 30.0)),
        )

    def check_scope(self) -> None:
        """Raise if the target URL host is outside the declared scope."""
        host = urlparse(self.url).hostname
        if self.scope_host and host != self.scope_host:
            raise ScopeViolation(
                f"URL host {host!r} is outside declared scope {self.scope_host!r}. "
                "Refusing to send. Fix scope_host in the target profile if this is intended."
            )

    def build_headers(self) -> dict:
        return _expand_env(copy.deepcopy(self.headers))

    def build_body(self, payload: str) -> Any:
        if self.body_template is None:
            # Fallback: send the payload as a bare JSON string.
            return payload
        body = _inject_payload(copy.deepcopy(self.body_template), payload)
        return _expand_env(body)

    def extract_reply(self, response_json: Any, raw_text: str) -> str:
        """Pull the assistant reply out of the response using response_path."""
        if self.response_path and response_json is not None:
            val = _resolve_path(response_json, self.response_path)
            if val is not None:
                return val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)
        return raw_text


class ScopeViolation(Exception):
    """Raised when a request would leave the declared scope."""


def _resolve_path(obj: Any, path: str) -> Any:
    """Resolve 'a.b.0.c' against nested dicts/lists. Returns None if absent."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        else:
            return None
    return cur
