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
    # Allowlist of in-scope hosts (exact or leading-wildcard "*.example.com").
    scope_hosts: list = field(default_factory=list)
    timeout: float = 30.0
    # Cross-tenant: a lookup term the probe asks about, and a secret planted in
    # tenant B's knowledge base. Detection is confirmed only if the secret comes
    # back (see core.detectors.analyze bside_secret).
    cross_tenant_lookup: str | None = None
    cross_tenant_bside: str | None = None
    # Dotted path to the messages array inside body_template, for multi-turn
    # conversations. Defaults to auto-detecting the first list of {role, content}.
    messages_path: str | None = None
    # Compliance: require identified traffic before sending, and back off on 429.
    require_identification: bool = True
    max_retries: int = 2

    @classmethod
    def load(cls, path: str) -> "Target":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        # Scope allowlist: accept a list (scope_hosts) or a single scope_host, and
        # default to the configured URL's host when neither is given.
        scope_hosts = raw.get("scope_hosts")
        if isinstance(scope_hosts, str):
            scope_hosts = [scope_hosts]
        if not scope_hosts:
            one = raw.get("scope_host") or urlparse(raw["url"]).hostname
            scope_hosts = [one] if one else []
        ct = raw.get("cross_tenant", {}) or {}
        return cls(
            name=raw.get("name", "unnamed-target"),
            url=raw["url"],
            method=raw.get("method", "POST").upper(),
            headers=raw.get("headers", {}),
            body_template=raw.get("body_template"),
            response_path=raw.get("response_path"),
            rate_limit_seconds=float(raw.get("rate_limit_seconds", 2.0)),
            scope_host=scope_hosts[0] if scope_hosts else None,
            scope_hosts=scope_hosts,
            timeout=float(raw.get("timeout", 30.0)),
            cross_tenant_lookup=ct.get("lookup"),
            cross_tenant_bside=ct.get("bside_secret"),
            messages_path=raw.get("messages_path"),
            require_identification=bool(raw.get("require_identification", True)),
            max_retries=int(raw.get("max_retries", 2)),
        )

    def check_scope(self) -> None:
        """Raise if the target URL host is outside the declared scope allowlist."""
        host = urlparse(self.url).hostname
        if self.scope_hosts and not _host_in_scope(host, self.scope_hosts):
            raise ScopeViolation(
                f"URL host {host!r} is outside declared scope {self.scope_hosts!r}. "
                "Refusing to send. Fix scope_hosts in the target profile if this is intended."
            )

    def identification(self) -> tuple[bool, str]:
        """Is this traffic attributable? Returns (ok, how). Many programs require
        identified recon — an X-Bug-Bounty-style header or a researcher UA."""
        hdrs = {k.lower(): (v or "") for k, v in _expand_env(self.headers).items()}
        for name in ("x-bug-bounty", "x-hackerone-research", "x-bugcrowd-researcher",
                     "x-researcher", "x-yeswehack"):
            if hdrs.get(name, "").strip():
                return True, name
        ua = hdrs.get("user-agent", "").strip()
        if ua and "python-requests" not in ua.lower():
            return True, "user-agent"
        return False, ""

    def check_identification(self) -> None:
        """Raise if identified traffic is required but no identifying header is set."""
        if not self.require_identification:
            return
        ok, _ = self.identification()
        if not ok:
            raise ComplianceError(
                "No identifying header set (e.g. X-Bug-Bounty) and require_identification "
                "is on. Many programs require attributable traffic. Add one to the target "
                "profile's headers, or set require_identification=false to override."
            )

    def build_headers(self) -> dict:
        return _expand_env(copy.deepcopy(self.headers))

    def build_body(self, payload: str) -> Any:
        if self.body_template is None:
            # Fallback: send the payload as a bare JSON string.
            return payload
        body = _inject_payload(copy.deepcopy(self.body_template), payload)
        return _expand_env(body)

    def build_body_messages(self, messages: list[dict]) -> Any:
        """Build a request body carrying a full conversation (multi-turn).

        The messages array in body_template is replaced with the accumulated
        conversation so turn N is sent with all prior turns as context.
        """
        msgs = [{"role": m["role"], "content": m["content"]} for m in messages]
        if self.body_template is None:
            return _expand_env({"messages": msgs})
        body = copy.deepcopy(self.body_template)
        placed = False
        if self.messages_path:
            placed = _set_path(body, self.messages_path, msgs)
        if not placed:
            placed = _replace_messages(body, msgs)
        if not placed:
            # No messages array in the template — fall back to single-turn with
            # the last user message so the target still gets something sensible.
            last = next((m["content"] for m in reversed(msgs)
                         if m.get("role") == "user"), "")
            body = _inject_payload(copy.deepcopy(self.body_template), last)
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


class ComplianceError(Exception):
    """Raised when a send would violate a compliance rail (e.g. unidentified traffic)."""


def _host_in_scope(host: str | None, patterns: list) -> bool:
    """Exact match, or a leading-wildcard '*.example.com' (matches sub.example.com
    and example.com itself)."""
    if not host:
        return False
    for p in patterns:
        if not p:
            continue
        if p == host:
            return True
        if p.startswith("*.") and (host == p[2:] or host.endswith(p[1:])):
            return True
    return False


def _looks_like_messages(value: Any) -> bool:
    return (isinstance(value, list) and len(value) > 0
            and all(isinstance(i, dict) and "role" in i for i in value))


def _replace_messages(obj: Any, messages: list) -> bool:
    """Replace the first messages-like list found inside obj. Mutates in place."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _looks_like_messages(v):
                obj[k] = [dict(m) for m in messages]
                return True
            if _replace_messages(v, messages):
                return True
    elif isinstance(obj, list):
        for v in obj:
            if _replace_messages(v, messages):
                return True
    return False


def _set_path(obj: Any, path: str, value: Any) -> bool:
    """Set a dotted path (supports list indices). Returns False if it doesn't resolve."""
    parts = path.split(".")
    cur = obj
    for part in parts[:-1]:
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return False
        elif isinstance(cur, dict):
            if part not in cur:
                return False
            cur = cur[part]
        else:
            return False
    last = parts[-1]
    if isinstance(cur, list):
        try:
            cur[int(last)] = value
            return True
        except (ValueError, IndexError):
            return False
    if isinstance(cur, dict):
        cur[last] = value
        return True
    return False


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
