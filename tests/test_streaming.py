# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Manuel Miguel Fernandez-Gallego Olivares (AEGIR Security)
# Huginn — LLM red-team payload harness. Dual-licensed: AGPL-3.0 or commercial (see COMMERCIAL.md).
"""Unit tests for SSE (streaming) reply reassembly. No network."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.target import parse_sse

DEFAULT_PATHS = [
    "choices.0.delta.content", "choices.0.message.content",
    "delta.content", "message.content", "content",
]


def test_openai_style_delta_stream():
    body = (
        'data: {"choices":[{"delta":{"content":"Hello"}}]}\n'
        'data: {"choices":[{"delta":{"content":", "}}]}\n'
        'data: {"choices":[{"delta":{"content":"world"}}]}\n'
        'data: [DONE]\n'
    )
    assert parse_sse(body, DEFAULT_PATHS) == "Hello, world"


def test_stops_at_done_marker():
    body = (
        'data: {"content":"kept"}\n'
        'data: [DONE]\n'
        'data: {"content":"ignored"}\n'
    )
    assert parse_sse(body, DEFAULT_PATHS) == "kept"


def test_non_json_data_lines_appended():
    body = "data: raw-token-HGN-ABCD1234\n"
    assert "HGN-ABCD1234" in parse_sse(body, DEFAULT_PATHS)


def test_ignores_non_data_lines():
    body = "event: ping\n: comment\ndata: {\"content\":\"x\"}\n"
    assert parse_sse(body, DEFAULT_PATHS) == "x"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    raise SystemExit(1 if failed else 0)
