# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Manuel Miguel Fernandez-Gallego Olivares (AEGIR Security)
# Huginn — LLM red-team payload harness. Dual-licensed: AGPL-3.0 or commercial (see COMMERCIAL.md).
"""Unit tests for the P1 compliance rails — scope allowlist + identification. No network."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.target import Target, ScopeViolation, ComplianceError


def _target(**over):
    base = dict(name="t", url="https://api.example.com/chat",
                headers={"X-Bug-Bounty": "Manuel_Miguel"},
                scope_hosts=["api.example.com"])
    base.update(over)
    return Target(**base)


def test_scope_allows_listed_host():
    _target().check_scope()  # must not raise


def test_scope_blocks_unlisted_host():
    t = _target(url="https://evil.example.org/chat")
    try:
        t.check_scope()
        assert False, "expected ScopeViolation"
    except ScopeViolation:
        pass


def test_scope_wildcard_matches_subdomain_and_apex():
    t = _target(url="https://api.sub.example.com/chat", scope_hosts=["*.example.com"])
    t.check_scope()
    t2 = _target(url="https://example.com/chat", scope_hosts=["*.example.com"])
    t2.check_scope()


def test_identification_required_by_default():
    t = _target(headers={})
    try:
        t.check_identification()
        assert False, "expected ComplianceError"
    except ComplianceError:
        pass


def test_identification_satisfied_by_header():
    _target().check_identification()  # X-Bug-Bounty present -> ok


def test_identification_override():
    t = _target(headers={}, require_identification=False)
    t.check_identification()  # explicitly opted out -> ok


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
