#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Manuel Miguel Fernandez-Gallego Olivares (AEGIR Security)
# Huginn — LLM red-team payload harness. Dual-licensed: AGPL-3.0 or commercial (see COMMERCIAL.md).
"""
Huginn CLI — batch runner + reviewer.

Fire a battery of payloads at a target and log every request/response to
history.jsonl, then triage what came back.

Examples:
    # Run every direct-injection probe against a target profile
    python run.py --target config/target.example.json --phase direct_injection

    # Run everything, cap at 3 payloads per phase
    python run.py --target config/mybot.json --phase all --max 3

    # Review a history file: show only the interesting hits
    python run.py --report --history history.jsonl

Authorised testing only. The target profile carries your researcher token and
the scope lock; Huginn refuses to send outside the declared scope.
"""

from __future__ import annotations

import argparse
import json
import sys

from core.target import Target, ScopeViolation
from core.library import load, PHASES
from core.sender import Sender

C_RESET = "\033[0m"; C_RED = "\033[31m"; C_YEL = "\033[33m"
C_GRN = "\033[32m"; C_DIM = "\033[2m"; C_BOLD = "\033[1m"


def _conf_color(conf: str) -> str:
    return {"high": C_RED, "medium": C_YEL, "low": C_DIM}.get(conf, "")


def run(args) -> int:
    try:
        target = Target.load(args.target)
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"{C_RED}Could not load target profile: {exc}{C_RESET}", file=sys.stderr)
        return 2

    try:
        target.check_scope()
    except ScopeViolation as exc:
        print(f"{C_RED}{exc}{C_RESET}", file=sys.stderr)
        return 3

    payloads = load(args.phase)
    if args.max:
        # cap per phase
        capped, seen = [], {}
        for p in payloads:
            seen[p.phase] = seen.get(p.phase, 0) + 1
            if seen[p.phase] <= args.max:
                capped.append(p)
        payloads = capped

    print(f"{C_BOLD}Huginn{C_RESET}  target={target.name}  host={target.scope_host}  "
          f"payloads={len(payloads)}  rate={target.rate_limit_seconds}s  "
          f"log={args.history}")
    print(f"{C_DIM}{'-'*72}{C_RESET}")

    sender = Sender(target, history_path=args.history)
    interesting = 0
    for i, p in enumerate(payloads, 1):
        res = sender.send_payload(p)
        if res.error:
            print(f"{i:>3}. {C_DIM}{p.phase}/{p.id}{C_RESET}  "
                  f"{C_RED}ERROR{C_RESET} {res.error}")
            continue
        tag = (f"{C_RED}INTERESTING{C_RESET}" if res.interesting
               else f"{C_DIM}ok{C_RESET}")
        print(f"{i:>3}. {p.phase}/{p.id}  [{res.status_code}] {res.latency_ms}ms  {tag}")
        for h in res.hits:
            col = _conf_color(h.confidence)
            print(f"      {col}→ [{h.confidence}] {h.detector}{C_RESET}: {h.reason}")
            print(f"        {C_DIM}{h.snippet}{C_RESET}")
        if res.interesting:
            interesting += 1

    print(f"{C_DIM}{'-'*72}{C_RESET}")
    print(f"Done. {interesting} interesting of {len(payloads)}. "
          f"Full log: {args.history}")
    return 0


def report(args) -> int:
    try:
        with open(args.history, "r", encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
    except OSError as exc:
        print(f"{C_RED}Cannot read history: {exc}{C_RESET}", file=sys.stderr)
        return 2
    hot = [r for r in rows if r.get("interesting")]
    print(f"{C_BOLD}Review{C_RESET} {args.history}  total={len(rows)}  "
          f"interesting={len(hot)}")
    print(f"{C_DIM}{'-'*72}{C_RESET}")
    for r in hot:
        print(f"{r['phase']}/{r['payload_id']}  [{r.get('status_code')}]  {r['ts']}")
        print(f"  {C_DIM}sent:{C_RESET} {r['sent_text'][:100]}")
        for h in r.get("hits", []):
            col = _conf_color(h.get("confidence", ""))
            print(f"  {col}→ [{h['confidence']}] {h['detector']}{C_RESET}: {h['reason']}")
    if not hot:
        print(f"{C_GRN}Nothing flagged. Target held up against these probes.{C_RESET}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Huginn — LLM red-team payload harness")
    ap.add_argument("--target", help="path to a target profile JSON")
    ap.add_argument("--phase", default="all",
                    help=f"phase to run: all | {' | '.join(PHASES)}")
    ap.add_argument("--max", type=int, default=0, help="max payloads per phase")
    ap.add_argument("--history", default="history.jsonl", help="JSONL log path")
    ap.add_argument("--report", action="store_true",
                    help="review an existing history file instead of sending")
    args = ap.parse_args()

    if args.report:
        return report(args)
    if not args.target:
        ap.error("--target is required unless --report is used")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
