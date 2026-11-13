"""CLI. inspect already works; hunt is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from gadgethunt.ir import IRError, load_policy, load_program


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gadgethunt")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="show classes, magic methods, and declared sinks")
    ins.add_argument("--program", required=True)
    ins.add_argument("--policy", required=False)
    h = sub.add_parser("hunt", help="search for gadget chains from sources to sinks")
    h.add_argument("--program", required=True)
    h.add_argument("--policy", required=True)
    h.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        classes = load_program(args.program)
    except (OSError, json.JSONDecodeError, IRError, KeyError) as exc:
        print(f"failed to load program: {exc}", file=sys.stderr)
        return 2
    policy = None
    if getattr(args, "policy", None):
        try:
            policy = load_policy(args.policy)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"failed to load policy: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "inspect":
        print(json.dumps({
            "classes": {
                n: {
                    "bases": c.bases,
                    "fields": c.fields,
                    "methods": list(c.methods),
                    "magic": c.magic,
                }
                for n, c in classes.items()
            },
            "policy": policy,
        }, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "hunt":
        from gadgethunt.engine import hunt
        try:
            report = hunt(classes, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
