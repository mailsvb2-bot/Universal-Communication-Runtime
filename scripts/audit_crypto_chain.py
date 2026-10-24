#!/usr/bin/env python3
"""Fail-closed diagnosis of RUSTSEC-2026-0387 in UCR's six Cargo.lock files."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import tomllib

LOCKS = (
    "Cargo.lock", "fuzz/Cargo.lock", "crates/ucr-sdk/Cargo.lock",
    "crates/ucr-reference-messenger/Cargo.lock", "crates/ucr-ai-actor/Cargo.lock",
    "crates/ucr-chaos-lab/Cargo.lock",
)
VULNERABLE = "crypto-bigint"

def audit_lock(path: Path):
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    packages = data["package"]
    offenders = []
    for package in packages:
        if package["name"] != VULNERABLE:
            continue
        version = package["version"]
        parsed = tuple(int(part) for part in version.split("."))
        if parsed < (0, 7, 6):
            parents = [
                {"name": parent["name"], "version": parent["version"]}
                for parent in packages
                if any(dep == VULNERABLE or dep.startswith(VULNERABLE + " ")
                       for dep in parent.get("dependencies", []))
            ]
            offenders.append({"package": VULNERABLE, "version": version, "parents": parents})
    return {"lockfile": str(path), "offenders": offenders, "packages": len(packages)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--allow-vulnerable", action="store_true",
                        help="diagnostic only; do not use as a CI security bypass")
    args = parser.parse_args()
    root = args.root.resolve()
    missing = [str(root / path) for path in LOCKS if not (root / path).is_file()]
    if missing:
        print("ERROR: Missing required lockfiles:\n" + "\n".join(missing), file=sys.stderr)
        return 2
    try:
        results = [audit_lock(root / path) for path in LOCKS]
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: Invalid Cargo.lock: {error}", file=sys.stderr)
        return 2
    report = json.dumps(
        {"advisory": "RUSTSEC-2026-0387", "fixed_minimum": "0.7.6", "locks": results},
        ensure_ascii=False, indent=2,
    )
    print(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report + "\n", encoding="utf-8")
    if any(item["offenders"] for item in results) and not args.allow_vulnerable:
        print("BLOCKED: unsafe crypto-bigint is still present", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
