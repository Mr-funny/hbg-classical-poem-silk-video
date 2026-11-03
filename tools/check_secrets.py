#!/usr/bin/env python3
from __future__ import annotations

import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "__pycache__"}
TEXT_SUFFIXES = {
    "", ".md", ".txt", ".py", ".sh", ".yml", ".yaml", ".json", ".svg", ".gitignore"
}
PATTERNS = {
    "OpenAI-style key": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    "GitHub token": re.compile(r"\bgh[opsu]_[A-Za-z0-9]{20,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    "Bearer token": re.compile(r"Bearer\s+[A-Za-z0-9._~-]{20,}"),
    "64-character hex secret": re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I),
    "private macOS path": re.compile(r"/Users/[^/\s]+/"),
    "private Linux home path": re.compile(r"/home/[^/\s]+/"),
    "private Windows path": re.compile(r"[A-Za-z]:[\\/]{1,2}Users[\\/]{1,2}[^\\/\s]+", re.I),
}
EXTRA_PATTERNS_ENV = "POEM_SECRET_PATTERNS"


def load_extra_patterns() -> dict[str, re.Pattern[str]]:
    """Compile operator-supplied patterns instead of hardcoding private identifiers."""
    extra: dict[str, re.Pattern[str]] = {}
    raw = os.environ.get(EXTRA_PATTERNS_ENV, "")
    for index, line in enumerate(raw.splitlines(), start=1):
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            extra[f"extra pattern #{index}"] = re.compile(candidate, re.I)
        except re.error as error:
            print(f"warn ignoring invalid {EXTRA_PATTERNS_ENV} entry #{index}: {error}")
    return extra


def main() -> int:
    findings: list[str] = []
    patterns = {**PATTERNS, **load_extra_patterns()}
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        if path.name == ".env" or path.name.endswith("cookies.json"):
            findings.append(f"forbidden credential file: {path.relative_to(ROOT)}")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"README.md", "LICENSE"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in patterns.items():
            if pattern.search(text):
                findings.append(f"{label}: {path.relative_to(ROOT)}")
    if findings:
        for finding in findings:
            print(f"ERROR {finding}")
        return 1
    print("No secrets or private local paths detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())