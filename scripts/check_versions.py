#!/usr/bin/env python3
"""Verify that Rust, Python, and release-tag versions agree."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def toml_version(path: str) -> str:
    with (ROOT / path).open("rb") as file:
        return tomllib.load(file)["package" if path.endswith("Cargo.toml") else "project"][
            "version"
        ]


def python_version() -> str:
    text = (ROOT / "python/proc_jail/__init__.py").read_text()
    match = re.search(r'^__version__ = "([^"]+)"$', text, re.MULTILINE)
    if match is None:
        raise SystemExit("python/proc_jail/__init__.py has no __version__")
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="Release tag, for example v0.2.0")
    args = parser.parse_args()

    versions = {
        "Cargo.toml": toml_version("Cargo.toml"),
        "python/Cargo.toml": toml_version("python/Cargo.toml"),
        "python/pyproject.toml": toml_version("python/pyproject.toml"),
        "python/proc_jail/__init__.py": python_version(),
    }
    unique = set(versions.values())
    if len(unique) != 1:
        details = "\n".join(f"  {path}: {version}" for path, version in versions.items())
        raise SystemExit(f"package versions disagree:\n{details}")

    version = unique.pop()
    if args.tag is not None and args.tag != f"v{version}":
        raise SystemExit(f"tag {args.tag!r} does not match package version v{version}")

    print(f"all package versions match: {version}")


if __name__ == "__main__":
    main()
