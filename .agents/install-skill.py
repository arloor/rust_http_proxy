#!/usr/bin/env python3
"""Install this repository's MITM skill into the current user's skill directory."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sys
import tempfile
import uuid
from pathlib import Path


SKILL_NAME = "rust-http-proxy-mitm"
NAME_PATTERN = re.compile(r"(?m)^name: ([a-z0-9]+(?:-[a-z0-9]+)*)$")


def file_manifest(root: Path) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        manifest[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def validate_source(source: Path) -> dict[str, str]:
    skill_file = source / "SKILL.md"
    if not skill_file.is_file():
        raise ValueError(f"missing {skill_file}")
    text = skill_file.read_text(encoding="utf-8")
    match = NAME_PATTERN.search(text)
    if match is None:
        raise ValueError("SKILL.md has no valid unquoted name")
    if match.group(1) != source.name:
        raise ValueError(f"skill name {match.group(1)!r} does not match directory {source.name!r}")
    if source.name != SKILL_NAME:
        raise ValueError(f"expected source directory {SKILL_NAME!r}")
    manifest = file_manifest(source)
    if not manifest:
        raise ValueError("skill source is empty")
    return manifest


def install(source: Path, target_root: Path, force: bool) -> Path:
    source_manifest = validate_source(source)
    target_root.mkdir(parents=True, exist_ok=True)
    destination = target_root / source.name
    destination_exists = destination.exists() or destination.is_symlink()
    if destination_exists and not destination.is_dir():
        raise FileExistsError(f"{destination} exists and is not a directory")
    if destination_exists and not force:
        raise FileExistsError(f"{destination} already exists; rerun with --force to replace it")

    staging_parent = Path(tempfile.mkdtemp(prefix=f".{source.name}-install-", dir=target_root))
    staged = staging_parent / source.name
    backup: Path | None = None
    try:
        shutil.copytree(source, staged)
        if file_manifest(staged) != source_manifest:
            raise RuntimeError("staged files do not match the source")

        if destination_exists:
            backup = target_root / f".{source.name}-backup-{uuid.uuid4().hex}"
            os.replace(destination, backup)
        try:
            os.replace(staged, destination)
            if file_manifest(destination) != source_manifest:
                raise RuntimeError("installed files do not match the source")
        except BaseException:
            if destination.exists():
                shutil.rmtree(destination)
            if backup is not None:
                os.replace(backup, destination)
                backup = None
            raise

        if backup is not None:
            shutil.rmtree(backup)
            backup = None
        return destination
    finally:
        if backup is not None and backup.exists():
            if not destination.exists():
                os.replace(backup, destination)
            else:
                shutil.rmtree(backup)
        shutil.rmtree(staging_parent, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-root",
        type=Path,
        default=Path.home() / ".agents" / "skills",
        help="Skill installation root (default: ~/.agents/skills)",
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing installation")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    source = Path(__file__).resolve().parent / "skills" / SKILL_NAME
    try:
        destination = install(source, args.target_root.expanduser().resolve(), args.force)
    except (FileExistsError, OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"Installed {SKILL_NAME} to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
