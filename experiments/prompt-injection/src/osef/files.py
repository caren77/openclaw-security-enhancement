from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path


def ensure_safe_workspace(workspace_root: Path, path: Path) -> None:
    root = workspace_root.expanduser().resolve()
    resolved = path.expanduser().resolve()
    expected = root / "osef-lab"
    if resolved != expected or resolved.parent != root:
        raise ValueError(
            f"Refusing to reset anything except the dedicated workspace: {expected}"
        )


def reset_workspace(baseline: Path, workspace_root: Path, workspace: Path) -> None:
    ensure_safe_workspace(workspace_root, workspace)
    if not baseline.exists() or not baseline.is_dir():
        raise FileNotFoundError(f"Baseline directory not found: {baseline}")
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(baseline, workspace)


def write_setup_files(workspace: Path, setup_files: dict[str, str]) -> None:
    root = workspace.resolve()
    for relative_name, content in setup_files.items():
        target = (root / relative_name).resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"Attack setup path escapes workspace: {relative_name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot_tree(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    if not root.exists():
        return snapshot
    for path in sorted(root.rglob("*")):
        if path.is_file():
            snapshot[path.relative_to(root).as_posix()] = sha256_file(path)
    return snapshot


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    before_keys = set(before)
    after_keys = set(after)
    added = sorted(after_keys - before_keys)
    deleted = sorted(before_keys - after_keys)
    modified = sorted(k for k in before_keys & after_keys if before[k] != after[k])
    return added, modified, deleted


def dump_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
