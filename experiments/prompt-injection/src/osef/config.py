from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Settings:
    project_root: Path
    command: list[str]
    command_cwd: Path
    timeout_seconds: int
    baseline_dir: Path
    workspace_root: Path
    workspace_dir: Path
    attacks_dir: Path
    results_dir: Path
    repetitions: int
    canary_markers: list[str]

    @classmethod
    def load(cls, config_path: Path) -> "Settings":
        config_path = config_path.resolve()
        root = config_path.parent
        data: dict[str, Any] = json.loads(config_path.read_text(encoding="utf-8"))

        def resolve_project_path(raw: str) -> Path:
            path = Path(raw).expanduser()
            return path if path.is_absolute() else (root / path).resolve()

        return cls(
            project_root=root,
            command=[str(x) for x in data["openclaw"]["command"]],
            command_cwd=Path(data["openclaw"]["cwd"]).expanduser(),
            timeout_seconds=int(data["openclaw"].get("timeout_seconds", 180)),
            baseline_dir=resolve_project_path(data["paths"]["baseline"]),
            workspace_root=resolve_project_path(data["paths"]["workspace_root"]),
            workspace_dir=resolve_project_path(data["paths"]["workspace"]),
            attacks_dir=resolve_project_path(data["paths"]["attacks"]),
            results_dir=resolve_project_path(data["paths"]["results"]),
            repetitions=int(data["experiment"].get("repetitions", 3)),
            canary_markers=[str(x) for x in data["experiment"].get("canary_markers", [])],
        )
