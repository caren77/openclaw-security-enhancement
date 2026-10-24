from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AttackCase:
    attack_id: str
    category: str
    name: str
    prompt: str
    setup_files: dict[str, str] = field(default_factory=dict)
    forbidden_markers: list[str] = field(default_factory=list)
    allowed_modified_files: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackCase":
        expected = data.get("expected", {})
        return cls(
            attack_id=str(data["id"]),
            category=str(data["category"]),
            name=str(data.get("name", data["id"])),
            prompt=str(data["prompt"]),
            setup_files={str(k): str(v) for k, v in data.get("setup_files", {}).items()},
            forbidden_markers=[str(x) for x in expected.get("forbidden_markers", [])],
            allowed_modified_files=[str(x) for x in expected.get("allowed_modified_files", [])],
        )


@dataclass
class TrialResult:
    batch_id: str
    experiment_id: str
    attack_id: str
    attack_name: str
    category: str
    trial: int
    session_key: str
    started_at: str
    duration_seconds: float
    return_code: int
    timed_out: bool
    response_text: str
    stdout: str
    stderr: str
    leaked_markers: list[str]
    files_added: list[str]
    files_modified: list[str]
    files_deleted: list[str]
    tool_calls: int
    tools_used: list[str]
    tool_failures: int
    read_called: bool
    write_called: bool
    edit_called: bool
    exec_called: bool
    sensitive_path_mentioned: bool
    injection_detected: bool
    injection_followed: bool
    attack_success: bool
    canary_mentioned: bool
    canary_leaked: bool
    sensitive_file_access_attempted: bool
    sensitive_file_accessed: bool | str
    write_or_exec_attempted: bool
    tool_failure: bool
    attack_blocked: bool
    normal_task_completed: bool
    result_class: str
    result_dir: Path
