from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool


class OpenClawClient:
    def __init__(self, command_template: list[str], cwd: Path, timeout_seconds: int) -> None:
        self.command_template = command_template
        self.cwd = cwd
        self.timeout_seconds = timeout_seconds

    def build_command(self, prompt: str, session_key: str) -> list[str]:
        replacements = {
            "prompt": prompt,
            "session_key": session_key,
        }
        return [part.format(**replacements) for part in self.command_template]

    def run(self, prompt: str, session_key: str) -> CommandResult:
        command = self.build_command(prompt, session_key)
        try:
            completed = subprocess.run(
                command,
                cwd=self.cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env={**os.environ, "NO_COLOR": "1"},
            )
            return CommandResult(completed.returncode, completed.stdout, completed.stderr, False)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return CommandResult(124, stdout, stderr, True)

    @staticmethod
    def extract_response(stdout: str) -> str:
        text = stdout.strip()
        if not text:
            return ""
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return text

        result = payload.get("result") if isinstance(payload, dict) else None
        if isinstance(result, dict):
            meta = result.get("meta")
            if isinstance(meta, dict):
                visible = meta.get("finalAssistantVisibleText")
                if isinstance(visible, str) and visible.strip():
                    return visible
            payloads = result.get("payloads")
            if isinstance(payloads, list) and payloads and isinstance(payloads[0], dict):
                fallback = payloads[0].get("text")
                if isinstance(fallback, str) and fallback.strip():
                    return fallback

        preferred_keys = ("finalAssistantVisibleText", "reply", "response", "text", "message", "output")

        def search(value):
            if isinstance(value, dict):
                for key in preferred_keys:
                    candidate = value.get(key)
                    if isinstance(candidate, str) and candidate.strip():
                        return candidate
                for child in value.values():
                    found = search(child)
                    if found:
                        return found
            elif isinstance(value, list):
                for child in value:
                    found = search(child)
                    if found:
                        return found
            return None

        found = search(payload)
        if found:
            return found
        return json.dumps(payload, ensure_ascii=False, indent=2)
