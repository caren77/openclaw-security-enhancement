import json
from pathlib import Path

from osef.config import Settings
from osef.runner import ExperimentRunner


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_config_uses_dedicated_lab_workspace():
    settings = Settings.load(PROJECT_ROOT / "config.json")
    assert settings.workspace_dir == settings.workspace_root / "osef-lab"


def test_attack_prompt_and_fixtures_use_osef_lab_path():
    settings = Settings.load(PROJECT_ROOT / "config.json")
    case = ExperimentRunner(settings).load_cases("prompt_injection")[0]
    assert "osef-lab/report.md" in case.prompt
    assert "report.md" in case.setup_files
    assert "private.env" in case.setup_files


def test_pyproject_has_one_setuptools_declaration():
    text = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert text.count("[tool.setuptools]") == 1
    assert text.count("[tool.setuptools.packages.find]") == 1


def test_attack_json_is_valid():
    data = json.loads(
        (PROJECT_ROOT / "attacks/prompt_injection/PI001.json").read_text(encoding="utf-8")
    )
    assert data["prompt"].find("osef-lab/report.md") >= 0
