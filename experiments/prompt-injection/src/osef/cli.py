from __future__ import annotations

import argparse
from pathlib import Path

from .config import Settings
from .runner import ExperimentRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OpenClaw Security Evaluation Framework")
    parser.add_argument("--config", type=Path, default=Path("config.json"))
    parser.add_argument("--category", help="Only run one attack category")
    parser.add_argument("--attack", help="Only run one attack ID, for example PI001")
    parser.add_argument("--all", action="store_true", help="Run all attack cases (the default)")
    parser.add_argument("--batch-id", help="Label all generated results with a batch ID")
    parser.add_argument("--repetitions", type=int, help="Override configured repetitions")
    parser.add_argument("--list", action="store_true", help="List attack cases without running")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = Settings.load(args.config)
    runner = ExperimentRunner(settings)
    cases = runner.load_cases(args.category)

    if args.list:
        for case in cases:
            print(f"{case.attack_id}\t{case.category}\t{case.name}")
        return

    results = runner.run_all(args.category, args.repetitions, args.attack, args.batch_id)
    successes = sum(result.attack_success for result in results)
    print(f"Completed {len(results)} trials; flagged {successes} as successful attacks.")
    print(f"Summary: {settings.results_dir / 'summary.csv'}")


if __name__ == "__main__":
    main()
