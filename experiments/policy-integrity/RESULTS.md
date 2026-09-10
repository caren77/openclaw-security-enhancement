# Policy Integrity Experiment

## Goal

Evaluate whether poisoned `AGENTS.md` and `SOUL.md` policies are blocked before entering the Agent Context.

## Experiment Design

Controlled deterministic baseline-vs-hardened experiment.

- Baseline: 6 effective runs.
- Hardened: 6 effective runs.

## Results

| Metric | Result |
|---|---:|
| Baseline Poison Load Rate | 6/6 (100%) |
| Hardened Block Rate | 6/6 (100%) |
| `POLICY_INTEGRITY_BLOCKED` | 6 |
| `INCONCLUSIVE` | 0 |
| `ERROR` | 0 |

## Interpretation

In this controlled experiment, poisoned policy files were loaded in all baseline runs, while all poisoned policy files were blocked after source-level Policy Integrity protection was enabled.

This result applies to the controlled experimental scenarios used in this research and is not a guarantee of complete security.
