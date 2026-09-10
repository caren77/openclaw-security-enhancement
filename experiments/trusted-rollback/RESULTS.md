# Trusted Rollback Experiment

## Goal

Evaluate fail-closed policy integrity behavior, trusted snapshot recovery, and safe loading on a later turn.

## Experiment Design

Controlled deterministic comparison with 6 no-rollback runs and 6 rollback-enabled runs.

## Results

| Metric | Result |
|---|---:|
| No-Rollback Expected Behavior | 6/6 |
| Rollback PASS | 6/6 |
| Integrity-only Block Rate | 6/6 (100%) |
| Recovery Success Rate | 6/6 (100%) |
| Next-turn Recovery Rate | 6/6 (100%) |
| No-Rollback Residual Poison Rate | 6/6 |
| Rollback Residual Poison Rate | 0/6 |
| `BLOCK` | 12 |
| `RECOVERED` | 6 |
| `RECOVERY_FAILED` | 0 |
| `INCONCLUSIVE` | 0 |
| `ERROR` | 0 |

The current turn remained blocked after a successful recovery. Restored trusted policy became eligible for loading only on a later turn.

## Debugging Note

The first rollback experiment exposed a real implementation bug: recovery occurred even when the rollback feature flag was disabled.

Root cause:

`verifyPolicyFileContent()` unconditionally invoked trusted recovery on hash mismatch.

A minimal feature-flag guard was added, regression tests were introduced, and the complete experiment was rerun.

The original failed experiment was preserved.

## Limitation

This result applies to the controlled experimental scenarios used in this research and is not a guarantee of complete security.
