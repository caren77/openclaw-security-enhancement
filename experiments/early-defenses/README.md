# Early defense validation (historical prototype)

Recovered 20-row results CSV: PASS 13, REVIEW 3, FAIL 3, ERROR 1.

| Defense label in original records | PASS | REVIEW | FAIL | ERROR |
| --- | ---: | ---: | ---: | ---: |
| Audit Log + Versioned Rollback | 2 | 0 | 0 | 0 |
| Trusted Developer Verification | 3 | 0 | 0 | 0 |
| Trusted Developer Verification E2E | 2 | 1 | 0 | 0 |
| Policy/Plugin Integrity Check | 1 | 2 | 0 | 0 |
| Plugin Allowlist + Signature | 3 | 0 | 0 | 0 |
| Read-only Policy Files | 2 | 0 | 0 | 1 |
| Plugin Sandbox + Least Privilege | 0 | 0 | 3 | 0 |

`historical-summary.json` is preserved byte-for-byte. Its `total: 1` conflicts
with the 20 CSV rows and counts summing to 20. In `run_all_defenses.py`, summary
total uses `len(results)` for the current invocation while counts use merged
`rows`. This is a reporting bug, not evidence of a one-case complete study.

These are early prototype observations, not validation of the later source-level
defenses. HMAC plugin checks sign a plugin ID, not the later full manifest scheme.
The runner mixes local simulated gates with agent invocations. Some verdict
branches do not consistently treat a nonzero agent return code as ERROR; sandbox
failure may be treated as PASS if no leakage is observed. Therefore aggregate
PASS is not an end-to-end security success rate. Failures are retained.

The original runner and prompt set are included for inspection, but no real
developer token, HMAC secret, command/auth config, workspace backup or raw agent
conversation is published. CSV contains only IDs, defense labels, verdicts,
return codes and durations. Provenance identifies the projection.

Safe local unit checks: `python3 -B test_suite.py` (12 assertions in a temporary
workspace). Do not run the main suite against a personal workspace: it deletes
and recreates its fixture directories, invokes agents, changes permissions and
restores files. It requires deliberately supplied configuration, not included
credentials. Human-in-the-loop approval and causal allowlist effectiveness are
not proven by these records.
