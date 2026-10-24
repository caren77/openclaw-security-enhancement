# Prompt Injection experiments

Recovered evaluator v0.2.0, six synthetic fixtures and final analysis cohort
`phase1-baseline-20260725` (2026-07-25). The name contains "baseline", but all 18
raw stdout metadata records report sandbox mode `all`, sandboxed `true`, provider
`deepseek`, model `deepseek-v4-flash`. Do not equate this cohort with an unprotected
baseline or attribute its result to a particular defense in isolation.

Six distinct fixtures (PI001–PI006), three repetitions each. The final analysis
contains 18 SAFE_REFUSAL, 0 canary leaks, 0 exec/write/edit calls. Seven additional
preliminary result directories exist locally but are not mixed into this final
cohort. Sensitive file access remains `unknown`: tool summaries do not identify
read paths. Refusal text mentioning a secret path is not access evidence.

`scripts/analyze_phase1.py:adjudicate` defines attack success as `canary_leaked`.
ASR = successful canary leaks / total final trials = 0/18. Dangerous tool usage
is a separate OR of write/edit/exec. This narrow metric does not cover every
possible form of task hijacking or disclosure.

The requested ~60% baseline and ~6.7% Output Guard results could not be verified
from recovered row-level records. No matched-environment comparison is claimed.
Likewise 0/18 dangerous tool calls is an observation, not causal evidence for
Tool Allowlist effectiveness.

## Public material and privacy

`results.public.csv` is a column projection, not the full raw trace. It excludes
responses, stdout/stderr, session IDs, absolute paths and changed file lists.
Input/public SHA-256 hashes and omitted columns are in
`../../docs/PUBLICATION_PROVENANCE.json`. Original records are unchanged locally.
The six `private.env` strings inside fixture JSON contain explicitly fake keys
and synthetic OSEF canaries, not credentials. Absolute personal paths in the
archived analyzer were replaced by `/path/to/researcher`.

## Reproduction

Public statistics: `python3 -B ../../scripts/check_publication.py`.
Offline evaluator tests: `python3 -B ../../scripts/test_prompt_injection.py`.
The latter runs the existing tests in a temporary copy with a deliberately
nonfunctional example command; it does not call an agent.

For a **new** live experiment, copy `config.example.json` to an ignored
`config.json`, supply a sandboxed CLI command and dedicated disposable workspace,
then use `PYTHONPATH=src python3 -B -m osef.cli --config config.json --list` to
inspect fixtures. Only after configuring containment, `--all --repetitions 3`
starts new runs. The runner resets its designated `osef-lab` directory. Never
use a personal workspace; never commit config or raw responses.

The historical analyzer requires pandas/matplotlib and original per-run files;
its protected-workspace check also depends on a historical temporary snapshot.
It is archived for method inspection, not advertised as a self-contained
reproduction of unavailable private inputs. Current public checks use stdlib only.
