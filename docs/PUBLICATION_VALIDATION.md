# Publication validation — 2026-10-24

This is new publication-time validation, not a reconstruction of historical
experiment runs. Source files were copied/exported, not changed in the original
research checkout. Prior published experiments, source modules, license and
historical review notes are retained. The original README is preserved as
`../README_PRE_PUBLICATION.md`.

## Repository and patch identity

- Publication base main: `48e8dbf2c691a57c646bbed06caa46c960cb2997`.
- Work branch: `codex/research-publication-completion`, in a separate local clone.
- Source base: `090cb491227e45cdbdc0a65ea2718c8fe62461c9`.
- `python3 -B scripts/verify_patches.py /path/to/openclaw`: all three patches
  passed check/apply in a temporary directory seeded with exact upstream base
  files. Patched TypeScript files matched the research checkout; all ten Scanner
  snapshot files matched byte-for-byte. No source-checkout Git metadata was
  changed by this patch check.
- `python3 -B scripts/check_publication.py`: 49 primary export hashes plus two
  supplemental hashes verified; public statistics assertions passed.
- `git diff --cached --check`: passed. Unified-diff artifacts are marked
  `-whitespace` in `.gitattributes` because empty context lines require a space;
  their bytes are preserved and validated by actual patch application.
  Local Markdown target checks passed after adding
  this report and keeping the historical README at repository root.

## Executed offline tests

OpenClaw commands ran through `node scripts/run-vitest.mjs` in the existing
research checkout with its existing dependencies (Node v26.0.0):

| Target | Passed |
| --- | ---: |
| src/skills/security/scanner.test.ts | 60/60 |
| src/skills/loading/workspace-load.test.ts + session.test.ts + src/node-host/skills.test.ts + src/skills/runtime/remote-skills.test.ts | 70/70 |
| src/agents/policy-integrity.test.ts | 21/21 |
| src/plugins/plugin-verification.test.ts | 19/19 |
| src/agents/sandbox/docker-daemon-host-paths.test.ts | 3/3 |
| src/agents/sandbox/docker.config-hash-recreate.test.ts | 12/12 |
| Total TypeScript tests | 185/185 |

The first unprivileged Scanner test attempt was blocked before test execution
by filesystem permissions on the wrapper's temporary lock. The permitted rerun
passed. The wrapper generated transient locks/caches, not source changes.
These runs used the existing dirty research checkout, **not** a clean full
installation built solely from the exported patches. Mechanical patch checks
and focused test evidence must not be mistaken for a clean-build certification.

Python 3.12 offline checks in the publication clone:

- `python3 -B scripts/test_prompt_injection.py`: 16/16 existing tests passed.
  The small publication runner executes unittest cases and zero-argument test
  functions in a temporary copy; no agent is launched and no pytest dependency
  was installed.
- In `experiments/agent-misoperation`, `python3 -B -m unittest test_evaluator -v`:
  12/12 passed.
- In `experiments/early-defenses`, `python3 -B test_suite.py`: 12/12 local
  assertions passed in a temporary workspace.

No full build, typecheck, dependency reinstall, live gateway/LLM experiment,
Docker container execution or cross-platform test was performed. No fresh
Scanner formal experiment is claimed. The optional filename-protection
prototype has no newly executed dedicated behavioral suite.

## Experimental evidence checks

- Prompt Injection: final analysis cohort 18 rows, six IDs repeated three times;
  canary/exec/write/edit/return-code/timeout fields checked against 18 raw
  `result.json` files selected by batch ID. Safe raw-record projection and input
  hashes appear in `../experiments/prompt-injection/raw-evidence.public.json`.
  All 18 report sandboxed=true and mode=all. No unprotected-baseline comparison
  can be inferred. Seven preliminary directories are excluded.
- Misoperation: 60 final rows, 20 IDs, SAFE 28 / REVIEW 15 / MISOPERATION 17;
  no ERROR rows. Category totals checked. This verifies reported classifications,
  not independent replay/re-adjudication of all tool actions.
- Early defense CSV: 20 rows; 13 PASS / 3 REVIEW / 3 FAIL / 1 ERROR. Historical
  summary's total=1 is retained with an explanation of the merge-count bug.
- Existing published policy, rollback and plugin CSVs: 12 rows each, six per
  condition. Rollback's control still blocks first-turn loading: it is a
  no-recovery condition, not a successful poison-loading baseline.
- Scanner: no original per-run fixture/harness/result directory recovered.
  The historical 6/6 detection, 5/6 BLOCK and 0/6 benign BLOCK summary is labeled
  unverified; no absent fields were invented.

## Public-data safety

Explicit file allowlists were used. No auth configuration, real .env, credential
store, database, Docker socket, private workspace backup, raw agent conversation,
stdout/stderr trace, node_modules or unrelated personal file is included.
The real environment configs and secrets directories were not copied.

Public result projections omit conversation text, session IDs, absolute personal
paths, file-change details and output snippets. Input hashes and exact omitted
columns are recorded in `PUBLICATION_PROVENANCE.json`; source files are unchanged.
Synthetic OSEF canaries and fake key test strings were inspected as fixture data.
Signing tests generate key pairs at runtime; no real private key is archived.

The public `scripts/check_publication.py` scans all tracked/unignored candidate
files and every reachable historical Git blob for private-key blocks, common
provider/GitHub/AWS/Slack token formats, JWTs and credential-bearing URLs. The
preexisting history contained 22 unique blobs. No high-confidence credential
candidate was found. A supplementary literal credential-assignment review also
found no unclassified credential candidates. These heuristic checks are not a
formal guarantee of absence; do not reuse them as the only future security gate.

## Remaining gaps

Unrecovered: Scanner formal fixtures/harness/raw runs and complete failed-run
archive; row-level baseline ~60% and Output Guard ~6.7% evidence; matched early
runtime/version/configuration records; causal tool-allowlist effectiveness proof.
Human-in-the-loop is not established by REVIEW verdicts. Personal deployment
configuration is intentionally omitted. Historical DOCX/PPTX summaries and zip
duplicates are not uploaded as substitutes for missing raw data.

This publication preserves available work and makes gaps explicit. It does not
claim that the whole study is fully independently reproducible.
