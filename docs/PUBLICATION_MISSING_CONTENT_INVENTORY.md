# Publication inventory (before assembly)

Inspected 2026-10-24. Remote `main` and the clean Desktop publication checkout
both resolve to `48e8dbf2c691a57c646bbed06caa46c960cb2997`. There are no
unpublished commits in that checkout. Assembly uses a separate clone and branch
`codex/research-publication-completion`; the research checkout is not edited.

| Area | Already published | Missing / located material | Evidence boundary |
| --- | --- | --- | --- |
| Policy Integrity | Implementation, tests, controlled result CSV and notes | Pinned upstream integration patch | Preserve existing results unchanged |
| Trusted Rollback | Shared policy implementation, tests, results | Integration reproduction instructions | Preserve existing results unchanged |
| Plugin Verification | Implementation, tests, results and design | Pinned upstream integration patch | Preserve existing results unchanged |
| Prompt Injection | Nothing | Local evaluator, six attack fixtures, final analysis table with 18 trials | Baseline ~60% and Output Guard ~6.7% not yet verified; 18 trials is not 18 distinct fixtures |
| Agent Misoperation | Nothing | Local evaluator, fixtures and 60-run result tables | Need verify enum counts; REVIEW is not confirmed misoperation |
| Early defenses | Nothing | Local defense validation suite and result CSV | Historical summaries conflict; preserve failures and qualify simulations |
| Skill Scanner | Nothing | Modified scanner, four integration modules and five test files in research checkout | Original upstream commit is 090cb491227e45cdbdc0a65ea2718c8fe62461c9; files are not standalone |
| Scanner experiment | Nothing | Architecture, calibration and gap analysis notes | Historical temporary raw experiment directory not found; do not manufacture replacement records |
| Publication safety | Historic review only | New history/content scan and provenance manifest needed | Exclude credentials, auth state, logs, private conversations and unrelated workspace files |

Only explicit research files and safe structured result fields will be copied.
Source originals are preserved. Public result projections will be labeled as
derived, with input hashes and omitted columns; they are not complete raw traces.
No result will be inferred from a filename alone. Follow-up evidence and checks
are recorded in `PUBLICATION_VALIDATION.md` and the experiment READMEs.
