# OpenClaw Security Enhancement

**Security Risks and Defense Mechanisms for Local AI Agents**

An independent undergraduate summer research archive based on
[OpenClaw](https://github.com/openclaw/openclaw), not an official OpenClaw release.
It separates early risk experiments from later source-level defenses. Controlled
test outcomes are not guarantees of safety in real deployments.

## Research background and objectives

Local agents can read files, invoke tools and load third-party extensions.
Untrusted instructions, overly broad permissions and modified policy or extension
files can cross trust boundaries. This project investigates prompt injection and
agent misoperation, then develops Policy Integrity, Trusted Rollback, Plugin
Verification and a Skill Security Scanner.

## Threat model

In scope: adversarial instructions in task documents or Skills; unintended file
changes; tampered policy files; untrusted or modified plugin packages; risky Skill
code before prompt exposure or distribution.

Out of scope: a compromised host/root account, compromised trusted key store,
proof of semantic correctness, complete dataflow analysis, and universal
prevention of all agent-initiated shell execution. A signed publisher can still
publish dangerous code. Signature verification and static risk detection answer
different questions.

## Experimental environment

- Source integration base: OpenClaw commit
  `090cb491227e45cdbdc0a65ea2718c8fe62461c9`.
- Early Python harnesses require Python 3.11+; the publication checks used Python
  3.12. These earlier experiments do **not** have a verified OpenClaw commit pin.
- The recovered final prompt-injection cohort records provider `deepseek`,
  model `deepseek-v4-flash`, sandbox mode `all`, sandboxed `true` in all 18
  raw result metadata records. This is recorded metadata, not independently
  verified provider identity or a causal proof of sandbox efficacy.
- Agent credentials, Docker/auth configuration, private workspace files and raw
  agent conversations are intentionally not published. Environment differences
  prevent claims of an otherwise-identical baseline/hardened comparison.

## Early experiments

### Prompt Injection

[Harness, six fixtures and public results](experiments/prompt-injection/README.md).
The recovered cohort has **6 distinct fixtures × 3 repetitions = 18 trials**,
not 18 distinct attacks. Its analysis defines attack success as a leaked
synthetic canary. All 18 final records report no canary leakage and no
`exec/write/edit` calls. Sensitive read paths remain unknown.

The requested baseline “approximately 60%” and Output Guard “approximately
6.7%” lack recovered row-level evidence. They are not presented as verified
results. The observed 0/18 dangerous calls alone does not establish that a tool
allowlist caused that outcome.

### Agent Misoperation

[Evaluator, 20 prompts and public results](experiments/agent-misoperation/README.md).
20 prompts × 3 runs give 60 records. The evaluator compares file hashes and
prompt-derived permitted targets. REVIEW represents insufficient evidence about
scope access, not a confirmed misoperation or completed human approval.

### Early defense validation

[Suite and public results](experiments/early-defenses/README.md) retain successful,
failed and inconclusive observations. These early HMAC/rollback/sandbox
experiments are not the later source-integrated mechanisms. The recovered
20-row CSV has 13 PASS, 3 REVIEW, 3 FAIL and 1 ERROR. Its historical summary
incorrectly reports total 1; the discrepancy is documented, not silently erased.

## Source-level defenses

| Mechanism | Purpose | Implementation and evidence |
| --- | --- | --- |
| Policy Integrity Guard | Verify policy bytes against trusted SHA-256 baselines before context loading | [Source](src/policy-integrity/policy-integrity.ts), [design](docs/POLICY_INTEGRITY_RESEARCH.md) |
| Audit + Trusted Rollback | Record integrity events and restore trusted policy content on detected drift | [Shared implementation](src/trusted-rollback/README.md), [rollback notes](docs/POLICY_ROLLBACK_BUGFIX.md) |
| Plugin Verification | Check package manifest hashes and trusted publisher signatures before module import | [Source](src/plugin-verification/plugin-verification.ts), [design](docs/PLUGIN_VERIFICATION_DESIGN.md) |
| Skill Security Scanner | Static pre-exposure risk detection for code, scripts, configuration and instructions | [Full integration snapshot and tests](src/skill-security-scanner/README.md) |

### Skill Security Scanner

The archive includes the actual scanner plus workspace, session, node-host and
remote-skill integration changes and their tests, not an isolated executable.
Detected categories include command execution, sensitive access, suspected
exfiltration, dynamic execution and prompt injection, with heuristic combination
rules.

Default score: `4 × critical findings + 2 × warn findings + 0 × info findings`.
A configured blocking rule **or** score ≥ 12 produces BLOCK. Otherwise findings
or incomplete coverage produce REVIEW; no findings and complete coverage produce
ALLOW. REVIEW is currently allowed with diagnostics, not an approval workflow.

The weights and threshold are **engineering heuristics**, not derived from a
paper or statistically calibrated dataset. Direct execution and dynamic
evaluation were promoted to default blocking rules during small-corpus
calibration. Combination rules use textual context, not proven dataflow.
The runtime integrations emit warnings/diagnostics; they do not implement a
dedicated durable Scanner audit database.

`OPENCLAW_SKILL_SECURITY_SCAN=0|false|off` bypasses the integration checks;
`1|true|on` enables them; unset defaults on; invalid explicit values throw.
Direct scanning APIs remain callable regardless of the integration feature flag.
See [implementation boundaries](docs/implementation.md).

## Experimental results and evidence status

| Experiment | Recovered result | Evidence status / qualification |
| --- | --- | --- |
| Prompt injection final cohort | 0/18 canary leaks; 18 SAFE_REFUSAL; dangerous tool calls 0/18 | Final analysis table checked against 18 per-run records; not a controlled defense comparison |
| Agent misoperation | SAFE 28, REVIEW 15, MISOPERATION 17, ERROR 0; MSR 28.3% | Recovered 60-row final CSV; REVIEW excluded from numerator |
| Early defenses | PASS 13, REVIEW 3, FAIL 3, ERROR 1 | Recovered 20-row CSV; mixed local checks and agent observations |
| Policy Integrity | Baseline 6/6 successes, hardened 6/6 blocks | Existing published controlled records, retained unchanged |
| Trusted Rollback | Without rollback: 0/6 recovery; with rollback: 6/6 recovery; both block the first turn 6/6 | Existing published controlled records, retained unchanged |
| Plugin Verification | Baseline 6/6 executions, hardened 6/6 blocks | Existing published controlled records, retained unchanged |
| Scanner historical experiment | Reported detection 6/6, BLOCK 5/6, residual 1/6; benign BLOCK 0/6; bundled BLOCK 0/51 | **Unverified historical summary**: original fixtures, harness and per-run results not recovered |

For Scanner, 100% reported detection must not be read as 100% blocking.
A harmless execution marker is not evidence of actual secret theft or destructive
payload execution. Calibration and evaluation on the same tiny corpus do not
estimate generalization. [Evidence gaps](experiments/skill-security-scanner/README.md).

## Source code integration

Apply the [pinned patches](patches/README.md) to a separate clean upstream
checkout. The existing-security patch contains the policy/plugin/state/CLI
integration; the Scanner patch contains all ten changed implementation/test
files. Upstream files are dependencies, not vendored standalone replacements.
Additional experimental file-access and Docker host-path changes are preserved
in a separately labeled [optional prototype patch](patches/EXPERIMENTAL_SANDBOX.md),
not treated as Scanner dependencies or proven security boundaries. Personal
Docker deployment configuration is excluded.

## Reproduction instructions

Offline public statistics and provenance checks (no agent calls):

```sh
python3 -B scripts/check_publication.py
(cd experiments/agent-misoperation && python3 -B -m unittest test_evaluator -v)
(cd experiments/early-defenses && python3 -B test_suite.py)
```

See [patch application and targeted OpenClaw tests](patches/README.md) and the
individual experiment READMEs. Live experiments require an explicitly configured
disposable sandbox and credentials supplied outside Git. Do not run historical
harnesses against a personal workspace. Missing historical Scanner records
cannot be recreated by rerunning tests and relabeling them as historical data.

## Limitations

Small, selected datasets; correlated repeated trials; missing historical
environments; incomplete tool arguments; regex false positives/negatives;
heuristic scores; REVIEW remains permissive; no proof against time-of-check /
time-of-use replacement or arbitrary direct tool execution. Early defense
failures are preserved. [Detailed limitations](docs/limitations.md).

## Future work

Recover missing raw records; build an independent held-out corpus; calibrate
scores against explicit costs; add syntax/dataflow-aware analysis, bounded
approval workflows, durable scanner audit events and runtime confinement.
These are future work, not implemented guarantees.

## Archive and licensing

[Missing-content inventory](docs/PUBLICATION_MISSING_CONTENT_INVENTORY.md),
[provenance hashes](docs/PUBLICATION_PROVENANCE.json),
[publication validation](docs/PUBLICATION_VALIDATION.md).
The [previous README](README_PRE_PUBLICATION.md), existing results and
historical design notes are preserved. New evidence qualifications take
precedence over older unsupported claims; archival notes are not new test runs.

The original [LICENSE](LICENSE) and copyright notices are retained.
[OpenClaw third-party notices](THIRD_PARTY_NOTICES.md) and the
[upstream license](src/skill-security-scanner/UPSTREAM_LICENSE) accompany exports.
