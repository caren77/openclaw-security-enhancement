# Skill Security Scanner source archive

This directory preserves ten actual post-change upstream files, their license,
and three historical design/calibration notes. Apply the pinned patch described
in [the integration guide](../../patches/README.md); do not run these files as a
standalone application or copy just scanner.ts into a different OpenClaw version.

## Source map (relative to upstream/)

| File / function | Role |
| --- | --- |
| src/skills/security/scanner.ts / scanSkillSecurityContent | Scan supplied text; returns findings and a policy decision |
| src/skills/security/scanner.ts / scanSkillDirectorySync | Traverse supported Skill package files, scan contents and summarize coverage |
| src/skills/security/scanner.ts / evaluateSkillSecurityFindings | Sum severity weights and apply blocking-rule / threshold policy |
| src/skills/security/scanner.ts / isSkillSecurityScanEnabled | Shared feature-flag parsing at runtime integration points |
| src/skills/loading/workspace.ts / loadSkillEntries | Filter merged Skill records before producing usable entries |
| src/skills/loading/session.ts / loadSkillFromFile | Reject blocked file content before returning session Skill objects |
| src/node-host/skills.ts / scanNodeHostedSkills | Reject blocked packages before node-host distribution |
| src/skills/runtime/remote-skills.ts / prepareNodeSkills | Scan received Markdown before preparing remote entries |

Each integration has a corresponding test file. The existing legacy
`scanDirectoryWithSummary` audit API is distinct from the new decision-producing
API. A CLI audit warning is not itself proof of pre-execution enforcement.

## Decision semantics

`score = 4 * critical_count + 2 * warn_count`. Info findings contribute zero.
The default threshold is 12, but a default blocking rule blocks even below 12.
The scanner de-duplicates findings by rule/file/line in its content collection;
the evaluator itself sums the supplied array. No score cap is applied.

Direct-block rules include `dangerous-exec`, `dynamic-code-execution`,
`base64-execute`, `destructive-delete`, `runtime-download-execute`,
`shell-pipe-to-shell`, `secret-exfiltration`, `likely-secret-exfiltration` and
three prompt-injection rules (ignore-instructions, security-disable, secret-theft).
Nonblocking findings and incomplete scans are REVIEW, and REVIEW is allowed.
Thus a lone sensitive-path warning normally scores 2 and remains REVIEW.

The scoring constants and rule policy are heuristic, not a paper-derived or
statistically validated risk model. Legitimate process execution can be blocked;
indirect/obfuscated malicious behavior can be missed. No new rules, scores or
thresholds were introduced during publication.

## Guarantees not claimed

The four gates precede exposure/registration along those paths. They do not
mediate arbitrary later file reads or tool execution, analyze all remote package
files, prevent post-scan replacement, or prove code safety. Combination rules
correlate text, not semantic dataflow. Runtime diagnostics are not a dedicated
durable audit store. See [limitations](../../docs/limitations.md).

Historical notes retain contemporaneous wording, including experiment claims.
The current [experiment evidence status](../../experiments/skill-security-scanner/README.md)
qualifies those claims; missing raw runs were not recreated.
