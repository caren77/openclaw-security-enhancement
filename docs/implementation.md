# Implementation and integration boundaries

The new publication exports existing research code; it does not change Scanner
rules or add a new runtime feature. The exact base and patches are documented in
`../patches/README.md`. Prior source files and CSVs remain untouched.

## Scanner

Paths below are relative to `../src/skill-security-scanner/upstream/`.

- `src/skills/security/scanner.ts:571`: default blocking rule set; line 584:
  default score threshold 12; line 587: flag parser.
- `src/skills/security/scanner.ts:1012`: `evaluateSkillSecurityFindings` sums
  critical=4, warn=2, info=0, then checks rule membership OR threshold. Policy
  overrides are an API argument, not a documented end-user approval interface.
- `src/skills/security/scanner.ts:798`: textual combination rules. Proximity
  windows are not a dataflow graph or proof that a secret reaches a network sink.
- `src/skills/security/scanner.ts:910`: per-content finding deduplication.
- `src/skills/loading/workspace.ts:1283`: filter accepted records before mapping
  Skill entries. Warning logging is deduplicated in process.
- `src/skills/loading/session.ts:274`: package scan for SKILL.md, content scan for
  other session files, error/rejection for BLOCK and warning for REVIEW.
- `src/node-host/skills.ts:139`: node-host directory scan before distribution.
- `src/skills/runtime/remote-skills.ts:34`: remote Markdown-only scan before
  preparing entries; unseen remote scripts cannot be inspected at this point.

Default-on parsing accepts 1/true/on and 0/false/off. Invalid explicit flag input
throws. Disabling the runtime gate does not disable standalone scan functions
or the preexisting audit API. REVIEW does not stop execution. Diagnostics omit
source evidence in these integrations and expose rule IDs; the scanner also
redacts recognized literal secret evidence. These are not guarantees that all
possible secrets are recognized.

## Existing defenses

The integration patch wires the archived policy implementation into
`src/agents/workspace.ts`, plugin trust checks into three loader entry paths,
and baseline/key-management commands into `src/cli/security-cli.ts`. SQLite
schema, migrations and generated types are included. Trusted Rollback shares
the policy module. Historical standalone copies are retained for continuity;
the pinned patch is the authoritative integration artifact for this export.

## Safety boundary

This is static pre-exposure risk detection, not a universal execution reference
monitor. Scan/execute races, code outside scanned files, dynamic dependencies,
agent use of other tools and permissive REVIEW policy remain relevant risks.
No dedicated Scanner audit table or human approval state machine is implemented.
