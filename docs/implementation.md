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

### Enabling and interpreting the four defenses

These instructions apply after installing the pinned patches in a disposable
upstream checkout; none changes the current security policy.

| Mechanism | Why this hook / check | Activation and limits |
| --- | --- | --- |
| Policy Integrity | `src/agents/workspace.ts` checks the bytes about to enter context, including cache hits, using `verifyPolicyFileContent` | Initialize trusted files with `pnpm openclaw security policy-integrity init --workspace /absolute/path/to/disposable/workspace`, then launch with `OPENCLAW_POLICY_INTEGRITY=1`. Protects AGENTS.md/SOUL.md, not every file; requires a trustworthy baseline and state store. |
| Trusted Rollback | The same policy module handles hash mismatch after recording BLOCK, using stored trusted content rather than learning the attacked file | Also set `OPENCLAW_POLICY_ROLLBACK=1`. Integrity must be enabled. Recovery does not make the already-blocked turn proceed; missing/invalid snapshots or recovery errors are not successful restores. |
| Plugin Verification | `src/plugins/loader.ts` checks trust before normal, runtime and CLI module imports, preventing evaluation before verification on those paths | Enroll a trusted Ed25519 public key with `pnpm openclaw security plugin-trust add-key --key-id <id> --publisher <label> --public-key <PEM-text>` and set `OPENCLAW_PLUGIN_VERIFICATION=1`. Packages need `openclaw.plugin.sig.json` signing the canonical manifest; use the source tests as a signing example. `--public-key` takes PEM text, not a filename. Bundled-origin plugins bypass this check. |
| Skill Scanner | Workspace/session/node-host/remote hooks reject BLOCK before exposure or distribution | Default on, or `OPENCLAW_SKILL_SECURITY_SCAN=1`; `0` bypasses the gates. REVIEW allows use with diagnostics; this is not a universal execution monitor. |

Plugin manifest coverage is limited to the extensions listed in
`src/plugin-verification/plugin-verification.ts` (.js/.mjs/.cjs/.ts/.mts/.cts/.json),
excluding node_modules and .git. Valid signatures do not imply safe behavior;
uncovered files, dependencies, host compromise and later mutation remain limits.
Never publish signing private keys or initialize baselines from unreviewed files.

Tests and patch commands: [integration guide](../patches/README.md). Policy and
rollback share `src/agents/policy-integrity.test.ts`; plugin checks use
`src/plugins/plugin-verification.test.ts`; Scanner has five archived test files.

## Safety boundary

This is static pre-exposure risk detection, not a universal execution reference
monitor. Scan/execute races, code outside scanned files, dynamic dependencies,
agent use of other tools and permissive REVIEW policy remain relevant risks.
No dedicated Scanner audit table or human approval state machine is implemented.
