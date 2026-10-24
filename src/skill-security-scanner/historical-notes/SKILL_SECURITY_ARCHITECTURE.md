# Skill Security Scanner Architecture

## Scope

This document records the real OpenClaw skill lifecycle and the enforcement point for
pre-execution static risk detection. The scanner is a heuristic risk detector, not a proof that a
skill is safe. Its decisions are `ALLOW`, `REVIEW`, and `BLOCK`.

## Skill layout and content

The canonical local skill is a directory containing `SKILL.md`. `SKILL.md` has frontmatter (at
minimum a name and description on the main workspace-loading path) plus Markdown instructions.
The directory may also contain referenced support files. The bundled `skills/` tree confirms that
real skills use:

- Markdown instructions and references (`SKILL.md`, `README.md`, `references/*.md`);
- JavaScript / TypeScript-family code (`.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, and related forms);
- shell scripts and executable files (`.sh`, files with a shell shebang, and extensionless bins);
- Python (`.py`);
- JSON, YAML, TOML, and other configuration/data files;
- prompt/instruction text and skill-specific workflow formats.

The scanner therefore must inspect the complete bounded skill directory, not only `SKILL.md` or
JavaScript files. It must not follow symlinks out of the already validated skill root.

## Discovery path

The primary OpenClaw runtime discovery path is in `src/skills/loading/workspace.ts`:

1. `loadSkillEntries()` resolves bounded discovery limits and trusted symlink target roots.
2. Its nested `loadSkills()` resolves each configured source root, discovers `SKILL.md` candidates,
   validates containment, and bounds recursive directory walks.
3. `loadContainedSkillRecords()` calls `loadSkillsFromDirSafe()` in
   `src/skills/loading/local-loader.ts`.
4. `loadSingleSkillDirectory()` reads `SKILL.md` through `openRootFileSync()`, parses frontmatter,
   and creates the in-memory `Skill` record. Reading/parsing is data processing and does not execute
   skill code.
5. `loadSkillEntries()` merges sources by name with this precedence (last wins): extra, bundled,
   managed, personal `.agents`, project `.agents`, workspace.

The discovered local roots are:

- bundled skills from `resolveBundledSkillsDir()`;
- configured `skills.load.extraDirs` and plugin-contributed skill directories;
- managed skills under the OpenClaw config directory (`skills/`);
- personal `~/.agents/skills`;
- project `<workspace>/.agents/skills`;
- project `<workspace>/skills`.

Plugin skill roots are resolved by `src/skills/loading/plugin-skills.ts`. Generated plugin skill
links under the OpenClaw config directory are additionally checked by
`loadGeneratedPluginSkillRecords()` before loading.

There is a secondary SDK/session resource path in `src/skills/loading/session.ts`.
`loadSkills()` / `loadSkillsFromDirInternal()` recursively discover `SKILL.md` (and explicit root
Markdown skill files), while `DefaultResourceLoader.updateSkillsFromPaths()` in
`src/agents/sessions/resource-loader.ts` exposes the resulting skills to an `AgentSession`.
Embedded OpenClaw runs disable ambient discovery on this resource loader and instead receive the
workspace snapshot described below, but the SDK path is still an execution-capable public path and
must enforce the same scanner decision.

## Remote node skill path

`src/node-host/skills.ts::scanNodeHostedSkills()` discovers named child directories under the node
host's managed skills directory, loads `SKILL.md`, and publishes bounded descriptors. The gateway
receives them through `src/skills/runtime/remote-skills.ts::replaceRemoteNodeSkills()`, parses them
in `prepareNodeSkills()`, and merges them with local entries in `mergeRemoteNodeSkillEntries()`.
Only `SKILL.md` content is sent to the gateway; referenced scripts remain on the node. Consequently,
the complete directory must be scanned on the node before publication, and the gateway should scan
the received instruction content again as a defense-in-depth check.

## Loading and registration path

The primary convergence point is the final `SkillEntry[]` produced by
`src/skills/loading/workspace.ts::loadSkillEntries()` and exposed by
`loadWorkspaceSkillEntries()` / `loadVisibleWorkspaceSkillEntries()`.

That same entry set feeds all important registrations:

- `resolveWorkspaceSkillPromptState()` builds the available-skills system-prompt catalog and the
  `resolvedSkills` runtime snapshot;
- `src/skills/discovery/command-specs.ts::buildWorkspaceSkillCommandSpecs()` registers user
  invocable skill slash commands and optional direct tool dispatch;
- `src/skills/loading/workspace.ts::syncSkillsToWorkspace()` copies selected skill directories into
  sandbox workspaces;
- `src/skills/runtime/embedded-run-entries.ts::resolveEmbeddedRunSkillEntries()` reconstructs
  runtime entries when a snapshot does not already carry resolved skills;
- session snapshot builders in `src/skills/runtime/session-snapshot.ts` cache the resolved set.

## Execution path

Skills are primarily instruction bundles rather than modules imported and executed by the loader.
The execution-relevant paths are:

1. `formatSkillsForPrompt()` publishes a skill's name, description, version, and `SKILL.md` path to
   the model.
2. The model reads the selected `SKILL.md` through the normal read tool. Exact remote `node://`
   skill content is served by `src/agents/agent-tools.read.ts::wrapReadToolWithSkillContent()`.
3. The model follows the skill instructions and may read or execute referenced support scripts
   through normal tools. Normal tool/sandbox/approval policy remains a separate enforcement layer.
4. A user slash command is resolved by
   `src/skills/discovery/chat-command-invocation.ts::resolveSkillCommandInvocation()`.
   `src/auto-reply/reply/get-reply-inline-actions.ts` either rewrites the user message to activate
   the skill or directly invokes a declared tool after `resolveSkillDispatchTools()` applies the
   normal tool policy pipeline.

## Existing scanner and gap

`src/skills/security/scanner.ts` already contains bounded JavaScript/TypeScript heuristics used by
security audit, install-release tests, and Skill Workshop proposal checks. Before this project it:

- scanned only JavaScript/TypeScript-family extensions in directory mode;
- had no `ALLOW` / `REVIEW` / `BLOCK` decision model;
- was not called by workspace loading, command registration, snapshot construction, node skill
  publication, or the SDK/session resource loader.

It therefore provided useful audit evidence but did not guarantee pre-execution enforcement.

## Selected enforcement point

The main enforcement point is the end of `loadSkillEntries()`, after precedence resolution and
frontmatter parsing but before the returned entries reach prompt rendering, command registration,
sandbox synchronization, or runtime snapshots.

Reasons:

- all local discovery sources converge there;
- only winning entries are scanned, avoiding duplicate work on shadowed skills;
- canonical/validated roots and bounded loading limits are already available;
- parsing `SKILL.md` is non-executing, so the scan still occurs before any skill instruction is
  exposed to an agent or any support code can run;
- filtering a `BLOCK` entry at this point removes it consistently from every downstream consumer,
  while `REVIEW` entries can remain visible with a security warning for operator review.

Equivalent checks are required at two non-converging boundaries:

- `src/skills/loading/session.ts` before a skill is returned to `DefaultResourceLoader`;
- `src/node-host/skills.ts` before node skills are published, plus received-content validation in
  `src/skills/runtime/remote-skills.ts`.

## Pre-execution guarantee

For local workspace/managed/bundled/plugin skills, a `BLOCK` decision is enforced before the skill
can be added to the agent prompt, registered as a slash command, copied into a sandbox, or included
in a fresh runtime snapshot. The SDK/session and node-host boundaries provide the same guarantee for
their distinct loading paths.

The guarantee is bounded to the files visible during the scan. It does not prove safety, prevent a
file from changing after the scan, or replace runtime sandbox/tool/approval controls. Existing
watch/snapshot invalidation causes changed skills to be reloaded and rescanned; eliminating every
possible time-of-check/time-of-use race would require immutable content-addressed materialization,
which is outside this static scanner's scope.

## Decision policy

- `ALLOW`: no recognized risky behavior and the bounded scan completed.
- `REVIEW`: one or more suspicious primitives or sensitive accesses were found, or the scan could
  not cover the complete bounded input. The skill remains loadable but emits a redacted warning.
- `BLOCK`: a high-confidence dangerous rule (for example prompt-security override, pipe-to-shell,
  broad destructive deletion, or likely secret exfiltration), or a configured aggregate risk
  threshold, is reached. The skill is omitted before registration/exposure.

Findings contain rule id, category, severity, relative file, line, and redacted/truncated evidence.
They never include secret values.

## Implemented scanner API

The implementation extends the existing owner module `src/skills/security/scanner.ts` instead of
creating a second scanner under `src/security/`. Keeping one scanner avoids divergent audit and
runtime rules while preserving the existing `scanSource()`, `scanSkillContent()`, and
`scanDirectoryWithSummary()` callers.

The pre-execution API is:

- `scanSkillDirectorySync()` for a bounded complete local skill package;
- `scanSkillSecurityContent()` for remote or virtual `SKILL.md` content;
- `evaluateSkillSecurityFindings()` for default or caller-supplied decision policy.

It scans recognized code, shell, Markdown/prompt, JSON/YAML/TOML/config, known extensionless config,
and executable files. Hidden payloads are included; dependency/VCS trees (`node_modules`, `.git`,
and `.svn`) and symlinks are not followed. The default policy blocks high-confidence rule IDs or an
aggregate risk score of 12, reviews lower-confidence findings and incomplete scans, and allows a
complete scan with no findings.

The runtime integrations log only skill identity/path and rule IDs. Evidence remains bounded and
credential-redacted inside the report and is not written to the runtime warning log.
