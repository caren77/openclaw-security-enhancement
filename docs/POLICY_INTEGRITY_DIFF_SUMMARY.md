# Policy Integrity Diff Summary

This document reports only the Policy Integrity work. Pre-existing Docker/sandbox modifications in the worktree are intentionally excluded from the scoped counts and remain untouched.

## Files

Source files modified:

- `src/agents/workspace.ts`
- `src/cli/security-cli.ts`
- `src/state/openclaw-state-schema.sql`
- `src/state/openclaw-state-schema.generated.ts`
- `src/state/openclaw-state-db.generated.d.ts`
- `src/state/openclaw-state-db.ts`

Source/test files added:

- `src/agents/policy-integrity.ts`
- `src/agents/policy-integrity.test.ts`

Research documents added:

- `POLICY_INTEGRITY_RESEARCH.md`
- `POLICY_INTEGRITY_EXPERIMENT_PLAN.md`
- `POLICY_INTEGRITY_DIFF_SUMMARY.md`

## Counts

- Added cumulative Policy Integrity + Rollback code/test lines: 708
- Deleted code/test lines: 10
- Focused Policy Integrity test cases: 12
- Test executions: 24/24 passed across two configured projects
- Workspace + Security CLI regression tests: 117/117 passed

## Git Diff Stat

`git diff --stat` does not include untracked files until they are staged. The final report records both the literal command output and a complete scoped stat that includes new untracked Policy Integrity files without staging them.

```text
Literal whole-worktree `git diff --stat` (tracked files only; includes pre-existing work):

 docker-compose.yml                                 | 13 ++--
 packages/agent-core/src/harness/env/nodejs.ts      | 68 ++++++++++++++++++++
 src/agents/sandbox/browser.ts                      | 48 +++++++++-----
 .../sandbox/docker.config-hash-recreate.test.ts    | 38 +++++++++++
 src/agents/sandbox/docker.ts                       | 73 +++++++++++++++++-----
 src/agents/sandbox/workspace-mounts.ts             | 13 +++-
 src/agents/workspace.ts                            | 37 ++++++++---
 src/cli/security-cli.ts                            | 33 ++++++++++
 src/state/openclaw-state-db.generated.d.ts         | 21 +++++++
 src/state/openclaw-state-schema.generated.ts       | 23 +++++++
 src/state/openclaw-state-schema.sql                | 23 +++++++
 12 files changed, 353 insertions(+), 45 deletions(-)

Complete scoped implementation/test stat (includes untracked new source/test files):

 src/agents/policy-integrity.test.ts           | 241 ++++++++++++++++++++++++++++++
 src/agents/policy-integrity.ts                | 332 ++++++++++++++++++++++++++++++++++++
 src/agents/workspace.ts                       |  37 +++--
 src/cli/security-cli.ts                       |  33 ++++
 src/state/openclaw-state-db.generated.d.ts    |  23 +++
 src/state/openclaw-state-db.ts                 |   2 +
 src/state/openclaw-state-schema.generated.ts  |  25 +++
 src/state/openclaw-state-schema.sql           |  25 +++
 8 files changed, 708 insertions(+), 10 deletions(-)
```
