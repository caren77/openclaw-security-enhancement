# Policy Rollback Flag Bugfix

## Bug description

The rollback comparison experiment showed that `OPENCLAW_POLICY_ROLLBACK` being unset still caused trusted snapshot recovery on every integrity mismatch. The no-rollback condition therefore recovered 6/6 poisoned files instead of leaving them poisoned and blocked.

## Root cause

`src/agents/policy-integrity.ts`, function `verifyPolicyFileContent()`, unconditionally called `recoverFromTrustedSnapshot()` after writing the `BLOCK` audit event when `baseline.sha256 !== actualSha256`. No rollback feature-flag predicate existed.

## Fix

Added `isPolicyRollbackEnabled()` using the repository `parseBooleanValue()` convention. Recovery is now called only when the parsed value is true. Integrity remains fail-closed and throws `POLICY_INTEGRITY_BLOCKED` in both cases. With integrity disabled, rollback has no effect and integrity is not implicitly enabled.

Accepted values: unset, empty string, `0`, and `false` are false; `1` and `true` are true (the shared parser also accepts its standard true/false aliases).

## Regression tests

Added parsing coverage and R-FLAG-01/02/03/04/05 behavior coverage in `src/agents/policy-integrity.test.ts`: unset/`0`/`false` produce only `BLOCK` and preserve poisoned disk content; enabled values recover and audit `RECOVERED`.

## Verification

- Policy Integrity, Workspace, and Security CLI tests: 159/159 passed.
- `pnpm db:kysely:check`: passed.
- `pnpm tsgo:core`: passed.
- `pnpm build`: passed.
- `pnpm lint`: blocked by pre-existing UI i18n orphan keys, unrelated to this change.

## Experiments

Before fix: no-rollback 6/6 FAIL (automatic recovery); rollback 6/6 PASS.

After fix: no-rollback 6/6 PASS; rollback 6/6 PASS. Final artifacts are retained at `<TEMP_EXPERIMENT_DIR>/`.

