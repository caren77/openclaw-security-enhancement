# Policy Integrity Guard Research Notes

## 1. Vulnerability

The motivating attack path is persistent policy poisoning:

1. An attacker supplies a Developer Impersonation or prompt-injection payload.
2. The Agent is induced to modify `AGENTS.md` or `SOUL.md`.
3. A later turn reloads the modified bootstrap file.
4. The poisoned policy becomes persistent context and can influence later Agent behavior.

The vulnerability is not merely that a file can be written. The security boundary fails when a later runtime load treats attacker-modified policy bytes as trusted instructions.

## 2. Original OpenClaw Flow

`loadWorkspaceBootstrapFiles()` enumerated bootstrap files and called `readWorkspaceFileWithGuards()`. That reader preserved the workspace boundary, rejected unsafe filesystem aliases through `openRootFile()`, pinned a file descriptor, retried transient I/O errors, and cached content by canonical path/inode metadata. It did not authenticate `AGENTS.md` or `SOUL.md` content against an operator-approved value.

Original flow:

```text
workspace file -> openRootFile -> identity cache -> read/cache -> Agent context
```

These filesystem guards prevent several path and race attacks, but they do not detect an authorized-in-filesystem yet unauthorized-in-policy modification.

## 3. Modified OpenClaw Flow

```text
AGENTS.md / SOUL.md
  -> openRootFile (workspace boundary + pinned fd)
  -> read bytes or obtain identity-matched cached bytes
  -> SHA-256
  -> lookup operator-initialized baseline in shared state SQLite
  -> match: cache/return to Agent context
  -> missing or mismatch: append audit event and throw POLICY_INTEGRITY_BLOCKED
```

Files other than `AGENTS.md` and `SOUL.md` retain their original behavior. Enforcement is opt-in with `OPENCLAW_POLICY_INTEGRITY=1`.

## 4. Source Files Modified

- `src/agents/workspace.ts`: runtime enforcement at the guarded bootstrap read boundary.
- `src/cli/security-cli.ts`: explicit baseline initialization/update command.
- `src/state/openclaw-state-schema.sql`: baseline and audit tables.
- `src/state/openclaw-state-schema.generated.ts`: generated runtime schema.
- `src/state/openclaw-state-db.generated.d.ts`: generated Kysely types.
- `src/agents/policy-integrity.ts`: integrity algorithm and persistence operations.
- `src/agents/policy-integrity.test.ts`: isolated security tests.
- `src/state/openclaw-state-db.ts`: additive migration for trusted snapshot columns.

## 5. Policy Integrity Algorithm

1. Check whether enforcement is enabled and the basename is `AGENTS.md` or `SOUL.md`.
2. Canonicalize the workspace with `realpath` to obtain the baseline key.
3. Compute SHA-256 over the exact string about to be returned to the Agent.
4. Read the expected hash from `policy_integrity_baselines`, keyed by canonical workspace and filename.
5. If no row exists, fail closed and record `baseline_missing`.
6. If hashes differ, fail closed and record `hash_mismatch`.
7. Only matching content reaches the workspace cache/return path.

The baseline is never generated during startup or runtime verification.

## 6. Trusted Policy Snapshot and Rollback

Each explicit baseline initialization now stores both the SHA-256 and the exact trusted `AGENTS.md`/`SOUL.md` content in `policy_integrity_baselines.trusted_content`. Existing rows created before this feature have an empty snapshot and cannot be silently used for recovery.

On a hash mismatch, the runtime performs this sequence:

```text
BLOCK audit
  -> atomically replace the policy path from trusted_content
  -> reopen through openRootFileSync (pinned fd)
  -> read and SHA-256 the restored bytes
  -> RECOVERED audit when the hash matches
  -> RECOVERY_FAILED audit otherwise
  -> keep the current turn blocked
```

Recovery never treats the attacked file as a new snapshot. A new trusted version requires the explicit `security policy-integrity init --force` operator action. The next turn can load the restored file after normal integrity verification.

## 7. SHA-256 Baseline Design

Initialize a workspace explicitly:

```bash
pnpm openclaw security policy-integrity init --workspace /absolute/path/to/workspace
```

Explicitly approve changed policies:

```bash
pnpm openclaw security policy-integrity init --workspace /absolute/path/to/workspace --force
```

Enable enforcement for the OpenClaw process:

```bash
OPENCLAW_POLICY_INTEGRITY=1 pnpm openclaw gateway
```

Baselines are stored in `OPENCLAW_STATE_DIR/openclaw.sqlite` (normally `~/.openclaw/openclaw.sqlite`), not in the Agent workspace. OpenClaw already owns and permission-hardens this database: the default state directory is mode `0700` and the database is mode `0600`. This keeps baselines outside workspace-only file tools and follows the repository's database-first state architecture.

This location is more trustworthy than a workspace sidecar, but it is not a hardware trust root. A process with the same OS account and unrestricted host filesystem or database access can still alter it.

## 8. Cache Security Consideration

Both paths converge on `verifyPolicyFileContent()` before returning:

- Cache miss: bytes are read once from the descriptor pinned by `openRootFile()`, verified, and only then cached.
- Cache hit: the identity-matched cached bytes are verified again against the current baseline before return.

A cache hit therefore cannot bypass integrity enforcement. If an attacker changes file content while exactly preserving the cache identity, OpenClaw can return only the previously verified cached bytes, not the new unverified bytes. A cold read or an identity change reads the pinned descriptor and verifies the resulting content.

## 9. Fail-Closed Design

With enforcement enabled:

- baseline present + matching hash: allow;
- baseline present + mismatching hash: block;
- baseline absent: block with `Policy integrity enabled but trusted baseline is missing for <file>.`;
- database/audit failure during verification: no policy content is returned.

The main bootstrap loader throws `PolicyIntegrityError` with code `POLICY_INTEGRITY_BLOCKED`. It does not silently mark an integrity failure as a normal missing file.

With enforcement disabled, no baseline database lookup or hash enforcement occurs and the original bootstrap behavior remains.

## 10. Audit Log Design

Blocked and recovery events are appended to `policy_integrity_audit_events` in the shared SQLite state database. Each row stores:

- ISO timestamp;
- canonical workspace key;
- filename;
- expected SHA-256 (nullable for missing baseline);
- actual SHA-256;
- action `BLOCK`, `RECOVERED`, or `RECOVERY_FAILED`;
- reason `baseline_missing`, `hash_mismatch`, or `recovery`;
- recovery error when recovery fails.

The audit row never stores policy content, prompts, API keys, or tokens. The table is not append-only against a same-user host compromise; see limitations.

## 11. Unit Test Results

Twelve focused test cases cover non-policy files, matching `AGENTS.md`, matching `SOUL.md`, both mismatch/recovery cases, missing baseline, disabled enforcement, cache-hit re-verification, audit fields, absence of policy content in audit rows, missing snapshots, and explicit `--force` updates.

Observed result: 10 cases executed in two configured test projects, 20/20 executions passed. Workspace and Security CLI regression run: 117/117 passed. Kysely schema generation verification, core TypeScript, core test TypeScript, scoped lint, Kysely guardrails, and full build passed.

## 12. Security Limitations

- The baseline is protected by OS permissions and workspace separation, not by a separate principal, TPM, signature, or remote transparency service. Unrestricted host tools under the same OS user can modify `openclaw.sqlite`.
- The audit table is locally mutable by the same OS user/database owner. It provides useful research evidence but not tamper-evident logging.
- `OPENCLAW_STATE_DIR` controls which state database is trusted. An attacker able to replace process environment/configuration can redirect the trust store.
- SHA-256 authenticates bytes only relative to the stored baseline; it does not identify who approved an update. `--force` is an explicit operator action but has no additional authentication ceremony.
- Baselines are keyed by canonical workspace path. Moving/copying a workspace requires explicit initialization in its new canonical location.
- The current guard protects bootstrap files loaded through `readWorkspaceFileWithGuards()`. Other code paths that read similarly named files directly are outside this research scope.
- Repeated verification adds a SQLite lookup and SHA-256 computation on protected bootstrap reads. This is intentional for the requested cache-hit invariant.
- Recovery is best-effort: if the snapshot is absent, atomic replacement fails, boundary validation fails, or the restored hash differs, the current turn remains blocked and `RECOVERY_FAILED` is recorded.

## 13. Future Improvements

- Sign baseline records with a key held outside the Agent runtime, or anchor hashes in a TPM/keychain-backed operator service.
- Stream audit events to an append-only remote collector or hash-chain local records.
- Bind baseline updates to authenticated operator approvals and record approver identity/reason.
- Replace the environment flag with a reviewed typed configuration surface and migration/doctor support if promoted beyond research use.
- Add a startup preflight that reports all protected-workspace baseline status before serving turns without regenerating baselines.
- Extend protected-file policy through a typed allowlist only after reviewing all bootstrap owners and compatibility impact.
