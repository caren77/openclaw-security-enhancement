# Source Integration Points

This document records where the research modules connect to OpenClaw production runtime paths without copying those large production files into this repository.

## 1. Policy Integrity

Integration path: `src/agents/workspace.ts`

```text
readWorkspaceFileWithGuards()
→ read policy content
→ Policy Integrity verification
→ SHA-256 trusted baseline
→ PASS / POLICY_INTEGRITY_BLOCKED
```

Protected policy files:

- `AGENTS.md`
- `SOUL.md`

The verification decision is made before policy content is admitted to the Agent Context.

## 2. Trusted Rollback

Trusted Rollback integrates Policy Integrity, the state database, and security auditing.

```text
hash mismatch
→ BLOCK
→ audit
→ trusted snapshot restore
→ pinned-fd reread
→ SHA-256 re-verification
→ current turn remains blocked
→ next turn may load restored trusted policy
```

The recovery action does not turn the blocked current read into a successful read.

## 3. Plugin Verification

Integration path: `src/plugins/loader.ts`

```text
discover plugin
→ resolve runtime artifact
→ openRootFileSync
→ Plugin Verification
→ loadPluginModule()
```

Verification occurs before plugin module execution. An invalid or tampered candidate is rejected before `loadPluginModule()` evaluates it.

## Production Files Deliberately Excluded

Only the integration points are documented here. The following large OpenClaw production files are not copied:

- `src/agents/workspace.ts`
- `src/plugins/loader.ts`
- `src/cli/security-cli.ts`
- `src/state/openclaw-state-schema.sql`
- `src/state/openclaw-state-schema.generated.ts`
- `src/state/openclaw-state-db.generated.d.ts`
