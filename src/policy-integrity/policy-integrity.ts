// Protects workspace policy files with operator-initialized SHA-256 baselines.
import { createHash } from "node:crypto";
import syncFs from "node:fs";
import path from "node:path";
import { openRootFile, openRootFileSync } from "../infra/boundary-file-read.js";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import { replaceFileAtomicSync } from "../infra/replace-file.js";
import { parseBooleanValue } from "../utils/boolean.js";
import type { DB as OpenClawStateKyselyDatabase } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
} from "../state/openclaw-state-db.js";

const PROTECTED_POLICY_FILENAMES = new Set(["AGENTS.md", "SOUL.md"]);
const MAX_POLICY_FILE_BYTES = 2 * 1024 * 1024;

type PolicyIntegrityDatabase = Pick<
  OpenClawStateKyselyDatabase,
  "policy_integrity_audit_events" | "policy_integrity_baselines"
>;

type PolicyIntegrityAuditAction = "BLOCK" | "RECOVERED" | "RECOVERY_FAILED";

export type PolicyIntegrityFailureReason = "baseline_missing" | "hash_mismatch";
type PolicyIntegrityAuditReason = PolicyIntegrityFailureReason | "recovery";

export class PolicyIntegrityError extends Error {
  readonly code = "POLICY_INTEGRITY_BLOCKED";
  readonly reason: PolicyIntegrityFailureReason;
  readonly file: string;

  constructor(params: { file: string; reason: PolicyIntegrityFailureReason; message: string }) {
    super(params.message);
    this.name = "PolicyIntegrityError";
    this.file = params.file;
    this.reason = params.reason;
  }
}

export function isPolicyIntegrityEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.OPENCLAW_POLICY_INTEGRITY === "1";
}

export function isPolicyRollbackEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return parseBooleanValue(env.OPENCLAW_POLICY_ROLLBACK) === true;
}

export function isProtectedPolicyFile(filePath: string): boolean {
  return PROTECTED_POLICY_FILENAMES.has(path.basename(filePath));
}

export function computePolicySha256(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function canonicalWorkspaceKey(workspaceDir: string): string {
  return syncFs.realpathSync.native(path.resolve(workspaceDir));
}

function writeAuditEvent(params: {
  workspaceKey: string;
  file: string;
  expectedSha256: string | null;
  actualSha256: string;
  reason: PolicyIntegrityAuditReason;
  action: PolicyIntegrityAuditAction;
  recoveryError?: string | null;
  env: NodeJS.ProcessEnv;
}): void {
  runOpenClawStateWriteTransaction(
    (database) => {
      const db = getNodeSqliteKysely<PolicyIntegrityDatabase>(database.db);
      executeSqliteQuerySync(
        database.db,
        db.insertInto("policy_integrity_audit_events").values({
          timestamp: new Date().toISOString(),
          workspace_key: params.workspaceKey,
          file_name: params.file,
          expected_sha256: params.expectedSha256,
          actual_sha256: params.actualSha256,
          action: params.action,
          reason: params.reason,
          recovery_error: params.recoveryError ?? null,
        }),
      );
    },
    { env: params.env },
  );
}

function recoverFromTrustedSnapshot(params: {
  filePath: string;
  workspaceDir: string;
  file: string;
  expectedSha256: string;
  trustedContent: string;
  env: NodeJS.ProcessEnv;
}): "recovered" | "failed" {
  if (!params.trustedContent) {
    writeAuditEvent({
      workspaceKey: canonicalWorkspaceKey(params.workspaceDir),
      file: params.file,
      expectedSha256: params.expectedSha256,
      actualSha256: computePolicySha256(params.trustedContent),
      reason: "hash_mismatch",
      action: "RECOVERY_FAILED",
      recoveryError: "trusted snapshot is missing",
      env: params.env,
    });
    return "failed";
  }
  try {
    replaceFileAtomicSync({
      filePath: params.filePath,
      content: params.trustedContent,
      mode: 0o600,
      tempPrefix: ".openclaw-policy-recovery",
      copyFallbackOnPermissionError: true,
    });
    const opened = openRootFileSync({
      absolutePath: params.filePath,
      rootPath: params.workspaceDir,
      boundaryLabel: "workspace root",
      maxBytes: MAX_POLICY_FILE_BYTES,
    });
    if (!opened.ok) {
      throw new Error("restored policy file failed workspace boundary validation");
    }
    try {
      const restored = syncFs.readFileSync(opened.fd, "utf-8");
      const actualSha256 = computePolicySha256(restored);
      if (actualSha256 !== params.expectedSha256) {
        writeAuditEvent({
          workspaceKey: canonicalWorkspaceKey(params.workspaceDir),
          file: params.file,
          expectedSha256: params.expectedSha256,
          actualSha256,
          reason: "hash_mismatch",
          action: "RECOVERY_FAILED",
          recoveryError: "restored snapshot hash mismatch",
          env: params.env,
        });
        return "failed";
      }
      writeAuditEvent({
        workspaceKey: canonicalWorkspaceKey(params.workspaceDir),
        file: params.file,
        expectedSha256: params.expectedSha256,
        actualSha256,
        reason: "recovery",
        action: "RECOVERED",
        env: params.env,
      });
      return "recovered";
    } finally {
      syncFs.closeSync(opened.fd);
    }
  } catch (error) {
    writeAuditEvent({
      workspaceKey: canonicalWorkspaceKey(params.workspaceDir),
      file: params.file,
      expectedSha256: params.expectedSha256,
      actualSha256: computePolicySha256(params.trustedContent),
      reason: "recovery",
      action: "RECOVERY_FAILED",
      recoveryError: error instanceof Error ? error.message : String(error),
      env: params.env,
    });
    return "failed";
  }
}

export function verifyPolicyFileContent(params: {
  filePath: string;
  workspaceDir: string;
  content: string;
  env?: NodeJS.ProcessEnv;
}): { ok: true } | { ok: false; error: PolicyIntegrityError } {
  const env = params.env ?? process.env;
  if (!isPolicyIntegrityEnabled(env) || !isProtectedPolicyFile(params.filePath)) {
    return { ok: true };
  }

  const file = path.basename(params.filePath);
  const workspaceKey = canonicalWorkspaceKey(params.workspaceDir);
  const actualSha256 = computePolicySha256(params.content);
  const database = openOpenClawStateDatabase({ env });
  const db = getNodeSqliteKysely<PolicyIntegrityDatabase>(database.db);
  const baseline = executeSqliteQuerySync(
    database.db,
    db
      .selectFrom("policy_integrity_baselines")
      .select(["sha256", "trusted_content"])
      .where("workspace_key", "=", workspaceKey)
      .where("file_name", "=", file)
      .limit(1),
  ).rows[0];

  if (!baseline) {
    writeAuditEvent({
      workspaceKey,
      file,
      expectedSha256: null,
      actualSha256,
      reason: "baseline_missing",
      action: "BLOCK",
      env,
    });
    return {
      ok: false,
      error: new PolicyIntegrityError({
        file,
        reason: "baseline_missing",
        message: `Policy integrity enabled but trusted baseline is missing for ${file}.`,
      }),
    };
  }

  if (baseline.sha256 !== actualSha256) {
    writeAuditEvent({
      workspaceKey,
      file,
      expectedSha256: baseline.sha256,
      actualSha256,
      reason: "hash_mismatch",
      action: "BLOCK",
      env,
    });
    const recovery = isPolicyRollbackEnabled(env)
      ? recoverFromTrustedSnapshot({
          filePath: params.filePath,
          workspaceDir: params.workspaceDir,
          file,
          expectedSha256: baseline.sha256,
          trustedContent:
            typeof baseline.trusted_content === "string" ? baseline.trusted_content : "",
          env,
        })
      : null;
    return {
      ok: false,
      error: new PolicyIntegrityError({
        file,
        reason: "hash_mismatch",
        message: `Policy integrity check failed for ${file}: SHA-256 mismatch; load blocked${recovery ? `; recovery ${recovery}.` : "."}`,
      }),
    };
  }

  return { ok: true };
}

async function readPolicyFileFromPinnedDescriptor(params: {
  workspaceDir: string;
  file: string;
}): Promise<string> {
  const filePath = path.join(params.workspaceDir, params.file);
  const opened = await openRootFile({
    absolutePath: filePath,
    rootPath: params.workspaceDir,
    boundaryLabel: "workspace root",
    maxBytes: MAX_POLICY_FILE_BYTES,
  });
  if (!opened.ok) {
    throw new Error(
      `Cannot initialize policy integrity baseline for ${params.file}: file unavailable.`,
    );
  }
  try {
    return syncFs.readFileSync(opened.fd, "utf-8");
  } finally {
    syncFs.closeSync(opened.fd);
  }
}

export async function initializePolicyIntegrityBaseline(params: {
  workspaceDir: string;
  force?: boolean;
  env?: NodeJS.ProcessEnv;
}): Promise<{ workspace: string; files: Record<string, string>; updated: boolean }> {
  const env = params.env ?? process.env;
  const workspace = canonicalWorkspaceKey(params.workspaceDir);
  const contents = await Promise.all(
    [...PROTECTED_POLICY_FILENAMES].map(async (file) => ({
      file,
      content: await readPolicyFileFromPinnedDescriptor({ workspaceDir: workspace, file }),
    })),
  );
  const files = Object.fromEntries(
    contents.map(({ file, content }) => [file, computePolicySha256(content)]),
  );
  let updated = false;

  runOpenClawStateWriteTransaction(
    (database) => {
      const db = getNodeSqliteKysely<PolicyIntegrityDatabase>(database.db);
      const existing = executeSqliteQuerySync(
        database.db,
        db
          .selectFrom("policy_integrity_baselines")
          .select("file_name")
          .where("workspace_key", "=", workspace)
          .limit(1),
      ).rows[0];
      if (existing && !params.force) {
        throw new Error(
          "Policy integrity baseline already exists for this workspace; pass --force to explicitly update it.",
        );
      }
      updated = Boolean(existing);
      const now = new Date().toISOString();
      for (const [file, sha256] of Object.entries(files)) {
        executeSqliteQuerySync(
          database.db,
          db
            .insertInto("policy_integrity_baselines")
            .values({
              workspace_key: workspace,
              file_name: file,
              sha256,
              trusted_content: contents.find((entry) => entry.file === file)?.content ?? "",
              initialized_at: now,
              updated_at: now,
            })
            .onConflict((conflict) =>
              conflict.columns(["workspace_key", "file_name"]).doUpdateSet({
                sha256,
                trusted_content: contents.find((entry) => entry.file === file)?.content ?? "",
                updated_at: now,
              }),
            ),
        );
      }
    },
    { env },
  );

  return { workspace, files, updated };
}
