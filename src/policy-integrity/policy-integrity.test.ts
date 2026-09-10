// Policy integrity tests use isolated workspace and state directories only.
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  closeOpenClawStateDatabase,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import {
  computePolicySha256,
  initializePolicyIntegrityBaseline,
  isPolicyRollbackEnabled,
  verifyPolicyFileContent,
} from "./policy-integrity.js";
import {
  DEFAULT_AGENTS_FILENAME,
  DEFAULT_HEARTBEAT_FILENAME,
  DEFAULT_SOUL_FILENAME,
  loadWorkspaceBootstrapFiles,
} from "./workspace.js";

describe("Policy Integrity Guard", () => {
  let rootDir: string;
  let workspaceDir: string;
  let stateDir: string;
  let originalIntegrityEnv: string | undefined;
  let originalStateDirEnv: string | undefined;
  let originalRollbackEnv: string | undefined;

  beforeEach(async () => {
    originalIntegrityEnv = process.env.OPENCLAW_POLICY_INTEGRITY;
    originalStateDirEnv = process.env.OPENCLAW_STATE_DIR;
    originalRollbackEnv = process.env.OPENCLAW_POLICY_ROLLBACK;
    rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-policy-integrity-"));
    workspaceDir = path.join(rootDir, "workspace");
    stateDir = path.join(rootDir, "state");
    await fs.mkdir(workspaceDir, { recursive: true });
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "trusted agents\n");
    await fs.writeFile(path.join(workspaceDir, DEFAULT_SOUL_FILENAME), "trusted soul\n");
    process.env.OPENCLAW_STATE_DIR = stateDir;
    process.env.OPENCLAW_POLICY_INTEGRITY = "1";
    process.env.OPENCLAW_POLICY_ROLLBACK = "1";
  });

  afterEach(async () => {
    closeOpenClawStateDatabase();
    if (originalIntegrityEnv === undefined) {
      delete process.env.OPENCLAW_POLICY_INTEGRITY;
    } else {
      process.env.OPENCLAW_POLICY_INTEGRITY = originalIntegrityEnv;
    }
    if (originalStateDirEnv === undefined) {
      delete process.env.OPENCLAW_STATE_DIR;
    } else {
      process.env.OPENCLAW_STATE_DIR = originalStateDirEnv;
    }
    if (originalRollbackEnv === undefined) delete process.env.OPENCLAW_POLICY_ROLLBACK;
    else process.env.OPENCLAW_POLICY_ROLLBACK = originalRollbackEnv;
    await fs.rm(rootDir, { recursive: true, force: true });
  });

  it("does not apply integrity policy to HEARTBEAT.md", async () => {
    const heartbeatPath = path.join(workspaceDir, DEFAULT_HEARTBEAT_FILENAME);
    await fs.writeFile(heartbeatPath, "heartbeat\n");

    expect(
      verifyPolicyFileContent({
        filePath: heartbeatPath,
        workspaceDir,
        content: "heartbeat\n",
      }),
    ).toEqual({ ok: true });
  });

  it.each([
    [undefined, false],
    ["", false],
    ["0", false],
    ["false", false],
    ["1", true],
    ["true", true],
  ])("parses rollback flag %s as %s", (value, expected) => {
    const env = value === undefined ? {} : { OPENCLAW_POLICY_ROLLBACK: value };
    expect(isPolicyRollbackEnabled(env)).toBe(expected);
  });

  it.each([undefined, "0", "false"])("does not recover when rollback is %s", async (value) => {
    if (value === undefined) delete process.env.OPENCLAW_POLICY_ROLLBACK;
    else process.env.OPENCLAW_POLICY_ROLLBACK = value;
    await initializePolicyIntegrityBaseline({ workspaceDir });
    const poisoned = "poisoned agents\n";
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), poisoned);
    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toMatchObject({
      code: "POLICY_INTEGRITY_BLOCKED",
    });
    expect(await fs.readFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "utf8")).toBe(poisoned);
    const rows = openOpenClawStateDatabase().db
      .prepare("SELECT action FROM policy_integrity_audit_events ORDER BY sequence")
      .all() as Array<{ action: string }>;
    expect(rows.map((row) => row.action)).toEqual(["BLOCK"]);
  });

  it("loads AGENTS.md when its baseline hash matches", async () => {
    await initializePolicyIntegrityBaseline({ workspaceDir });

    const baseline = openOpenClawStateDatabase()
      .db.prepare("SELECT trusted_content FROM policy_integrity_baselines WHERE file_name = ?")
      .get(DEFAULT_AGENTS_FILENAME) as { trusted_content: string };
    expect(baseline.trusted_content).toBe("trusted agents\n");

    const files = await loadWorkspaceBootstrapFiles(workspaceDir);
    expect(files.find((file) => file.name === DEFAULT_AGENTS_FILENAME)?.content).toBe(
      "trusted agents\n",
    );
  });

  it("loads SOUL.md when its baseline hash matches", async () => {
    await initializePolicyIntegrityBaseline({ workspaceDir });

    const files = await loadWorkspaceBootstrapFiles(workspaceDir);
    expect(files.find((file) => file.name === DEFAULT_SOUL_FILENAME)?.content).toBe(
      "trusted soul\n",
    );
  });

  it("blocks a modified AGENTS.md", async () => {
    await initializePolicyIntegrityBaseline({ workspaceDir });
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "poisoned agents\n");

    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toMatchObject({
      code: "POLICY_INTEGRITY_BLOCKED",
      file: DEFAULT_AGENTS_FILENAME,
      reason: "hash_mismatch",
    });
    expect(await fs.readFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "utf8")).toBe(
      "trusted agents\n",
    );
  });

  it("blocks a modified SOUL.md", async () => {
    await initializePolicyIntegrityBaseline({ workspaceDir });
    await fs.writeFile(path.join(workspaceDir, DEFAULT_SOUL_FILENAME), "poisoned soul\n");

    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toMatchObject({
      code: "POLICY_INTEGRITY_BLOCKED",
      file: DEFAULT_SOUL_FILENAME,
      reason: "hash_mismatch",
    });
    expect(await fs.readFile(path.join(workspaceDir, DEFAULT_SOUL_FILENAME), "utf8")).toBe(
      "trusted soul\n",
    );
  });

  it("fails closed with a clear error when the baseline is missing", async () => {
    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toThrow(
      "Policy integrity enabled but trusted baseline is missing for AGENTS.md.",
    );
  });

  it("preserves original loading behavior when integrity is disabled", async () => {
    delete process.env.OPENCLAW_POLICY_INTEGRITY;
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "changed without guard\n");

    const files = await loadWorkspaceBootstrapFiles(workspaceDir);
    expect(files.find((file) => file.name === DEFAULT_AGENTS_FILENAME)?.content).toBe(
      "changed without guard\n",
    );
  });

  it("re-verifies policy on a cache hit", async () => {
    await initializePolicyIntegrityBaseline({ workspaceDir });
    await loadWorkspaceBootstrapFiles(workspaceDir);
    const database = openOpenClawStateDatabase();
    database.db
      .prepare(
        "UPDATE policy_integrity_baselines SET sha256 = ? WHERE workspace_key = ? AND file_name = ?",
      )
      .run("0".repeat(64), await fs.realpath(workspaceDir), DEFAULT_AGENTS_FILENAME);

    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toMatchObject({
      code: "POLICY_INTEGRITY_BLOCKED",
      file: DEFAULT_AGENTS_FILENAME,
      reason: "hash_mismatch",
    });
  });

  it("writes the expected audit event after a mismatch", async () => {
    const trusted = "trusted agents\n";
    const poisoned = "poisoned agents\n";
    await initializePolicyIntegrityBaseline({ workspaceDir });
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), poisoned);
    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toBeDefined();

    const rows = openOpenClawStateDatabase()
      .db.prepare(
        `SELECT timestamp, file_name, expected_sha256, actual_sha256, action, reason
           FROM policy_integrity_audit_events
          ORDER BY sequence ASC`,
      )
      .all() as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      file_name: DEFAULT_AGENTS_FILENAME,
      expected_sha256: computePolicySha256(trusted),
      actual_sha256: computePolicySha256(poisoned),
      action: "BLOCK",
      reason: "hash_mismatch",
    });
    expect(rows[1]).toMatchObject({
      file_name: DEFAULT_AGENTS_FILENAME,
      expected_sha256: computePolicySha256(trusted),
      actual_sha256: computePolicySha256(trusted),
      action: "RECOVERED",
      reason: "recovery",
    });
    expect(rows[0]?.timestamp as string).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("does not store policy file content in the audit log", async () => {
    const poisoned = "TOP-SECRET-POLICY-CONTENT\n";
    await initializePolicyIntegrityBaseline({ workspaceDir });
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), poisoned);
    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toBeDefined();

    const rows = openOpenClawStateDatabase()
      .db.prepare("SELECT * FROM policy_integrity_audit_events")
      .all();
    expect(JSON.stringify(rows)).not.toContain(poisoned.trim());
  });

  it("records RECOVERY_FAILED and remains blocked when the trusted snapshot is absent", async () => {
    await initializePolicyIntegrityBaseline({ workspaceDir });
    openOpenClawStateDatabase()
      .db.prepare("UPDATE policy_integrity_baselines SET trusted_content = '' WHERE file_name = ?")
      .run(DEFAULT_AGENTS_FILENAME);
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "poisoned agents\n");

    await expect(loadWorkspaceBootstrapFiles(workspaceDir)).rejects.toMatchObject({
      code: "POLICY_INTEGRITY_BLOCKED",
    });
    const recovery = openOpenClawStateDatabase()
      .db.prepare(
        "SELECT action, reason, recovery_error FROM policy_integrity_audit_events WHERE action = 'RECOVERY_FAILED'",
      )
      .get() as { action: string; reason: string; recovery_error: string };
    expect(recovery).toMatchObject({
      action: "RECOVERY_FAILED",
      reason: "hash_mismatch",
      recovery_error: "trusted snapshot is missing",
    });
    expect(await fs.readFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "utf8")).toBe(
      "poisoned agents\n",
    );
  });

  it("updates the trusted snapshot only after an explicit force", async () => {
    await initializePolicyIntegrityBaseline({ workspaceDir });
    await fs.writeFile(path.join(workspaceDir, DEFAULT_AGENTS_FILENAME), "operator revision\n");

    await expect(initializePolicyIntegrityBaseline({ workspaceDir })).rejects.toThrow(
      "pass --force to explicitly update it",
    );
    await initializePolicyIntegrityBaseline({ workspaceDir, force: true });
    const baseline = openOpenClawStateDatabase()
      .db.prepare(
        "SELECT sha256, trusted_content FROM policy_integrity_baselines WHERE file_name = ?",
      )
      .get(DEFAULT_AGENTS_FILENAME) as { sha256: string; trusted_content: string };
    expect(baseline).toEqual({
      sha256: computePolicySha256("operator revision\n"),
      trusted_content: "operator revision\n",
    });
  });
});
