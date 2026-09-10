import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import {
  PLUGIN_SIGNATURE_FILENAME,
  addTrustedPluginKey,
  buildPluginIntegrityManifest,
  isPluginVerificationEnabled,
  verifyPluginTrust,
} from "./plugin-verification.js";

describe("plugin trust verification", () => {
  let root: string; let plugin: string; let state: string; let privateKey: crypto.KeyObject; let publicKey: crypto.KeyObject;
  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-plugin-verification-")); plugin = path.join(root, "plugin"); state = path.join(root, "state");
    await fs.mkdir(plugin); await fs.writeFile(path.join(plugin, "openclaw.plugin.json"), JSON.stringify({ id: "fixture" })); await fs.writeFile(path.join(plugin, "index.js"), "export const register = () => {};\n");
    ({ privateKey, publicKey } = crypto.generateKeyPairSync("ed25519")); process.env.OPENCLAW_STATE_DIR = state;
  });
  afterEach(async () => { closeOpenClawStateDatabase(); await fs.rm(root, { recursive: true, force: true }); });
  async function sign() { const keyId = "fixture-key"; addTrustedPluginKey({ keyId, publisher: "fixture", publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(), env: { OPENCLAW_STATE_DIR: state } }); const signature = crypto.sign(null, Buffer.from(buildPluginIntegrityManifest({ rootDir: plugin, pluginId: "fixture" })), privateKey).toString("base64"); await fs.writeFile(path.join(plugin, PLUGIN_SIGNATURE_FILENAME), JSON.stringify({ version: 1, algorithm: "ed25519", keyId, signature })); }
  const enabled = () => ({ OPENCLAW_STATE_DIR: state, OPENCLAW_PLUGIN_VERIFICATION: "1" } as NodeJS.ProcessEnv);
  it.each([[undefined, false],["", false],["0", false],["false", false],["1", true],["true", true]])("P7 parses %s", (v, expected) => expect(isPluginVerificationEnabled(v === undefined ? {} : { OPENCLAW_PLUGIN_VERIFICATION: v })).toBe(expected));
  it("P1 verifies a legitimate signed plugin", async () => { await sign(); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(true); });
  it("P2 rejects modified source", async () => { await sign(); await fs.appendFile(path.join(plugin, "index.js"), "// tamper"); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P3 rejects modified manifest", async () => { await sign(); await fs.appendFile(path.join(plugin, "openclaw.plugin.json"), " "); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P4 rejects modified signature", async () => { await sign(); const p=path.join(plugin, PLUGIN_SIGNATURE_FILENAME); await fs.writeFile(p, (await fs.readFile(p,"utf8")).replace(/.$/, "A")); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P5 rejects unknown key", async () => { await sign(); const p=path.join(plugin, PLUGIN_SIGNATURE_FILENAME); await fs.writeFile(p, (await fs.readFile(p,"utf8")).replace("fixture-key", "unknown")); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P6 rejects missing signature", async () => { expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P8 verifies before module evaluation (API is pure)", async () => { expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P9 rejects symlinked executable coverage", async () => { await sign(); await fs.symlink("index.js", path.join(plugin, "alias.js")); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P10 re-evaluates changed files", async () => { await sign(); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(true); await fs.appendFile(path.join(plugin, "index.js"), "x"); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P11 rejects malformed metadata", async () => { await fs.writeFile(path.join(plugin, PLUGIN_SIGNATURE_FILENAME), "{}"); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P12 rejects unsupported algorithm", async () => { await fs.writeFile(path.join(plugin, PLUGIN_SIGNATURE_FILENAME), JSON.stringify({ version: 1, algorithm: "rsa", keyId: "x", signature: "x" })); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: enabled() }).ok).toBe(false); });
  it("P13 rejects missing trusted store", async () => { await sign(); closeOpenClawStateDatabase(); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: { OPENCLAW_STATE_DIR: path.join(root,"other"), OPENCLAW_PLUGIN_VERIFICATION: "1" } }).ok).toBe(false); });
  it("preserves disabled behavior and exempts bundled origin", async () => { expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "config", env: { OPENCLAW_STATE_DIR: state } }).ok).toBe(true); expect(verifyPluginTrust({ rootDir: plugin, pluginId: "fixture", origin: "bundled", env: enabled() }).ok).toBe(true); });
});
