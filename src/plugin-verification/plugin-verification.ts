// Optional pre-execution trust verification for third-party plugins.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseBooleanValue } from "../utils/boolean.js";
import { openOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import type { PluginOrigin } from "./plugin-origin.types.js";

export const PLUGIN_SIGNATURE_FILENAME = "openclaw.plugin.sig.json";
const EXECUTABLE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".json"]);

export type PluginVerificationResult =
  | { ok: true; keyId: string; publisher: string }
  | { ok: false; reason: string; keyId?: string };

function audit(params: { pluginId: string; origin: PluginOrigin; rootDir: string; result: PluginVerificationResult; env: NodeJS.ProcessEnv }): void {
  const db = openOpenClawStateDatabase({ env: params.env }).db;
  db.prepare("INSERT INTO plugin_verification_audit_events (timestamp,plugin_id,plugin_origin,plugin_path,key_id,publisher,action,reason) VALUES (?,?,?,?,?,?,?,?)").run(new Date().toISOString(), params.pluginId, params.origin, params.rootDir, params.result.ok ? params.result.keyId : (params.result.keyId ?? null), params.result.ok ? params.result.publisher : null, params.result.ok ? "PLUGIN_VERIFIED" : "PLUGIN_REJECTED", params.result.ok ? "verified" : params.result.reason);
}

export function isPluginVerificationEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return parseBooleanValue(env.OPENCLAW_PLUGIN_VERIFICATION) === true;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value as Record<string, unknown>).toSorted().map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function listFiles(rootDir: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === PLUGIN_SIGNATURE_FILENAME) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isSymbolicLink()) throw new Error("plugin integrity tree contains symlink");
      else if (entry.isFile() && EXECUTABLE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) out.push(full);
    }
  };
  walk(rootDir);
  return out.toSorted();
}

export function buildPluginIntegrityManifest(params: { rootDir: string; pluginId: string }): string {
  const files = listFiles(params.rootDir).map((filePath) => ({
    path: path.relative(params.rootDir, filePath).split(path.sep).join("/"),
    sha256: crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex"),
  }));
  return canonicalJson({ version: 1, pluginId: params.pluginId, files });
}

function readSignature(rootDir: string): { version: number; algorithm: string; keyId: string; signature: string } | null {
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(rootDir, PLUGIN_SIGNATURE_FILENAME), "utf8")) as Record<string, unknown>;
    if (raw.version !== 1 || raw.algorithm !== "ed25519" || typeof raw.keyId !== "string" || typeof raw.signature !== "string") return null;
    return raw as { version: 1; algorithm: "ed25519"; keyId: string; signature: string };
  } catch { return null; }
}

export function verifyPluginTrust(params: { rootDir: string; pluginId: string; origin: PluginOrigin; env?: NodeJS.ProcessEnv }): PluginVerificationResult {
  const env = params.env ?? process.env;
  if (!isPluginVerificationEnabled(env) || params.origin === "bundled") return { ok: true, keyId: "bundled", publisher: "OpenClaw bundled" };
  const metadata = readSignature(params.rootDir);
  if (!metadata) { const result={ ok: false as const, reason: "missing_or_malformed_signature" }; audit({ ...params, result, env }); return result; }
  const db = openOpenClawStateDatabase({ env }).db;
  const trusted = db.prepare("SELECT publisher, public_key, enabled FROM plugin_trusted_publishers WHERE key_id = ?").get(metadata.keyId) as { publisher: string; public_key: string; enabled: number } | undefined;
  if (!trusted || trusted.enabled !== 1) { const result={ ok: false as const, reason: "unknown_key", keyId: metadata.keyId }; audit({ ...params, result, env }); return result; }
  let valid = false;
  try { valid = crypto.verify(null, Buffer.from(buildPluginIntegrityManifest({ rootDir: params.rootDir, pluginId: params.pluginId })), crypto.createPublicKey(trusted.public_key), Buffer.from(metadata.signature, "base64")); } catch { valid = false; }
  const result = valid ? { ok: true as const, keyId: metadata.keyId, publisher: trusted.publisher } : { ok: false as const, reason: "invalid_signature", keyId: metadata.keyId };
  audit({ ...params, result, env }); return result;
}

export function addTrustedPluginKey(params: { keyId: string; publisher: string; publicKey: string; env?: NodeJS.ProcessEnv }): void {
  const db = openOpenClawStateDatabase({ env: params.env });
  db.db.prepare("INSERT INTO plugin_trusted_publishers (key_id,publisher,public_key,algorithm,created_at,enabled) VALUES (?,?,?,?,?,1) ON CONFLICT(key_id) DO UPDATE SET publisher=excluded.publisher, public_key=excluded.public_key, enabled=1").run(params.keyId, params.publisher, params.publicKey, "ed25519", new Date().toISOString());
}

export function listTrustedPluginKeys(env?: NodeJS.ProcessEnv): unknown[] {
  return openOpenClawStateDatabase({ env }).db.prepare("SELECT key_id,publisher,algorithm,created_at,enabled FROM plugin_trusted_publishers ORDER BY key_id").all();
}

export function disableTrustedPluginKey(keyId: string, env?: NodeJS.ProcessEnv): void {
  openOpenClawStateDatabase({ env }).db.prepare("UPDATE plugin_trusted_publishers SET enabled=0 WHERE key_id=?").run(keyId);
}
