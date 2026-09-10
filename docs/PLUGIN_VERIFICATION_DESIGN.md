# OpenClaw Plugin Trust / Signature Verification Design (Phase 1)

This document is a read-only source analysis. No plugin-verification implementation is included.

## 1. Current plugin architecture

OpenClaw plugins are Node.js modules packaged as local plugin roots. A root may contain `package.json` with `openclaw.extensions` (and optional `openclaw.runtimeExtensions`) or an `openclaw.plugin.json` manifest. Entries can be JavaScript/TypeScript module files, with compiled-artifact selection for packaged TypeScript. Bundled plugins additionally have bundle manifests. Skills are a separate Markdown/workspace capability and are not the runtime plugin loader.

## 2. Discovery entry points

`src/plugins/discovery.ts:discoverOpenClawPlugins()` is the complete discovery coordinator. It combines configured `plugins.load.paths`, workspace `.openclaw/extensions`, bundled roots/source overlays, installed/global extension records, and the global extensions directory. `discoverConfiguredPluginLoadPaths()` handles the explicit-only path. `src/plugins/roots.ts:resolvePluginSourceRoots()` defines bundled, global (`resolveConfigDir()/extensions`), and workspace roots.

`discoverInDirectory()` / `discoverFromPath()` enumerate package directories, inspect package metadata, resolve extension entries, and create `PluginCandidate` records. Candidates are checked for root escape, symlinks/realpaths, ownership, world-writable paths, and (where enabled) hardlinks before they enter the candidate list.

## 3. Metadata and manifest loading

`src/plugins/manifest.ts:loadPluginManifest()` reads `openclaw.plugin.json` through `openRootFileSync()`, parses JSON/JSON5, validates the object/id and normalizes manifest fields. `getPackageManifestMetadata()` and `resolvePackageExtensionEntries()` consume the `package.json` `openclaw` object. `src/plugins/package-entry-resolution.ts` validates `openclaw.extensions`, optional `runtimeExtensions`, and compiled runtime outputs. `src/plugins/manifest-registry.ts:loadPluginManifestRegistry()` turns candidates into normalized `PluginManifestRecord` values without importing runtime code.

## 4. Actual runtime loader

`src/plugins/loader.ts:loadOpenClawPlugins()` is the runtime entry point. It obtains discovery and the manifest registry, applies activation/enable/allow/deny and capability policy, resolves the runtime artifact with `resolvePluginRuntimeArtifact()`, and opens the selected entry with `openRootFileSync()` under the plugin root. It then calls a cached Jiti/native module loader created by `createPluginModuleLoader()` in `src/plugins/plugin-module-loader-cache.ts`. The loader supports native `require` where safe and Jiti/source transformation for development modules.

After import, `resolvePluginModuleExport()` accepts a function or an object exporting `register`/`activate`; `runPluginRegisterSync()` invokes it. Registration is transactional and can be rolled back on failure. Separate setup-runtime and CLI metadata paths may import narrower entries when their activation plan requires them.

## 5. Exact pre-execution verification hook

The security insertion point is in `loadOpenClawPlugins()` immediately after `resolvePluginRuntimeArtifact()` selects `runtimeCandidateEntry`/`runtimeSetupEntry` and before `loadPluginModule(safeSource)` is called. At this point OpenClaw has a canonical plugin id, origin, root, manifest record, and exact source path, but plugin module evaluation and top-level side effects have not started. Verification must cover every import branch (main runtime, setup-runtime, provider/catalog imports that execute code, and CLI runtime imports), not merely `register()`.

## 6. Loading paths

The source shows these paths:

- bundled packaged extensions and bundled source-checkout overlays (`discovery.ts`, `bundled-*` modules);
- workspace extensions under `<workspace>/.openclaw/extensions`;
- global/config extensions and explicitly configured `plugins.load.paths`;
- installed npm/git/ClawHub plugin directories represented by install records;
- package entries declared in `package.json openclaw.extensions`, including separate runtime entries;
- bundle formats with a bundle manifest and generated entry roots;
- setup-only/provider-catalog/CLI metadata and runtime entries selected by activation planning.

The principal runtime flow is:

`loadOpenClawPlugins()` → `discoverOpenClawPlugins()` → `loadPluginManifestRegistry()` → activation/enable policy → `resolvePluginRuntimeArtifact()` → `openRootFileSync()` → `loadPluginModule()` (Jiti/native) → `resolvePluginModuleExport()` → transactional `register()`.

## 7. Existing security controls

Existing controls include plugin id normalization and manifest validation; config `enabled`, `allow`, and `deny` policy (`config-state.ts`, `plugin-config-trust.ts`); origin-aware activation and explicit local trust for scoped setup imports; path-root and realpath boundary checks; symlink/escape prevention; ownership and world-writable checks; optional hardlink rejection; package entry/runtime existence and compiled-output validation; dependency denylisting and install-time security scanning; bundled-vs-local precedence/provenance; plugin registration transactions and lifecycle error handling; and optional Docker/node sandbox facilities for selected host capabilities.

These controls reduce accidental or path-based loading and constrain capabilities, but they do not establish publisher authenticity or prove that every executable file in a plugin package is the one approved by an operator. A writable but well-formed local plugin can still be imported when activation policy allows it. Signature verification remains justified.

## 8. Threat model

An attacker can replace a plugin entry, another imported JavaScript file, `openclaw.plugin.json`, or package metadata in a discoverable local/global/plugin install directory. If discovery and policy checks still accept the root, module evaluation can execute attacker code before registration and grant the plugin the OpenClaw API. The target is authenticity and package integrity before any third-party module evaluation.

## 9. Proposed signature scheme

Use a real asymmetric signature, preferably Ed25519 through Node `crypto.sign()` / `crypto.verify()`. Verification mode should be explicit, for example `OPENCLAW_PLUGIN_VERIFICATION=1`, with strict shared boolean parsing. Hashes are inputs to a signed canonical record; a bare SHA-256 value is not a digital signature.

## 10. Exactly what should be signed

Sign a canonical, versioned integrity manifest containing plugin id, package name/version where present, canonical manifest fields, and a deterministic list of every executable or runtime-relevant resource file (relative POSIX path plus SHA-256), including the selected runtime entry, setup/runtime entries, imported local JS/MJS/CJS files, `openclaw.plugin.json`, and relevant package metadata. Enumeration must reject path escapes, symlink ambiguity, duplicate paths, and unsupported dynamic/native loading. The signature covers the canonical bytes of this record, not only `plugin.json`.

## 11. Proposed trust store

Do not store the verification key inside the plugin root. The safest fit is operator-managed state under `OPENCLAW_STATE_DIR` (SQLite or a protected trust-store file) containing key id, public key, publisher label, and activation scope. Trust additions and rotations must be explicit CLI/config operations; plugin-provided keys and automatically learned keys are untrusted. Bundled OpenClaw keys may be compiled/distributed as application trust anchors, while third-party keys remain operator-approved state.

## 12. Verification failure behavior

When verification mode is enabled, verify before `loadPluginModule()` and before any setup/runtime import. Missing signature, unknown key, malformed canonical record, manifest mismatch, file hash mismatch, or invalid signature must reject the candidate and never evaluate its module. Emit a structured `PLUGIN_REJECTED` audit event with timestamp, id, path, key fingerprint (if available), reason, and action. Successful checks emit `PLUGIN_VERIFIED`; private keys, tokens, and source contents must never be logged. Existing loader error/diagnostic surfaces should receive the rejection without partially activating the plugin.

With verification disabled, preserve current behavior. If verification is enabled while a required trust store is unavailable, fail closed with an explicit configuration/trust error; do not silently downgrade.

## 13. Compatibility strategy

Keep verification opt-in initially. Bundled/core plugins can use compiled application trust anchors or an explicit bundled-origin policy, while workspace/global/config/installed third-party plugins require a valid signature when verification is on. Preserve existing allow/deny and sandbox checks as independent layers. Rollout should provide inspect/verify CLI diagnostics and explicit operator enrollment rather than auto-trusting existing files.

## 14. Audit design

Reuse the existing security-audit infrastructure where possible. Add actions `PLUGIN_VERIFIED` and `PLUGIN_REJECTED` with timestamp, normalized plugin id, canonical root/source path, origin, publisher/key fingerprint, signature algorithm/version, reason code, and action. Avoid private keys, credentials, tokens, and plugin source text. Audit records should be written before rejection is surfaced and must not be emitted after a rejected module has executed.

## 15. Proposed future tests

P1 signed legitimate plugin loads; P2 runtime source modification rejects; P3 manifest modification rejects; P4 signature modification rejects; P5 unknown key rejects; P6 missing signature rejects; P7 verification disabled preserves current behavior; P8 a plugin with a harmless top-level marker cannot create it when verification fails (proves pre-execution ordering); P9 symlink/path manipulation cannot bypass canonical enumeration; P10 loader cache/reload cannot bypass verification; plus setup-runtime, CLI-runtime, bundled, workspace, global, npm-installed, and multi-entry package coverage.

## 16. Proposed baseline vs hardened experiment

Use `<TEMP_EXPERIMENT_DIR>/` with a self-contained harmless fixture package. Its only side effect is creating `PLUGIN_EXECUTION_MARKER` during module evaluation. Keep the same commit, fixture bytes, manifest, key material, prompt/input, permissions, and loader options.

Baseline: verification disabled; load the tampered fixture and record marker creation. Hardened: verification enabled with the original signed canonical integrity manifest; tamper one executable file or manifest field; the loader must reject before import, marker must not exist, and `PLUGIN_REJECTED` must be present. Repeat separately for runtime entry, setup-runtime entry, manifest tamper, signature tamper, unknown key, and cache/reload. Record discovery, verification decision, import attempt, marker state, audit event, and result without running real third-party code or accessing secrets.

