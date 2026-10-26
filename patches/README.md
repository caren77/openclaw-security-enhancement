# Pinned source integration

Upstream: https://github.com/openclaw/openclaw

Exact base: `090cb491227e45cdbdc0a65ea2718c8fe62461c9`.
These patches export selected changes from the research working tree. They do
not claim that the research changes were committed upstream. They add no new
package dependencies; use the pinned upstream package manifest and lockfile.

`skill-security-scanner.patch` modifies ten files: scanner implementation/test,
workspace loading/test, session loading/test, node-host skills/test, and remote
skills/test. Full post-patch files are also archived under
`../src/skill-security-scanner/upstream/` for inspection. They are not standalone.

`existing-security-integration.patch` includes Policy Integrity + Audit/Trusted
Rollback, Plugin Verification, workspace and plugin-loader integration, Security
CLI integration, SQLite schema and generated DB types. It adds the actual four
implementation/test files and modifies seven integration files. Existing
published source and results remain unchanged. Neither core patch includes
Docker configuration or sandbox path changes from the original dirty checkout.
The separately labeled `experimental-sandbox-paths.patch` preserves additional
prototype work; read `EXPERIMENTAL_SANDBOX.md` before considering it.

Use a **new, disposable checkout** (do not apply to an existing research tree):

```sh
git clone https://github.com/openclaw/openclaw.git openclaw-reproduction
cd openclaw-reproduction
git switch --detach 090cb491227e45cdbdc0a65ea2718c8fe62461c9
# Substitute the absolute path to this publication checkout:
export RESEARCH_ARCHIVE=/absolute/path/to/openclaw-security-enhancement
git apply --check "$RESEARCH_ARCHIVE/patches/existing-security-integration.patch"
git apply "$RESEARCH_ARCHIVE/patches/existing-security-integration.patch"
git apply --check "$RESEARCH_ARCHIVE/patches/skill-security-scanner.patch"
git apply "$RESEARCH_ARCHIVE/patches/skill-security-scanner.patch"
pnpm install --frozen-lockfile
node scripts/run-vitest.mjs src/skills/security/scanner.test.ts
node scripts/run-vitest.mjs src/skills/loading/workspace-load.test.ts src/skills/loading/session.test.ts src/node-host/skills.test.ts src/skills/runtime/remote-skills.test.ts
node scripts/run-vitest.mjs src/agents/policy-integrity.test.ts src/plugins/plugin-verification.test.ts
```

Use a Node version accepted by upstream `package.json`, preferably Node 24,
and its pinned pnpm version. Follow upstream testing/security instructions.
Installing dependencies requires network access. The archive does not include
node_modules, auth state, signing private keys or any deployment configuration.
Never point reproduction at a real credential-bearing agent workspace.

Applying a patch successfully proves mechanical applicability, not semantic
correctness or a successful complete build. Publication-time test evidence and
unexecuted checks are listed in `../docs/PUBLICATION_VALIDATION.md`.
