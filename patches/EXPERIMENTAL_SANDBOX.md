# Optional experimental file-access / sandbox patch

`experimental-sandbox-paths.patch` is a separate archive of real local changes
against the same pinned upstream commit. It is **not** required by the Scanner,
not a completed workspace allowlist, and not validated as a general security
boundary. Personal `docker-compose.yml` changes are excluded.

Included changes:

- `packages/agent-core/src/harness/env/nodejs.ts`: suffix-based checks in three
  read methods and one write method. Reads ending in private.env/.env/auth.json/
  token.txt and writes ending in AGENTS.md/SOUL.md are denied. This is a narrow
  prototype, not robust path authorization: suffix false positives, aliases,
  symlinks and other operations/shell tools can defeat the intended boundary.
- `src/agents/sandbox/docker-daemon-host-paths.ts` and its test: translate
  container-visible paths to Docker daemon host paths using inspected mounts.
- `src/agents/sandbox/docker.ts`, `browser.ts`, `workspace-mounts.ts` and
  `docker.config-hash-recreate.test.ts`: pass mapped paths to mount/config-hash
  construction. This supports Docker-outside-of-Docker setup; it is not proof
  of host isolation. Access to a Docker daemon remains highly privileged.

No original experiment links these exact source changes causally to an attack
success rate. Do not attribute 0/18 tool calls to this patch. It is retained so
the research archive does not omit incomplete work or present it as production
hardening. Follow the core patch instructions, then use `git apply --check` on
this optional patch in a disposable checkout. Publication validation distinguishes
mocked tests from actual Docker/live-agent testing, which was not performed.
