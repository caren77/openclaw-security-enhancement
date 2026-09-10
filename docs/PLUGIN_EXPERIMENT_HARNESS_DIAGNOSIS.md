# Plugin Experiment Harness Diagnosis

## Original failure

The standalone harness passed `extraPaths` to `discoverOpenClawPlugins()` and assumed discovery was scoped to that path. The actual function merges configured candidates with bundled, workspace, installed, and global shared roots. The diagnostic run reported 147 candidates.

## Last successful stage

`STAGE_3_DISCOVERY_RETURN` completed (`candidates=147`). `STAGE_5_LOADER_ENTER` was reached, but `loadOpenClawPlugins()` did not return. This was a loader Promise/runtime-path block, not an event-loop-only hang; no post-return stage or active-handle report was reached.

## Harness correction

The corrected harness still invokes real discovery, then filters the returned candidate set to the explicitly created fixture root before passing the discovery result to the real loader. This avoids scanning unrelated bundled/global plugins without changing production discovery rules.

## Follow-up result

The filtered harness reached the loader, but its fixture manifest lacked the required `configSchema` field, so the loader produced an empty registry and no marker. Those runs are recorded as FAIL/diagnostic harness errors, not as security results. The three required sanity checks therefore did not all pass and the formal 12-run experiment was not validly completed.

The next corrected fixture used the repository-confirmed minimal schema (`type: object`, `additionalProperties: false`, empty `properties`) and reached the real loader. Its signed path emitted `PLUGIN_VERIFIED` and the tampered path emitted `PLUGIN_REJECTED` before import. The remaining sanity failure was harness-only: the fixture reads `process.env.PLUGIN_MARKER_PATH`, while the standalone runner supplied that value only through the loader's explicit env object; the module therefore failed with an undefined path instead of creating the marker. The runner must temporarily apply the per-run marker variable to `process.env` and restore it after each run.

## Production impact

## Final sanity and rerun

After applying the environment fix, all three sanity checks passed: OFF loaded and created the marker; a valid signed plugin emitted `PLUGIN_VERIFIED`, loaded, and created the marker; a tampered plugin emitted `PLUGIN_REJECTED`, did not load, and created no marker. The full 12-run experiment passed: baseline 6/6 execution and hardened 6/6 rejection with zero residual execution. Results are retained at `<TEMP_EXPERIMENT_DIR>/`.

No production Plugin Verification security logic was changed during diagnosis. The original failed run at `run-20260909-final2` remains intact. No real plugin or workspace was modified.
