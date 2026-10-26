# Skill Security Scanner REVIEW Gap Analysis

## Scope and evidence

This analysis uses the unmodified first formal-experiment artifacts in
`/tmp/openclaw-skill-security-experiment/`. It was completed before changing scanner policy.
The first run is not a valid baseline comparison because its feature flag did not bypass the
scanner, but its hardened scan findings remain useful for explaining the three malicious REVIEW
decisions and comparing them with benign and bundled-skill REVIEW decisions.

The current default policy assigns 4 points to a critical finding, 2 to a warning, and 0 to an
informational finding. It blocks a report when a finding matches a default blocking rule or when
the aggregate score reaches 12. Any other non-empty report is REVIEW.

## Malicious fixtures that reached execution

| Fixture | Findings | Rule ID | Category | Severity | Risk score | Risk level | Final action | Why it did not BLOCK |
| --- | --- | --- | --- | --- | ---: | --- | --- | --- |
| `m1-dangerous-command` | Direct `child_process` command-execution call | `dangerous-exec` | `command-execution` | critical | 4 | REVIEW | REVIEW; execution marker reached | The rule was critical but was not a default blocking rule. A single critical finding scored 4, below the aggregate block threshold of 12. |
| `m2-sensitive-file` | Access to an explicitly sensitive filesystem path | `sensitive-path-access` | `sensitive-access` | warn | 2 | REVIEW | REVIEW; execution marker reached | Sensitive path access alone is a warning and is not a default blocking rule. There was no network-send, dynamic-execution, or other corroborating behavior, so the score remained 2. |
| `m4-dynamic-code` | Direct runtime code evaluation | `dynamic-code-execution` | `dynamic-code-execution` | critical | 4 | REVIEW | REVIEW; execution marker reached | The direct-evaluation rule was critical but was not a default blocking rule. The single finding scored 4, below the aggregate block threshold of 12. |

All three fixtures were detected. Their protection failure was therefore a policy-decision gap,
not a discovery or parsing failure: REVIEW is warning-only in the runtime integration and does not
prevent registration or prompt exposure.

## Benign fixture REVIEW

| Fixture | Findings | Rule ID | Category | Severity | Risk score | Risk level | Why REVIEW is appropriate |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| `b3-network-api` | Ordinary outbound API use through `fetch()` | `network-client` | `network-exfiltration` | info | 0 | REVIEW | Network capability deserves visibility, but there is no sensitive input, secret access, file read, obfuscation, or execution behavior. Blocking ordinary network clients would create broad false positives. |

## Bundled-skill REVIEW inventory

The 18 bundled REVIEW results are isolated or low-confidence capabilities rather than a confirmed
malicious dataflow. None reached the score threshold and none matched a default blocking rule.

| Bundled skill | Score | Findings | Interpretation |
| --- | ---: | --- | --- |
| `1password` | 2 | `prompt-sensitive-access` | Expected credential-manager documentation/instructions. |
| `bear-notes` | 2 | `sensitive-path-access` | Local application/configuration path reference. |
| `camsnap` | 2 | `sensitive-path-access` | Local application/configuration path reference. |
| `eightctl` | 2 | `sensitive-path-access` | Local application/configuration path reference. |
| `healthcheck` | 2 | `prompt-sensitive-access` | Security/credential guidance text, not an override plus execution request. |
| `himalaya` | 4 | two `sensitive-path-access` findings | Legitimate local configuration access, with no network exfiltration correlation. |
| `meme-maker` | 2 | `potential-exfiltration`, `network-client` | A file-to-network capability requiring review, but without a sensitive source or secret signal. |
| `model-usage` | 4 | `dangerous-runtime-command`, `sensitive-path-access` | Documented CLI/configuration behavior; no direct `child_process` execution primitive. |
| `openai-whisper-api` | 2 | `shell-interpolation` | Shell templating capability without a direct dynamic-evaluation finding. |
| `oracle` | 2 | `sensitive-path-access` | Local application/configuration path reference. |
| `ordercli` | 2 | `dynamic-import` | Runtime module selection, not `eval()` or `new Function()`. |
| `peekaboo` | 2 | `prompt-sensitive-access` | Tool instructions involving protected resources. |
| `session-logs` | 4 | `prompt-injection-system` | High-risk prompt wording that is visible for review but lacks the scanner's stronger override/security-disable combination. |
| `sherpa-onnx-tts` | 2 | `sensitive-environment-access` | A named environment-variable dependency without a network-send correlation. |
| `spotify-player` | 2 | `sensitive-path-access` | Local application/configuration path reference. |
| `tmux` | 4 | two `shell-interpolation` findings | Documented shell templating, not direct runtime code evaluation. |
| `trello` | 2 | `prompt-sensitive-access` | Credential-related setup documentation. |
| `video-frames` | 2 | `shell-interpolation` | Documented command templating without a direct dynamic-evaluation primitive. |

## Malicious REVIEW versus benign/bundled REVIEW

The strongest general differentiators are behavioral correlations:

- sensitive file or secret access plus an external network send;
- a download or decoded payload plus execution;
- prompt override/security-disable language plus a dangerous tool or command request;
- dynamic execution combined with secret access, network activity, or obfuscation.

Those combinations provide stronger evidence than standalone network access, a shell keyword in
documentation, a local configuration path, or credential-management instructions. The scanner
already demonstrates this distinction in `m3-secret-network` and `m6-multistage`, which BLOCKed
because their correlated findings included explicit exfiltration/download-and-execute rules.

However, none of the three residual malicious fixtures contains such a combination:

- `m1` contains one direct command-execution primitive;
- `m2` contains one sensitive-path access;
- `m4` contains one direct dynamic-code-evaluation primitive.

Consequently, a combination-only policy change cannot block these exact unchanged fixtures. The
safe calibration boundary is to distinguish high-confidence direct execution primitives from
broader capability indicators. Direct `child_process` invocation and direct `eval()`/`new
Function()` can be considered for default blocking without promoting lower-confidence rules such
as `dangerous-runtime-command`, `shell-interpolation`, or `dynamic-import`. Conversely,
`sensitive-path-access` alone should remain REVIEW because it is common in legitimate bundled
skills and does not establish disclosure or exfiltration.

## Root cause

The three misses share one structural cause: the old policy treated every isolated finding below
the aggregate threshold as REVIEW unless its rule ID was explicitly block-listed, even when the
finding was a high-confidence direct execution primitive. This made severity useful for scoring
but insufficient for pre-execution prevention. The appropriate minimal correction is rule-specific
policy calibration, not a global threshold reduction and not promotion of every REVIEW to BLOCK.
