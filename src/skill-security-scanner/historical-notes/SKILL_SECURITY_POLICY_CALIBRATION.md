# Skill Security Scanner Policy Calibration

## Constraints

This calibration was made only after the first-run REVIEW-gap analysis. It does not change the
aggregate block threshold (`12`), does not add fixture- or marker-specific logic, and does not
modify any experiment fixture. The change is limited to the default decision policy for two
existing, high-confidence findings.

## Rule changes

### `dangerous-exec`

- **Before:** A direct `child_process` execution call produced one critical finding and risk score
  4. Because the rule was not in the default blocking set, an otherwise isolated match was REVIEW.
- **After:** `dangerous-exec` is a default blocking rule. A confirmed direct call to
  `exec`, `execSync`, `spawn`, `spawnSync`, `execFile`, or `execFileSync` in `child_process`
  context is BLOCK.
- **Security rationale:** This finding represents a direct OS-process execution primitive, not a
  shell keyword in prose or a documented CLI command. Once a Skill contains this callable
  primitive, execution can cross the agent-to-host boundary before any later behavior is visible.
- **Potential false-positive impact:** A legitimate Skill that directly invokes `child_process`
  will now require policy remediation or an explicit non-default policy. Broader indicators such
  as `dangerous-runtime-command` remain REVIEW. The first-run 51-skill bundled corpus contained no
  `dangerous-exec` finding, so this does not promote its documented CLI use to BLOCK.

### `dynamic-code-execution`

- **Before:** Direct `eval()` or `new Function()` produced one critical finding and risk score 4.
  In isolation it was REVIEW because the rule was not a default blocking rule.
- **After:** `dynamic-code-execution` is a default blocking rule.
- **Security rationale:** Direct runtime evaluation makes the executed program depend on values
  unavailable to static inspection and is a primary bypass mechanism for pre-execution scanning.
  It is materially stronger evidence than runtime module selection or shell interpolation.
- **Potential false-positive impact:** Legitimate metaprogramming based on `eval()` or `new
  Function()` will be blocked by default. The lower-confidence `dynamic-import` and
  `shell-interpolation` rules remain REVIEW. The first-run bundled corpus contained no direct
  `dynamic-code-execution` finding.

## Deliberately unchanged behavior

### `sensitive-path-access`

- **Before:** Standalone sensitive path access was warn severity, score 2, REVIEW.
- **After:** Unchanged.
- **Security rationale:** Reading a sensitive path is important evidence, but without disclosure,
  external transmission, or execution it is not proof of malicious behavior. The scanner already
  raises correlated secret/file access plus external transmission to stronger exfiltration rules.
- **Potential false-positive impact avoided:** Multiple bundled skills legitimately reference
  local application and credential configuration paths. Globally blocking this rule would create
  benign BLOCK results and erase the intended distinction between capability and malicious flow.

### Aggregate scoring and combination rules

- The default BLOCK threshold remains `12`.
- Finding weights remain critical `4`, warn `2`, info `0`.
- Existing combination rules for secret access plus external network transfer, runtime download
  plus execution, and decoded payload plus execution are unchanged.
- Ordinary network access remains REVIEW, as do dynamic import, shell interpolation, documented
  runtime commands, and credential/security documentation when they lack a blocking combination.
