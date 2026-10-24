# Evidence and security limitations

1. Scanner critical/warn/info weights 4/2/0 and threshold 12 are hand-set policy
   constants. The recovered source and notes provide no paper derivation or
   statistical optimization. Existing calibration notes explain rule-policy
   choices, not mathematical validation of these constants.
2. Text/regex heuristics can flag legitimate code or documentation and miss
   aliases, obfuscation, semantic flows, dependencies or later mutation. A valid
   publisher signature does not imply benign behavior.
3. REVIEW remains allowed, including incomplete scan coverage. It must not be
   presented as manual approval or as a prevented attack.
4. Scanner fixtures/harness/raw historical runs were not recovered. Reported
   6/6 detection and 5/6 blocking are qualified historical claims. Unit tests
   performed now cannot substitute for missing formal experiment records.
5. Six prompt-injection designs repeated three times are 18 trials, not 18
   independent designs. The recovered cohort's sandbox metadata precludes
   calling it an unprotected baseline. No matched defense comparison supports
   the requested 60% and 6.7% figures in recovered row-level evidence.
6. No observed exec/write/edit calls does not prove an allowlist caused the
   outcome. Missing tool arguments mean sensitive reads remain unknown. Canary
   leakage is narrower than all prompt-injection success.
7. The misoperation evaluator uses language-dependent permitted-target heuristics
   and file diffs; it may miss harmful read-only actions. REVIEW is inconclusive.
   It does not consistently map subprocess failure to ERROR.
8. The early defense suite mixes simulated local checks and live observations,
   includes three sandbox FAILs and one ERROR, and has a total-count reporting
   bug. PASS is not a uniform end-to-end efficacy measure. Its simple HMAC gate
   is not the later integrated publisher-signature implementation.
9. Public result CSVs are privacy-preserving column projections. Omitted raw
   responses/tool traces limit independent behavioral re-adjudication. Hashes
   establish file identity, not authenticity of historical experimental claims.
10. Recovered code tests validate bounded behavior, not deployment safety. Full
    builds, live gateway experiments, cross-platform execution and formal
    verification are not implied by archive publication.
11. Credential-pattern scanning is heuristic, not a proof of absence. Inputs
    were explicitly allowlisted, raw conversations/configs excluded and known
    synthetic canaries reviewed. New credentials must never be committed.
