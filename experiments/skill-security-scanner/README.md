# Scanner experiment: evidence status

The implementation, integration tests and historical architecture/calibration/
REVIEW-gap notes were recovered. The original temporary experiment directory,
its six malicious and six benign fixtures, execution-marker harness and final
per-run CSV/JSON were **not recovered** during this publication pass.

The following is the researcher's historical summary, not a newly verified
dataset or a newly executed experiment:

| Metric | Reported historical value |
| --- | ---: |
| Malicious detection | 6/6 |
| Malicious BLOCK | 5/6 (83.3%) |
| Residual marker execution | 1/6 |
| Benign BLOCK | 0/6 |
| Bundled Skill BLOCK | 0/51 |

One sensitive-path sample reportedly remained REVIEW. That is consistent with
current policy but does not independently verify the historical run. Missing
ALLOW/REVIEW subtotals, baseline rows, ERROR counts and run hashes are not filled
in. No claim is made that the first failed experiment was completely preserved.

Interpretation limits: detection is not blocking; REVIEW is not completed manual
approval; a harmless execution marker only measures reaching a harness step,
not execution of the malicious payload. Conditional protection among blocked
samples differs from protection across all malicious samples. Policy calibration
and evaluation on the same small corpus are not held-out validation.

No replacement fixtures or simulated records were created to match the summary.
To reproduce the historical experiment, recover its original fixture/harness/run
files first. Current source tests are reproducible via `../../patches/README.md`
and are reported separately in `../../docs/PUBLICATION_VALIDATION.md`.
