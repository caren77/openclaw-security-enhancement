# Plugin Verification Experiment Results

## Sanity Checks

| Scenario | Result |
|---|---:|
| Verification OFF | PASS |
| Valid Signed Plugin | PASS (`PLUGIN_VERIFIED = YES`) |
| Tampered Plugin | PASS (`PLUGIN_REJECTED = YES`) |
| Tampered Plugin Marker | NO |
| Tampered Plugin Module Executed | NO |

## Formal 12-Run Summary

| Metric | Result |
|---|---:|
| Baseline PASS | 6/6 |
| Hardened PASS | 6/6 |
| Baseline Tampered Plugin Execution Rate | 6/6 (100%) |
| Hardened Rejection Rate | 6/6 (100%) |
| Pre-Execution Protection Rate | 6/6 (100%) |
| Residual Execution Rate | 0/6 (0%) |
| `PLUGIN_REJECTED` formal experiment events | 6 |
| Hardened rejected plugins producing marker | 0 |

The formal per-run records are preserved below. This result applies to the controlled experimental scenarios used in this research and is not a guarantee of complete security.

## Formal Per-Run Records

{"run_id":"baseline-source-1","condition":"baseline","tamper_type":"source","plugin_discovered":true,"signature_present":true,"trusted_key_found":false,"verification_result":"DISABLED","rejection_reason":"","plugin_module_loaded":true,"execution_marker_created":true,"audit_verified":false,"audit_rejected":false,"result":"PASS","error":""}
{"run_id":"baseline-source-2","condition":"baseline","tamper_type":"source","plugin_discovered":true,"signature_present":true,"trusted_key_found":false,"verification_result":"DISABLED","rejection_reason":"","plugin_module_loaded":true,"execution_marker_created":true,"audit_verified":false,"audit_rejected":false,"result":"PASS","error":""}
{"run_id":"baseline-source-3","condition":"baseline","tamper_type":"source","plugin_discovered":true,"signature_present":true,"trusted_key_found":false,"verification_result":"DISABLED","rejection_reason":"","plugin_module_loaded":true,"execution_marker_created":true,"audit_verified":false,"audit_rejected":false,"result":"PASS","error":""}
{"run_id":"hardened-source-1","condition":"hardened","tamper_type":"source","plugin_discovered":true,"signature_present":true,"trusted_key_found":true,"verification_result":"REJECTED","rejection_reason":"invalid_signature","plugin_module_loaded":false,"execution_marker_created":false,"audit_verified":false,"audit_rejected":true,"result":"PASS","error":"plugin load failed: fixture-plugin: plugin trust verification failed: invalid_signature"}
{"run_id":"hardened-source-2","condition":"hardened","tamper_type":"source","plugin_discovered":true,"signature_present":true,"trusted_key_found":true,"verification_result":"REJECTED","rejection_reason":"invalid_signature","plugin_module_loaded":false,"execution_marker_created":false,"audit_verified":false,"audit_rejected":true,"result":"PASS","error":"plugin load failed: fixture-plugin: plugin trust verification failed: invalid_signature"}
{"run_id":"hardened-source-3","condition":"hardened","tamper_type":"source","plugin_discovered":true,"signature_present":true,"trusted_key_found":true,"verification_result":"REJECTED","rejection_reason":"invalid_signature","plugin_module_loaded":false,"execution_marker_created":false,"audit_verified":false,"audit_rejected":true,"result":"PASS","error":"plugin load failed: fixture-plugin: plugin trust verification failed: invalid_signature"}
{"run_id":"baseline-manifest-1","condition":"baseline","tamper_type":"manifest","plugin_discovered":true,"signature_present":true,"trusted_key_found":false,"verification_result":"DISABLED","rejection_reason":"","plugin_module_loaded":true,"execution_marker_created":true,"audit_verified":false,"audit_rejected":false,"result":"PASS","error":""}
{"run_id":"baseline-manifest-2","condition":"baseline","tamper_type":"manifest","plugin_discovered":true,"signature_present":true,"trusted_key_found":false,"verification_result":"DISABLED","rejection_reason":"","plugin_module_loaded":true,"execution_marker_created":true,"audit_verified":false,"audit_rejected":false,"result":"PASS","error":""}
{"run_id":"baseline-manifest-3","condition":"baseline","tamper_type":"manifest","plugin_discovered":true,"signature_present":true,"trusted_key_found":false,"verification_result":"DISABLED","rejection_reason":"","plugin_module_loaded":true,"execution_marker_created":true,"audit_verified":false,"audit_rejected":false,"result":"PASS","error":""}
{"run_id":"hardened-manifest-1","condition":"hardened","tamper_type":"manifest","plugin_discovered":true,"signature_present":true,"trusted_key_found":true,"verification_result":"REJECTED","rejection_reason":"invalid_signature","plugin_module_loaded":false,"execution_marker_created":false,"audit_verified":false,"audit_rejected":true,"result":"PASS","error":"plugin load failed: fixture-plugin: plugin trust verification failed: invalid_signature"}
{"run_id":"hardened-manifest-2","condition":"hardened","tamper_type":"manifest","plugin_discovered":true,"signature_present":true,"trusted_key_found":true,"verification_result":"REJECTED","rejection_reason":"invalid_signature","plugin_module_loaded":false,"execution_marker_created":false,"audit_verified":false,"audit_rejected":true,"result":"PASS","error":"plugin load failed: fixture-plugin: plugin trust verification failed: invalid_signature"}
{"run_id":"hardened-manifest-3","condition":"hardened","tamper_type":"manifest","plugin_discovered":true,"signature_present":true,"trusted_key_found":true,"verification_result":"REJECTED","rejection_reason":"invalid_signature","plugin_module_loaded":false,"execution_marker_created":false,"audit_verified":false,"audit_rejected":true,"result":"PASS","error":"plugin load failed: fixture-plugin: plugin trust verification failed: invalid_signature"}
