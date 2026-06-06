# Minimal-Disclosure Authentication Experiment Report

## Summary by Mode

| Mode | Runs | Verified | Allowed | Median latency (ms) | Mean personal leakage (bits) | Mean protocol metadata (bits) | Mean exposed fields | Linkable presentations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline-full-identity | 12 | 12 | 7 | 0.0115 | 221 | 0 | 14 | 12 |
| selective-disclosure-merkle-vc | 12 | 12 | 7 | 70.7349 | 2.67 | 256 | 3 | 12 |
| blind-token-minimal-disclosure | 12 | 12 | 7 | 4.0201 | 1 | 149.33 | 1.17 | 0 |

## Correctness Matrix

| User | Policy | Consistent allow/deny decisions |
| --- | --- | --- |
| U001 | cyber_project_level2 | True |
| U001 | student_basic | True |
| U001 | trained_adult_student | True |
| U002 | cyber_project_level2 | True |
| U002 | student_basic | True |
| U002 | trained_adult_student | True |
| U003 | cyber_project_level2 | True |
| U003 | student_basic | True |
| U003 | trained_adult_student | True |
| U004 | cyber_project_level2 | True |
| U004 | student_basic | True |
| U004 | trained_adult_student | True |

## Revocation Check

- Revoked credential: `cred-U001`
- Token issuance after revocation allowed: `False`

## Notes

- Selective-disclosure Merkle credentials reduce field exposure but reveal a stable root.
- Blind tokens reveal only policy satisfaction at redemption time, but support only coarse policy classes.
- Numbers are Python local measurements for a teaching prototype, not production ZKP timings.