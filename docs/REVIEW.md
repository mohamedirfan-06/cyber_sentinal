# Project review — 2026-09-23

Reviewed the source, tests, package exports, and documentation under
`C:\CyberSentinel_AI`. The alternative path `C:\CyberSentinel\_AI` did not exist.
The original generation prompt was not present, so the existing documentation
and test expectations supplied the implementation scope.

## Fixed

- Package import paths, missing public exports, missing core package initializer,
  a missing test import, and an undefined statistics variable.
- Incident event serialization, consistent event IDs across JSON/anomalies/graphs,
  and UTC normalization for mixed naive/offset timestamps.
- Future-event leakage and empty-window crashes in feature extraction.
- Batch-relative anomaly normalization that always scored single events at 0.5.
- Saved models losing preprocessing configuration; custom scaler directories are
  now created, and loading updates detector state after both files are read.
- Brute-force detection missing short bursts within long batches or accepting
  an earlier/unrelated-in-time successful login.
- Account compromise false positives from normal logins; enabled indicator
  requirements and time windows now apply.
- PowerShell detection using authentication events from the future; unusual-device
  metadata can satisfy the configured alternate context check.
- Exfiltration detection ignoring time windows and ordering; sensitive file
  indicators cover the supplied synthetic scenarios.
- Coordinated attacks assembled from unrelated users/devices.
- Correlation labeling ordinary shared activity as attacks, scores exceeding one,
  alphabetical severity ranking, and chain-length settings limiting chain counts.
- Duplicate graph evidence when chains overlap and invalid/private IPv6 handling.
- Severity thresholds interpreted as lower bounds instead of documented upper
  bounds; rule evidence now accumulates with saturation rather than averaging away
  additional detections.
- Mutable default configuration sharing, shallow configuration exports, and
  invalid window/threshold settings.
- Flaky synthetic scenarios: seeded local randomness, distinct attacker IPs,
  consistent brute-force count/timing, and properly ordered compromise events.
- Incorrect MITRE IDs and several overly broad mappings. Pass the Hash uses
  [T1550.002](https://attack.mitre.org/techniques/T1550/002/);
  [T1021.004](https://attack.mitre.org/techniques/T1021/004/) denotes SSH.
  Removed the unsupported T1005.001 entry in favor of the existing
  [T1005](https://attack.mitre.org/techniques/T1005/) mapping. Mappings remain
  heuristic suggestions, not verified descriptions of attacker intent.

## Added

Installable package metadata, dependency declarations, README, command-line demo,
shared IP/file indicators, and 24 regression tests. Original scenario severity
assertions were retained; fixture timestamps and randomness were made explicit.

## Verification

Environment: Windows, Python 3.12.10, NumPy 2.5.2, scikit-learn 1.9.0, joblib 1.5.3.

```powershell
python -m unittest discover -s cybersentinel_ai/tests -v
python -m compileall -q cybersentinel_ai
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

- **58 tests passed**, including all five scenarios, 10-seed attack-rule checks,
  negative temporal/entity cases, strict JSON serialization, model persistence,
  configuration isolation, graph evidence, and a subprocess invocation of
  `python -m cybersentinel_ai --full`.
- The CLI demo returned CRITICAL for the seeded coordinated-attack scenario.
- Python compilation passed.
- Built `dist/cybersentinel_ai-1.0.0-py3-none-any.whl` successfully.
- ML worker pipes and pip temporary build directories needed execution outside
  the tool sandbox. The tests and build succeeded there.
- joblib emitted a NumPy 2.5 deprecation warning during model loading; persistence
  and prediction-equality tests passed. No third-party packages were changed.

## Remaining scope and limitations

This is an offline analysis library, not a complete deployed security platform.
No backend service or dashboard is included. Real-world detection accuracy,
large-stream performance, and production concurrency have not been established.
The engine currently emits at most one aggregate incident per batch and requires
rule evidence for incident creation. ML-only results are exposed as anomalies.
Business-hour checks use UTC. Keyword-based MITRE and sensitive-file mappings
need environment-specific validation. See the README for these API semantics.
