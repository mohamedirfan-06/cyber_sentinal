# Second review

Reviewed the current Python modules, public exports, test suite, packaging, CLI,
and documentation. The original 58 tests passed before this review.

## Changes

- Indexed feature windows with binary searches instead of rescanning the whole
  batch for every event; skipped coordinated-rule groups missing required evidence.
- Rejected duplicate input event IDs, malformed entity/metadata fields, non-finite
  JSON values, invalid configuration types, and misspelled configuration sections.
  Configuration dictionaries are copied so later caller changes cannot alter them.
- Preserved the existing fitted model and scaler when retraining fails; rejected
  incompatible saved objects and identical model/scaler output paths before writing.
- Split long correlation chains into overlapping bounded segments instead of
  dropping their final events; updated each segment's timeline, entities and score.
- Preserved the strongest confidence and combined evidence for duplicate technique
  mappings. Added input event IDs to event-, rule-, and chain-derived mappings.
- Fixed the dictionary timestamp path for trailing `Z` on Python 3.10 and corrected
  the documentation example that trained on the same attack events it analyzed.
- Added `test_robustness.py` with 12 tests and a reproducible batch timing script.

## Performance observations

Windows/Python 3.12.10, 3,000 synthetic normal events, seed 42, base time
2026-01-15 00:00 UTC. These are individual local elapsed-time measurements.

| Stage | Before | After |
| --- | ---: | ---: |
| Feature extraction | 2.159 s | 1.243 s |
| Rule evaluation | 0.359 s | 0.025 s |

A repeat of the final benchmark measured 1.174 s and 0.034 s respectively.
Run `python benchmarks/batch_analysis.py` to measure on your machine. This workload
does not establish production capacity; dense event windows still require repeated
aggregation, and correlation can remain expensive for large attack batches.

## Verification scope

Final result: **70 tests passed** in 21.846 seconds. Compilation passed, the wheel
built successfully, and the final wheel passed isolated import, analysis, strict
JSON serialization, and technique event-link checks.

The expanded suite covers all original tests, all five CLI scenarios, model
save/load and failure handling, input validation, JSON output, feature-window
boundaries/order, bounded chain evidence, and technique evidence links.
Compilation and package build checks are also performed. The pure-Python wheel
is imported directly in isolated Python mode to confirm its imports and analysis
work without using the source checkout.

The installed joblib/NumPy combination emits a deprecation warning during model
loading. Prediction/persistence tests pass; third-party packages were not changed.
Real-world detection accuracy, production-scale throughput, and backend/dashboard
integration remain unverified. This folder contains an offline analysis library.
