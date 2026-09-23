# CyberSentinel AI

Offline Python analysis engine for normalized security events. Includes synthetic
logs, Isolation Forest anomaly detection, five detection rules, event correlation,
attack graphs, risk scoring, incidents, and heuristic MITRE ATT&CK mappings.
This repository contains the analysis library; a web server and dashboard are not included.

## Install and run

From PowerShell in `C:\CyberSentinel_AI`, using Python 3.10 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m unittest discover -s cybersentinel_ai/tests -v
.\.venv\Scripts\python -m cybersentinel_ai
.\.venv\Scripts\python -m cybersentinel_ai --scenario brute_force --full
```

The demo runs locally on synthetic data, trains on a separate normal baseline,
and prints JSON. No external service, credentials, or network traffic is needed.
`--scenario` also accepts `normal_activity`, `account_compromise`, and `data_exfiltration`.
The standard-library unittest runner needs no extra test dependency.

## Python API

```python
from datetime import datetime, timedelta, timezone
from cybersentinel_ai import CyberSentinelAI, LogGenerator

base = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
generator = LogGenerator(seed=42)
engine = CyberSentinelAI()
engine.train_anomaly_detector(generator.generate_normal_activity(300, base - timedelta(days=1)))
result = engine.analyze_events(generator.generate_coordinated_attack(base))
print(result["statistics"])
```

Use `engine.analyze_events_simple(event_dicts)` for normalized JSON input, or
`analyze_events_from_dicts(event_dicts)` for rule analysis without a trained model.
Results can be serialized with `json.dumps(result)`. Event IDs survive dictionary
round trips and link anomalies and graph evidence back to input events.
Event IDs must be unique within each analysis batch. Entity names must be strings;
metadata and raw events must contain finite JSON values. Invalid input and invalid
configuration are rejected with `ValueError` before analysis.
Naive timestamps are interpreted as UTC; offset timestamps are converted to UTC.
The business-hours heuristic uses UTC hours 09:00–17:00.

## Analysis behavior and limits

- Features use the window ending at each event, without future-event leakage.
- ML scores use `clip(0.5 - decision_function, 0, 1)`; they are not probabilities.
  Train on representative normal data before analyzing new activity.
- Detection rules require ordered evidence within configured windows. Account
  compromise requires each enabled indicator. Enabled PowerShell context checks
  are alternatives. Unusual-device detection uses input metadata `is_unusual_device`.
- Correlation requires rule evidence; shared timing alone does not create an incident.
  Each analysis call currently returns at most one aggregate incident for the batch.
  ML-only anomalies remain in `anomalies`; they do not independently open incidents.
- Severity thresholds are inclusive upper bounds: LOW 0–30, MEDIUM 31–60,
  HIGH 61–80, CRITICAL 81–100. Untrained analysis has no ML contribution, so its
  severity can be lower. The score is an investigation heuristic, not confirmation.
- `correlation.max_chain_length` limits events per chain; longer chains are split
  into overlapping segments to retain later evidence. Feature extraction and
  correlation use in-memory batch scans; large production streams need further work.
- Model persistence stores preprocessing configuration alongside the model. Load
  only trusted model files because joblib uses pickle serialization.
- Use separate engine instances for concurrent requests; graph builders and model
  training hold mutable state. Synthetic tests do not establish real-world accuracy.

See [module documentation](docs/AI_MODULE.md) and [review results](docs/REVIEW.md).
The [second review](docs/SECOND_REVIEW.md) records the additional fixes, 70-test
verification, and before/after performance measurements.
