# CyberSentinel AI — AI/ML Security Event Analysis Module

For tested setup commands, current behavior, and limitations, see [README](../README.md).

## Overview

This module is the intelligence engine of the CyberSentinel AI platform. It takes normalized security events from multiple sources (authentication, network, firewall, endpoint, application) and determines:

- Whether behavior is anomalous (ML-based)
- Whether events form suspicious attack patterns (rule-based)
- Whether events from different sources form coordinated attacks (correlation)
- Affected entities (users, devices, IPs)
- Attack timeline and chain
- Risk score and incident severity
- Supporting evidence
- MITRE ATT&CK technique mappings

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      CyberSentinelAI                            │
│  (Main Entry Point - analyze_events())                         │
└─────────────────────────────────────────────────────────────────┘
          │              │              │              │
          ▼              ▼              ▼              ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ Feature  │  │  Rule    │  │  ML      │  │ Correl-  │
    │ Engineer │  │  Engine  │  │ Anomaly  │  │ ation    │
    └──────────┘  └──────────┘  └──────────┘  └──────────┘
          │              │              │              │
          └──────────────┴──────────────┴──────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Risk Engine     │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Incident Builder│
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  MITRE Mapper    │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Attack Graph    │
                    └──────────────────┘
```

### Core Components

| Module | Purpose | Key Class |
|--------|---------|-----------|
| `generator` | Synthetic log generation for testing | `LogGenerator` |
| `features` | Behavioral feature extraction | `FeatureEngineer` |
| `ml` | Isolation Forest anomaly detection | `AnomalyDetector` |
| `rules` | Deterministic attack pattern detection | `RuleEngine` |
| `correlation` | Multi-source event correlation | `CorrelationEngine` |
| `graph` | Attack graph visualization | `AttackGraphBuilder` |
| `risk` | Transparent risk scoring | `RiskEngine` |
| `incident` | Standard incident objects | `Incident`, `IncidentBuilder` |
| `mitre` | MITRE ATT&CK technique mapping | `MitreMapper` |
| `api` | Main integration interface | `CyberSentinelAI`, `analyze_events()` |

---

## Input Schema

### SecurityEvent (Normalized Event)

All events must conform to this schema:

```json
{
  "timestamp": "2026-01-15T12:00:00Z",
  "source": "authentication",
  "event_type": "failed_login",
  "user": "admin",
  "source_ip": "185.123.45.67",
  "destination_ip": null,
  "device": "SERVER-01",
  "port": null,
  "protocol": null,
  "action": "login_failed",
  "metadata": {},
  "is_demo": false
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | ISO8601 string / datetime | Yes | Event timestamp |
| `source` | Enum | Yes | `authentication`, `network`, `firewall`, `endpoint`, `application` |
| `event_type` | Enum | Yes | Specific event type (see below) |
| `user` | string | No | Username |
| `source_ip` | string | No | Source IP address |
| `destination_ip` | string | No | Destination IP address |
| `device` | string | No | Device/hostname |
| `port` | integer | No | Network port |
| `protocol` | string | No | Network protocol |
| `action` | Enum | No | Action taken |
| `metadata` | object | No | Additional context |
| `is_demo` | boolean | No | Marks synthetic/demo data |

### Event Types by Source

**Authentication:**
- `failed_login`, `successful_login`, `logout`, `password_change`, `privilege_escalation`

**Network:**
- `connection`, `port_scan`, `data_transfer`

**Firewall:**
- `blocked_connection`, `allowed_connection`, `rule_violation`

**Endpoint:**
- `process_execution`, `file_access`, `registry_change`, `powershell_execution`, `suspicious_process`

**Application:**
- `api_request`, `auth_failure`, `unusual_endpoint`

### Actions
- `login_failed`, `login_success`, `logout`, `block`, `allow`, `execute`, `read`, `write`, `delete`, `transfer`

---

## Output Schema

### analyze_events() Response

```json
{
  "incidents": [...],
  "anomalies": [...],
  "attack_chains": [...],
  "attack_graph": {...},
  "mitre_techniques": [...],
  "statistics": {...}
}
```

### Incident Object

```json
{
  "incident_id": "INC-A1B2C3D4",
  "severity": "CRITICAL",
  "risk_score": 91,
  "attack_type": "Coordinated Attack",
  "status": "OPEN",
  "start_time": "2026-01-15T12:00:00Z",
  "end_time": "2026-01-15T12:55:00Z",
  "users": ["admin"],
  "devices": ["SERVER-01"],
  "source_ips": ["185.123.45.67", "192.168.1.50"],
  "destination_ips": ["185.123.45.67"],
  "events": [...],
  "evidence": [...],
  "anomaly_score": 0.91,
  "attack_chain": [...],
  "mitre_techniques": [
    {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "confidence": 0.95, "evidence": [...]},
    {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "confidence": 0.88, "evidence": [...]}
  ],
  "recommendations": [
    "Immediately reset credentials for affected user accounts",
    "Block source IPs at firewall perimeter",
    "Isolate affected endpoints from network"
  ],
  "rule_matches": ["brute_force", "coordinated_attack"],
  "correlated_chains": ["CHAIN-A1B2"],
  "graph_id": "GRAPH-C3D4",
  "metadata": {...}
}
```

### Severity Levels

| Score Range | Severity | Description |
|-------------|----------|-------------|
| 0-30 | LOW | Benign or low-confidence anomalies |
| 31-60 | MEDIUM | Suspicious activity requiring review |
| 61-80 | HIGH | Likely attack, investigation needed |
| 81-100 | CRITICAL | Confirmed attack, immediate response |

---

## ML Model

### Isolation Forest Anomaly Detector

**Algorithm:** `sklearn.ensemble.IsolationForest`

**Configuration:**
```python
{
  "contamination": 0.1,      # Expected anomaly ratio
  "n_estimators": 100,       # Number of trees
  "max_samples": "auto",     # Subsample size
  "random_state": 42,        # Reproducibility
  "anomaly_threshold": 0.5   # Normalized score threshold
}
```

**Training:**
- Requires baseline "normal" events
- Call `train(normal_events)` before `predict()`
- Model and scaler persisted via `save()`/`load()`

**Features (28 total):**

| Category | Features |
|----------|----------|
| Authentication | failed_login_count, successful_login_count, login_frequency_per_min, unusual_login_time_score, new_source_ip_count, privilege_change_count, unique_users_per_ip, unique_ips_per_user |
| Network | connections_per_minute, unique_destination_count, bytes_sent_total, bytes_received_total, bytes_sent_per_connection, unusual_port_score, external_connection_ratio |
| Endpoint | suspicious_process_count, powershell_execution_count, endpoint_privilege_change_count, unique_processes_executed, file_access_count, sensitive_file_access_count |
| Application | request_frequency_per_min, auth_failure_count, unusual_endpoint_count, unique_endpoints_accessed |
| Cross-Source | source_diversity_score, event_type_diversity, time_span_minutes |

**Output per Event:**
- `raw_score`: Isolation Forest decision function output
- `normalized_score`: clip(0.5 - raw_score, 0, 1); higher = more anomalous
- `is_anomaly`: Boolean (normalized_score > threshold)
- `feature_contributions`: Per-feature deviation scores

---

## Rule Engine

Deterministic rules with configurable thresholds.

### Rules Implemented

| Rule | Type | Triggers | Severity |
|------|------|----------|----------|
| Brute Force | `brute_force` | ≥5 failed logins (15min) + same IP/user + optional success | HIGH/MEDIUM |
| Account Compromise | `account_compromise` | New IP + success + unusual time + privilege escalation | CRITICAL/HIGH |
| Suspicious PowerShell | `suspicious_powershell` | PS execution + auth anomaly OR unusual device | HIGH/MEDIUM |
| Data Exfiltration | `data_exfiltration` | Sensitive file access + large transfer (>100MB) + unusual dest | CRITICAL/HIGH |
| Coordinated Attack | `coordinated_attack` | Auth anomaly + endpoint anomaly + network anomaly (30min) | CRITICAL |

### Configurable Thresholds

```python
RuleThresholds(
    brute_force_failed_attempts=5,
    brute_force_time_window_minutes=15,
    brute_force_require_success=True,
    account_compromise_time_window_hours=24,
    exfiltration_large_transfer_bytes=104857600,  # 100 MB
    coordinated_time_window_minutes=30,
    # ... more
)
```

---

## Event Correlation

### Correlation Strategies

1. **Entity-Based:** Groups events sharing IP, user, device, process, session
2. **Temporal:** Events within time window (default 30 min) across sources
3. **Attack Pattern:** Matches known sequences (brute force → compromise → exfil)

### AttackChain Output

```json
{
  "chain_id": "CHAIN-A1B2",
  "attack_type": "brute_force_to_compromise",
  "correlation_score": 0.92,
  "start_time": "2026-01-15T12:00:00Z",
  "end_time": "2026-01-15T12:55:00Z",
  "entities": {
    "users": ["admin"],
    "devices": ["SERVER-01"],
    "source_ips": ["185.123.45.67"],
    "processes": ["powershell.exe"]
  },
  "steps": [
    {"sequence": 0, "event_type": "failed_login", "source": "authentication", ...},
    {"sequence": 1, "event_type": "successful_login", "source": "authentication", ...},
    ...
  ]
}
```

---

## Attack Graph

### Node Types
- `ip` — Source IP addresses
- `user` — User accounts
- `device` — Hostnames/devices
- `process` — Process names
- `destination` — Destination IPs
- `file` — File paths
- `session` — Session IDs

### Edge Types
- `logged_into` — IP/User → Device
- `accessed` — User/Process → File
- `executed` — User → Process
- `connected_to` — IP → Destination
- `transferred_to` — IP → Destination (data transfer)
- `escalated_on` — User → Device (privilege escalation)
- `spawned` — Process → Process

### Export Formats

```python
graph.to_dict()        # Native format
graph.to_cytoscape()   # Cytoscape.js compatible
```

---

## Risk Scoring

### Formula

```
risk_score = 
  ML_anomaly * 0.30 +
  Rule_matches * 0.30 +
  Correlation * 0.20 +
  Cross_source * 0.10 +
  Suspicious_behavior * 0.10
```

### Components

| Component | Weight | Calculation |
|-----------|--------|-------------|
| ML Anomaly | 30% | 0.7 × max normalized score + 0.3 × anomaly ratio |
| Rule Matches | 30% | Severity-weighted confidence sum |
| Correlation | 20% | Max chain score + chain count bonus |
| Cross-Source | 10% | Source diversity (max 5 sources) |
| Behavior | 10% | Heuristic suspicious pattern checks |

### Transparency

Every risk score includes full breakdown in `metadata.risk_breakdown`.

---

## MITRE ATT&CK Mapping

### Technique Coverage (41 heuristic mappings)

| Tactic | Techniques |
|--------|------------|
| Initial Access | T1078, T1078.002 |
| Execution | T1059, T1059.001, T1059.003, T1059.007 |
| Privilege Escalation | T1068, T1134, T1134.001 |
| Defense Evasion | T1562, T1562.001, T1070, T1027 |
| Credential Access | T1110, T1110.001, T1110.003, T1003, T1003.001, T1555 |
| Discovery | T1087, T1087.001, T1087.002, T1018, T1016, T1082 |
| Lateral Movement | T1021, T1021.001, T1550.002, T1550 |
| Collection | T1005, T1039, T1560 |
| Command & Control | T1071, T1071.001, T1573 |
| Exfiltration | T1041, T1048, T1567 |
| Impact | T1486, T1490 |

### Mapping Sources

1. **Event-level:** Direct keyword matching in event metadata
2. **Rule-level:** Rule type → technique mappings
3. **Chain-level:** Attack pattern → technique sequences

### Output

```json
[
  {
    "technique_id": "T1110.001",
    "name": "Password Guessing",
    "tactic": "Credential Access",
    "description": "Systematic guessing of passwords.",
    "confidence": 0.95,
    "evidence": ["failed_login: multiple_failed_logins detected (user=admin, ip=185.123.45.67)"]
  }
]
```

---

## Integration Instructions

### For Member 2 (FastAPI Backend)

```python
# Install dependencies
python -m pip install -e .

# Import and use
from cybersentinel_ai import analyze_events, SecurityEvent

# Option 1: Direct function call
events = [SecurityEvent.from_dict(e) for e in request_json["events"]]
result = analyze_events(events)

# Option 2: Class-based (persistent model)
from cybersentinel_ai import CyberSentinelAI

engine = CyberSentinelAI()
engine.train_anomaly_detector(baseline_events)
result = engine.analyze_events(new_events)

# Return result["incidents"] to Member 3's dashboard
```

### For Member 3 (React Dashboard)

```javascript
// Expected incident format for dashboard
const incident = {
  incident_id: "INC-A1B2C3D4",
  severity: "CRITICAL",
  risk_score: 91,
  attack_type: "Coordinated Attack",
  start_time: "2026-01-15T12:00:00Z",
  end_time: "2026-01-15T12:55:00Z",
  users: ["admin"],
  devices: ["SERVER-01"],
  source_ips: ["185.123.45.67"],
  mitre_techniques: [
    {technique_id: "T1110", name: "Brute Force", tactic: "Credential Access", confidence: 0.95}
  ],
  attack_chain: [...],
  attack_graph: {...},  // Convert with the Python builder: AttackGraphBuilder().build_from_events(events).to_cytoscape()
  recommendations: [...]
}
```

### Configuration

```python
from cybersentinel_ai import Config, analyze_events

config = Config.from_dict({
    "rules": {
        "brute_force_failed_attempts": 10,
        "brute_force_time_window_minutes": 10
    },
    "ml": {
        "contamination": 0.05,
        "anomaly_threshold": 0.6
    },
    "risk": {
        "ml_weight": 0.4,
        "rule_weight": 0.3
    }
})

result = analyze_events(events, config=config)
```

---

## Running Tests

```bash
cd C:\CyberSentinel_AI
python -m unittest discover -s cybersentinel_ai/tests -v
```

### Test Coverage

| Test Class | Scenarios Covered |
|------------|-------------------|
| `TestLogGenerator` | All 5 scenarios + validation |
| `TestFeatureEngineer` | Feature extraction, matrix |
| `TestAnomalyDetector` | Train/predict, save/load, attack detection |
| `TestRuleEngine` | All 5 rule types + normal activity |
| `TestCorrelationEngine` | Entity, temporal, pattern correlation |
| `TestAttackGraph` | Graph building, export formats |
| `TestRiskEngine` | Low vs critical risk scoring |
| `TestIncidentCreation` | Full pipeline incident generation |
| `TestFullPipeline` | All scenarios severity validation |
| `TestConfig` | Config serialization |

---

## Demo Log Generator

```python
from cybersentinel_ai import LogGenerator

gen = LogGenerator()

# Generate specific scenarios
events = gen.generate_scenario("coordinated_attack")
events = gen.generate_brute_force()
events = gen.generate_account_compromise()
events = gen.generate_data_exfiltration()
events = gen.generate_normal_activity(100)

# Mixed scenario (background + attacks)
events = gen.generate_mixed()
```

All generated events have `is_demo: true` and realistic timestamps.

---

## Dependencies

```
scikit-learn >= 1.3.0
numpy >= 1.24.0
joblib >= 1.3.0

```

Standard library only: `dataclasses`, `datetime`, `typing`, `collections`, `enum`, `uuid`, `pathlib`

---

## File Structure

```
cybersentinel_ai/
├── __init__.py              # Package exports
├── core/
│   ├── __init__.py
│   ├── schemas.py               # SecurityEvent, FeatureVector, enums
│   └── config.py                # Config, thresholds
├── generator/
│   ├── __init__.py
│   └── log_generator.py         # 5 attack scenarios
├── features/
│   ├── __init__.py
│   └── feature_engineer.py      # 28 behavioral features
├── ml/
│   ├── __init__.py
│   └── anomaly_detector.py      # IsolationForest wrapper
├── rules/
│   ├── __init__.py
│   └── rule_engine.py           # 5 deterministic rules
├── correlation/
│   ├── __init__.py
│   └── correlation_engine.py    # 3 correlation strategies
├── graph/
│   ├── __init__.py
│   └── attack_graph.py          # Graph build + Cytoscape export
├── risk/
│   ├── __init__.py
│   └── risk_engine.py           # Weighted risk scoring
├── incident/
│   ├── __init__.py
│   └── incident.py              # Standard incident object
├── mitre/
│   ├── __init__.py
│   └── mitre_mapper.py          # 41 heuristic mappings
├── api/
│   └── __init__.py              # CyberSentinelAI, analyze_events()
└── tests/
    ├── __init__.py
    └── test_all.py              # Comprehensive test suite
```

---

## Quick Start

Train the ML detector on separate normal baseline data as shown in the [README](../README.md).
The example below runs rules without ML; exact scores depend on inputs and configuration.

```python
from cybersentinel_ai import LogGenerator, analyze_events

# 1. Generate demo attack data
gen = LogGenerator()
events = gen.generate_coordinated_attack()

# 2. Analyze with rules (no baseline model trained)
result = analyze_events(events)

# 3. Inspect results
incident = result["incidents"][0]
print(f"Severity: {incident['severity']}")
print(f"Risk Score: {incident['risk_score']}")
print(f"MITRE: {[t['technique_id'] for t in incident['mitre_techniques']]}")
# Technique suggestions depend on the observed evidence.
```

---

## Notes

- **No external API dependencies** — fully offline capable
- **No frontend coupling** — pure Python package with JSON-serializable outputs
- **Configurable thresholds** — all rules tunable via `Config`
- **Model persistence** — `AnomalyDetector.save()`/`load()` for production
- **Demo data marked** — all generator events have `is_demo: true`
- **Concurrency** — use separate engine instances for concurrent analyses; builders and model training are mutable.
