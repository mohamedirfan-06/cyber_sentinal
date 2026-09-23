# CyberSentinel Database Integration

The MySQL schema lives in `database/` and is deliberately API-agnostic.

## Setup

1. Install MySQL 8+.
2. Run `01_create_database.sql`, `02_create_tables.sql`, `03_create_indexes.sql`, and `04_create_views.sql` as an administrator.
3. Replace the placeholder password in `07_create_app_user.sql`, run it as an administrator, and keep the password outside Git.
4. Run `05_seed_demo_data.sql` for the coordinated demo scenario.
5. Configure the Python process with `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`.
6. Install `mysql-connector-python` from `requirements.txt`.

## Member 1 contract

Call `CyberSentinelRepository().persist_result(result)` after `CyberSentinelAI.analyze_events(...)` returns. It inserts incident rows, normalized event rows, and `incident_events` links. The `result` dictionary is the existing engine output; no model behavior is changed. For complete incident evidence, also insert `attack_chains`, `indicators`, `threat_intelligence`, and `incident_mitre_techniques` using the IDs returned by their lookup queries.

## Member 3 dashboard contract

Expose API routes over the views and queries in `database/06_demo_queries.sql`:

- `GET /incidents`: `SELECT * FROM v_incident_summary ORDER BY last_seen DESC`
- `GET /incidents/{id}`: the final detail query using `incident_uuid = ?`
- `GET /events`: `SELECT * FROM v_recent_events ORDER BY event_timestamp DESC`
- `GET /analytics/summary`: counts from `incidents`, severity distribution, and top source IP queries
- `GET /threat-intelligence`: `SELECT * FROM v_threat_intelligence_summary`
- `GET /attack-chain/{incident_id}`: `SELECT * FROM attack_chains WHERE incident_id = ? ORDER BY sequence_number`

No credentials or API keys belong in SQL files or source control.
