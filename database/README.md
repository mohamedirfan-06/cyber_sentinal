# CyberSentinel MySQL Database

MySQL 8+ database: `cybersentinel`.

## Create from scratch

Run these files in order from MySQL Workbench or the MySQL client:

```text
01_create_database.sql
02_create_tables.sql
03_create_indexes.sql
04_create_views.sql
05_seed_demo_data.sql
```

Run `07_create_app_user.sql` separately as an administrator after replacing its placeholder password. Do not commit that password.

The seed contains a synthetic coordinated attack: 17 failed logins, a successful admin login from a new IP, privilege escalation, PowerShell, sensitive file access, outbound transfer, one critical incident, an IOC, threat intelligence, attack-chain steps, and MITRE mappings.

## Python connection

Install `mysql-connector-python`, then set `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`. Use `CyberSentinelRepository` from `cybersentinel_ai.database` to persist engine results. The engine itself remains runnable without MySQL.

## Files

- `02_create_tables.sql`: normalized tables and foreign keys
- `03_create_indexes.sql`: dashboard and investigation indexes
- `04_create_views.sql`: reusable dashboard views
- `05_seed_demo_data.sql`: idempotent synthetic data
- `06_demo_queries.sql`: SOC dashboard queries
- `07_create_app_user.sql`: least-privilege application user

Foreign keys protect event, incident, IOC, threat-intelligence, attack-chain, and MITRE relationships. Risk and confidence values are constrained to 0-100.
