# CyberSentinel Database Schema

The schema is implemented in `database/02_create_tables.sql` and uses InnoDB
foreign keys throughout.

```text
users                 devices
  \\                   /
   security_events --- anomalies
          |
   incident_events --- incidents --- attack_chains
          |             |  \\ 
          |             |   incident_mitre_techniques --- mitre_techniques
          |             \
          |              incident_indicators --- indicators --- threat_intelligence
```

`security_events` is the normalized ingestion table. `anomalies` stores ML
scores separately from application risk. `incidents` stores the dashboard-level
finding and `incident_events` preserves its evidence. Indicators and threat
intelligence are separate so one IOC can be checked by multiple providers.

Important indexes cover timestamp ranges, source and destination IPs, users,
event types, incident severity/status/risk, IOC lookup, and attack-chain order.
JSON columns retain provider-specific or source-specific fields without making
the relational contract unstable.