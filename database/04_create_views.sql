USE cybersentinel;

CREATE OR REPLACE VIEW v_active_incidents AS
SELECT incident_uuid, title, attack_type, severity, risk_score, status, first_seen, last_seen
FROM incidents
WHERE status IN ('NEW', 'INVESTIGATING');

CREATE OR REPLACE VIEW v_critical_incidents AS
SELECT incident_uuid, title, attack_type, risk_score, status, first_seen, last_seen
FROM incidents
WHERE severity = 'CRITICAL'
ORDER BY risk_score DESC;

CREATE OR REPLACE VIEW v_recent_events AS
SELECT e.id, e.event_uuid, e.event_timestamp, e.source, e.event_type, e.username,
       e.source_ip, e.destination_ip, e.severity, d.device_name
FROM security_events e
LEFT JOIN devices d ON d.id = e.device_id
WHERE e.event_timestamp >= CURRENT_TIMESTAMP - INTERVAL 24 HOUR;

CREATE OR REPLACE VIEW v_incident_summary AS
SELECT i.id, i.incident_uuid, i.title, i.attack_type, i.severity, i.risk_score, i.status,
       COUNT(DISTINCT ie.event_id) AS event_count,
       COUNT(DISTINCT ii.indicator_id) AS indicator_count,
       i.first_seen, i.last_seen
FROM incidents i
LEFT JOIN incident_events ie ON ie.incident_id = i.id
LEFT JOIN incident_indicators ii ON ii.incident_id = i.id
GROUP BY i.id, i.incident_uuid, i.title, i.attack_type, i.severity, i.risk_score,
         i.status, i.first_seen, i.last_seen;

CREATE OR REPLACE VIEW v_threat_intelligence_summary AS
SELECT reputation, COUNT(*) AS indicator_count, SUM(malicious) AS malicious_count
FROM threat_intelligence
GROUP BY reputation;

CREATE OR REPLACE VIEW v_attack_chain_summary AS
SELECT incident_id, COUNT(*) AS step_count,
       MIN(sequence_number) AS first_step, MAX(sequence_number) AS last_step
FROM attack_chains
GROUP BY incident_id;
