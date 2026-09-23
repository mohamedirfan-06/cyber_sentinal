USE cybersentinel;

-- Total incidents
SELECT COUNT(*) AS total_incidents FROM incidents;

-- Critical incidents
SELECT COUNT(*) AS critical_incidents FROM incidents WHERE severity = 'CRITICAL';

-- High-risk incidents
SELECT * FROM v_incident_summary WHERE risk_score >= 70 ORDER BY risk_score DESC;

-- Recent incidents
SELECT * FROM v_incident_summary ORDER BY last_seen DESC LIMIT 20;

-- Events per hour
SELECT DATE_FORMAT(event_timestamp, '%Y-%m-%d %H:00:00') AS event_hour, COUNT(*) AS event_count
FROM security_events GROUP BY event_hour ORDER BY event_hour;

-- Severity distribution
SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

-- Attack types
SELECT attack_type, COUNT(*) AS count FROM incidents GROUP BY attack_type ORDER BY count DESC;

-- Top source IPs
SELECT source_ip, COUNT(*) AS event_count FROM security_events WHERE source_ip IS NOT NULL
GROUP BY source_ip ORDER BY event_count DESC LIMIT 10;

-- Top affected users
SELECT username, COUNT(*) AS event_count FROM security_events WHERE username IS NOT NULL
GROUP BY username ORDER BY event_count DESC LIMIT 10;

-- Top affected devices
SELECT d.device_name, COUNT(*) AS event_count FROM security_events e JOIN devices d ON d.id = e.device_id
GROUP BY d.id, d.device_name ORDER BY event_count DESC LIMIT 10;

-- Threat intelligence statistics
SELECT * FROM v_threat_intelligence_summary;

-- Full incident detail for a dashboard page
SELECT i.*, e.event_uuid, e.event_timestamp, e.event_type, e.username, e.source_ip, e.severity AS event_severity
FROM incidents i JOIN incident_events ie ON ie.incident_id = i.id
JOIN security_events e ON e.id = ie.event_id
WHERE i.incident_uuid = ? ORDER BY e.event_timestamp;
