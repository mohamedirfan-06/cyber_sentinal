USE cybersentinel;

INSERT INTO users (username, email, department, role, is_privileged)
VALUES ('demo-admin', 'demo-admin@cybersentinel.local', 'Security', 'security_admin', TRUE),
       ('demo-employee', 'demo-employee@cybersentinel.local', 'Engineering', 'developer', FALSE)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP(6);

INSERT INTO devices (device_name, device_type, ip_address, operating_system, department, location, criticality)
VALUES ('WORKSTATION-23', 'WORKSTATION', '10.10.1.23', 'Windows 11', 'Engineering', 'Demo Office', 'MEDIUM'),
       ('DB-SERVER-01', 'DATABASE', '10.10.2.10', 'Ubuntu 24.04', 'Security', 'Demo DC', 'CRITICAL')
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP(6);

INSERT INTO mitre_techniques (technique_id, technique_name, tactic, description)
VALUES ('T1110', 'Brute Force', 'Credential Access', 'Repeated authentication attempts.'),
       ('T1059.001', 'PowerShell', 'Execution', 'Command and scripting interpreter using PowerShell.'),
       ('T1078', 'Valid Accounts', 'Defense Evasion', 'Use of valid account credentials.'),
       ('T1041', 'Exfiltration Over C2 Channel', 'Exfiltration', 'Exfiltration over an existing command channel.')
ON DUPLICATE KEY UPDATE technique_name = VALUES(technique_name), tactic = VALUES(tactic);

SET @admin_id = (SELECT id FROM users WHERE username = 'demo-admin');
SET @workstation_id = (SELECT id FROM devices WHERE device_name = 'WORKSTATION-23');
SET @base_time = CURRENT_TIMESTAMP(6) - INTERVAL 17 MINUTE;

INSERT INTO security_events
(event_uuid, event_timestamp, source, event_type, username, source_ip, device_id, action, severity, raw_message, metadata_json)
SELECT CONCAT('demo-failed-', seq), @base_time + INTERVAL (seq - 1) MINUTE, 'authentication', 'failed_login', 'demo-admin',
       '185.220.101.10', @workstation_id, 'login_failed', 'MEDIUM', 'Synthetic failed login for demo',
       JSON_OBJECT('attempt_number', seq, 'is_demo', TRUE)
FROM (SELECT 1 AS seq UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5
      UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10
      UNION ALL SELECT 11 UNION ALL SELECT 12 UNION ALL SELECT 13 UNION ALL SELECT 14 UNION ALL SELECT 15
      UNION ALL SELECT 16 UNION ALL SELECT 17) attempts
ON DUPLICATE KEY UPDATE event_uuid = event_uuid;

INSERT INTO security_events
(event_uuid, event_timestamp, source, event_type, username, source_ip, device_id, action, severity, metadata_json)
VALUES
('demo-successful-login', @base_time + INTERVAL 18 MINUTE, 'authentication', 'successful_login', 'demo-admin', '185.220.101.10', @workstation_id, 'login_success', 'HIGH', JSON_OBJECT('is_new_ip', TRUE, 'is_demo', TRUE)),
('demo-privilege-escalation', @base_time + INTERVAL 19 MINUTE, 'endpoint', 'privilege_escalation', 'demo-admin', '185.220.101.10', @workstation_id, 'execute', 'HIGH', JSON_OBJECT('is_suspicious', TRUE, 'is_demo', TRUE)),
('demo-powershell', @base_time + INTERVAL 20 MINUTE, 'endpoint', 'powershell_execution', 'demo-admin', '185.220.101.10', @workstation_id, 'execute', 'HIGH', JSON_OBJECT('command', 'Get-Credential; Invoke-WebRequest', 'is_suspicious', TRUE, 'is_demo', TRUE)),
('demo-file-access', @base_time + INTERVAL 21 MINUTE, 'endpoint', 'file_access', 'demo-admin', '185.220.101.10', @workstation_id, 'read', 'HIGH', JSON_OBJECT('file_path', 'C:\\Demo\\sensitive-report.xlsx', 'is_suspicious', TRUE, 'is_demo', TRUE)),
('demo-outbound-transfer', @base_time + INTERVAL 22 MINUTE, 'network', 'data_transfer', 'demo-admin', '10.10.1.23', @workstation_id, 'transfer', 'CRITICAL', JSON_OBJECT('bytes_sent', 524288000, 'is_suspicious', TRUE, 'is_demo', TRUE))
ON DUPLICATE KEY UPDATE event_uuid = event_uuid;

SET @incident_uuid = '00000000-0000-0000-0000-000000000001';
INSERT INTO incidents (incident_uuid, title, attack_type, severity, risk_score, status, description, first_seen, last_seen)
VALUES (@incident_uuid, 'Demo coordinated account compromise', 'Account Compromise / Data Exfiltration', 'CRITICAL', 94, 'INVESTIGATING',
        'Synthetic demonstration: repeated failures followed by valid login, privilege escalation, PowerShell, sensitive file access, and outbound transfer.',
        @base_time, @base_time + INTERVAL 22 MINUTE)
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP(6);
SET @incident_id = (SELECT id FROM incidents WHERE incident_uuid = @incident_uuid);

INSERT INTO incident_events (incident_id, event_id, relationship_type)
SELECT @incident_id, id, IF(event_uuid LIKE 'demo-failed-%', 'supporting', 'evidence')
FROM security_events
WHERE event_uuid LIKE 'demo-%'
ON DUPLICATE KEY UPDATE relationship_type = VALUES(relationship_type);

INSERT INTO attack_chains (incident_id, source_type, source_id, relationship, target_type, target_id, sequence_number)
VALUES (@incident_id, 'IP', '185.220.101.10', 'targets', 'USER', 'demo-admin', 1),
       (@incident_id, 'USER', 'demo-admin', 'uses', 'DEVICE', 'WORKSTATION-23', 2),
       (@incident_id, 'DEVICE', 'WORKSTATION-23', 'executes', 'PROCESS', 'PowerShell', 3),
       (@incident_id, 'PROCESS', 'PowerShell', 'reads', 'FILE', 'sensitive-report.xlsx', 4),
       (@incident_id, 'DEVICE', 'WORKSTATION-23', 'transfers_to', 'EXTERNAL_IP', '185.220.101.10', 5)
ON DUPLICATE KEY UPDATE relationship = VALUES(relationship);

INSERT INTO indicators (indicator_type, indicator_value, first_seen, last_seen, confidence, severity, source)
VALUES ('IP', '185.220.101.10', @base_time, @base_time + INTERVAL 22 MINUTE, 96, 'CRITICAL', 'CyberSentinel demo')
ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen), confidence = VALUES(confidence);
SET @indicator_id = (SELECT id FROM indicators WHERE indicator_type = 'IP' AND indicator_value = '185.220.101.10');
INSERT INTO incident_indicators (incident_id, indicator_id, relationship_type)
VALUES (@incident_id, @indicator_id, 'confirmed')
ON DUPLICATE KEY UPDATE relationship_type = VALUES(relationship_type);
INSERT INTO threat_intelligence (indicator_id, provider, reputation, confidence, country, malicious, threat_category, raw_response_json, checked_at)
VALUES (@indicator_id, 'Synthetic-Intel', 'MALICIOUS', 96, 'ZZ', TRUE, 'Credential attack infrastructure', JSON_OBJECT('demo', TRUE), CURRENT_TIMESTAMP(6));

INSERT INTO incident_mitre_techniques (incident_id, technique_id, evidence, confidence)
SELECT @incident_id, id, '17 failed logins in sequence', 98 FROM mitre_techniques WHERE technique_id = 'T1110'
ON DUPLICATE KEY UPDATE confidence = VALUES(confidence);
INSERT INTO incident_mitre_techniques (incident_id, technique_id, evidence, confidence)
SELECT @incident_id, id, 'PowerShell execution after privilege escalation', 95 FROM mitre_techniques WHERE technique_id = 'T1059.001'
ON DUPLICATE KEY UPDATE confidence = VALUES(confidence);
INSERT INTO incident_mitre_techniques (incident_id, technique_id, evidence, confidence)
SELECT @incident_id, id, 'Successful login from new source IP', 90 FROM mitre_techniques WHERE technique_id = 'T1078'
ON DUPLICATE KEY UPDATE confidence = VALUES(confidence);
INSERT INTO incident_mitre_techniques (incident_id, technique_id, evidence, confidence)
SELECT @incident_id, id, 'Large outbound data transfer', 92 FROM mitre_techniques WHERE technique_id = 'T1041'
ON DUPLICATE KEY UPDATE confidence = VALUES(confidence);
