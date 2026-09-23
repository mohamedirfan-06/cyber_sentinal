USE cybersentinel;

CREATE INDEX idx_events_timestamp ON security_events (event_timestamp);
CREATE INDEX idx_events_source_ip ON security_events (source_ip);
CREATE INDEX idx_events_destination_ip ON security_events (destination_ip);
CREATE INDEX idx_events_username ON security_events (username);
CREATE INDEX idx_events_type ON security_events (event_type);
CREATE INDEX idx_events_severity ON security_events (severity);
CREATE INDEX idx_anomalies_event ON anomalies (event_id);
CREATE INDEX idx_anomalies_flag ON anomalies (is_anomalous, anomaly_score);
CREATE INDEX idx_incidents_severity_risk ON incidents (severity, risk_score DESC);
CREATE INDEX idx_incidents_status ON incidents (status);
CREATE INDEX idx_incidents_last_seen ON incidents (last_seen);
CREATE INDEX idx_indicators_value_type ON indicators (indicator_value(255), indicator_type);
CREATE INDEX idx_threat_reputation ON threat_intelligence (reputation, malicious);
CREATE INDEX idx_attack_chain_incident_sequence ON attack_chains (incident_id, sequence_number);
