USE cybersentinel;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(128) NOT NULL,
    email VARCHAR(255) NULL,
    department VARCHAR(128) NULL,
    role ENUM('admin', 'employee', 'developer', 'security_admin', 'service_account') NOT NULL DEFAULT 'employee',
    is_privileged BOOLEAN NOT NULL DEFAULT FALSE,
    status ENUM('ACTIVE', 'DISABLED', 'LOCKED') NOT NULL DEFAULT 'ACTIVE',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS devices (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    device_name VARCHAR(255) NOT NULL,
    device_type ENUM('WORKSTATION', 'SERVER', 'DATABASE', 'NETWORK', 'CLOUD', 'OTHER') NOT NULL DEFAULT 'OTHER',
    ip_address VARCHAR(45) NULL,
    operating_system VARCHAR(128) NULL,
    department VARCHAR(128) NULL,
    location VARCHAR(128) NULL,
    criticality ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    status ENUM('ACTIVE', 'INACTIVE', 'QUARANTINED') NOT NULL DEFAULT 'ACTIVE',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_devices_name (device_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_uuid CHAR(36) NOT NULL,
    event_timestamp DATETIME(6) NOT NULL,
    source ENUM('authentication', 'firewall', 'network', 'endpoint', 'application', 'database') NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    username VARCHAR(128) NULL,
    source_ip VARCHAR(45) NULL,
    destination_ip VARCHAR(45) NULL,
    device_id BIGINT UNSIGNED NULL,
    port SMALLINT UNSIGNED NULL,
    protocol VARCHAR(32) NULL,
    action VARCHAR(64) NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'LOW',
    raw_message TEXT NULL,
    metadata_json JSON NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_security_events_uuid (event_uuid),
    CONSTRAINT fk_events_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
    CONSTRAINT chk_events_port CHECK (port IS NULL OR port BETWEEN 0 AND 65535)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS anomalies (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_id BIGINT UNSIGNED NOT NULL,
    anomaly_score DECIMAL(10,6) NOT NULL,
    risk_score DECIMAL(5,2) NOT NULL DEFAULT 0,
    model_name VARCHAR(128) NOT NULL,
    model_version VARCHAR(64) NULL,
    is_anomalous BOOLEAN NOT NULL DEFAULT FALSE,
    reason VARCHAR(1000) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_anomalies_event FOREIGN KEY (event_id) REFERENCES security_events(id) ON DELETE CASCADE,
    CONSTRAINT chk_anomalies_risk CHECK (risk_score BETWEEN 0 AND 100)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incidents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_uuid CHAR(36) NOT NULL,
    title VARCHAR(255) NOT NULL,
    attack_type VARCHAR(128) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    risk_score DECIMAL(5,2) NOT NULL,
    status ENUM('NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE') NOT NULL DEFAULT 'NEW',
    description TEXT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_incidents_uuid (incident_uuid),
    CONSTRAINT chk_incidents_risk CHECK (risk_score BETWEEN 0 AND 100),
    CONSTRAINT chk_incidents_time CHECK (last_seen >= first_seen)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incident_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    event_id BIGINT UNSIGNED NOT NULL,
    relationship_type ENUM('trigger', 'evidence', 'related', 'supporting') NOT NULL DEFAULT 'evidence',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_incident_event (incident_id, event_id),
    CONSTRAINT fk_incident_events_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_events_event FOREIGN KEY (event_id) REFERENCES security_events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS attack_chains (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    relationship VARCHAR(128) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    sequence_number INT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_attack_chain_step (incident_id, sequence_number),
    CONSTRAINT fk_attack_chains_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS indicators (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    indicator_type ENUM('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL', 'USERNAME', 'PROCESS') NOT NULL,
    indicator_value VARCHAR(2048) NOT NULL,
    first_seen DATETIME(6) NOT NULL,
    last_seen DATETIME(6) NOT NULL,
    confidence DECIMAL(5,2) NOT NULL DEFAULT 0,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    source VARCHAR(128) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_indicator (indicator_type, indicator_value(255)),
    CONSTRAINT chk_indicators_confidence CHECK (confidence BETWEEN 0 AND 100),
    CONSTRAINT chk_indicators_time CHECK (last_seen >= first_seen)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incident_indicators (
    incident_id BIGINT UNSIGNED NOT NULL,
    indicator_id BIGINT UNSIGNED NOT NULL,
    relationship_type ENUM('observed', 'suspected', 'confirmed') NOT NULL DEFAULT 'observed',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (incident_id, indicator_id),
    CONSTRAINT fk_incident_indicators_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_indicators_indicator FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    indicator_id BIGINT UNSIGNED NOT NULL,
    provider VARCHAR(128) NOT NULL,
    reputation ENUM('CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
    confidence DECIMAL(5,2) NOT NULL DEFAULT 0,
    country CHAR(2) NULL,
    isp VARCHAR(255) NULL,
    domain VARCHAR(255) NULL,
    malicious BOOLEAN NOT NULL DEFAULT FALSE,
    threat_category VARCHAR(255) NULL,
    raw_response_json JSON NULL,
    checked_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NULL,
    CONSTRAINT fk_threat_intelligence_indicator FOREIGN KEY (indicator_id) REFERENCES indicators(id) ON DELETE CASCADE,
    CONSTRAINT chk_threat_confidence CHECK (confidence BETWEEN 0 AND 100)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    technique_id VARCHAR(32) NOT NULL,
    technique_name VARCHAR(255) NOT NULL,
    tactic VARCHAR(128) NOT NULL,
    description TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_mitre_technique_id (technique_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incident_mitre_techniques (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    technique_id BIGINT UNSIGNED NOT NULL,
    evidence TEXT NULL,
    confidence DECIMAL(5,2) NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_incident_mitre (incident_id, technique_id),
    CONSTRAINT fk_incident_mitre_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_mitre_technique FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE,
    CONSTRAINT chk_mitre_confidence CHECK (confidence BETWEEN 0 AND 100)
) ENGINE=InnoDB;
