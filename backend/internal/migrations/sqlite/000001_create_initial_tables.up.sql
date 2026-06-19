CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source VARCHAR,
    log_type VARCHAR,
    message VARCHAR,
    parsed JSON,
    received_at DATETIME
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title VARCHAR,
    description VARCHAR,
    severity VARCHAR,
    status VARCHAR,
    assigned_to VARCHAR NULL,
    created_at DATETIME
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id VARCHAR,
    incident_id INTEGER NULL,
    title VARCHAR,
    description VARCHAR,
    severity VARCHAR,
    source_ip VARCHAR,
    failed_attempts INTEGER,
    time_window_minutes INTEGER,
    status VARCHAR,
    created_at DATETIME
);

CREATE INDEX IF NOT EXISTS ix_logs_received_at ON logs (received_at);
CREATE INDEX IF NOT EXISTS ix_alerts_source_rule_status ON alerts (source_ip, rule_id, status);
CREATE INDEX IF NOT EXISTS ix_alerts_incident_id ON alerts (incident_id);
