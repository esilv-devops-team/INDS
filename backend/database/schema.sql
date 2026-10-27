CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 0001

CREATE TABLE devices (
    id INTEGER NOT NULL,
    mac_address VARCHAR(17) NOT NULL,
    current_ip VARCHAR(45),
    hostname VARCHAR(255),
    vendor VARCHAR(255),
    is_trusted BOOLEAN DEFAULT 0 NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    CONSTRAINT pk_devices PRIMARY KEY (id),
    CONSTRAINT ck_devices_mac_format CHECK (mac_address GLOB '[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]'),
    CONSTRAINT ck_devices_observation_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT uq_devices_mac_address UNIQUE (mac_address),
    CONSTRAINT ck_devices_trusted_boolean CHECK (is_trusted IN (0, 1))
);

CREATE INDEX ix_devices_last_seen_at ON devices (last_seen_at);

CREATE TABLE incidents (
    id INTEGER NOT NULL,
    source_device_id INTEGER,
    rule_code VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    risk_score INTEGER,
    severity VARCHAR(10),
    status VARCHAR(20) DEFAULT 'open' NOT NULL,
    evidence_json JSON NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    resolved_at DATETIME,
    CONSTRAINT pk_incidents PRIMARY KEY (id),
    CONSTRAINT ck_incidents_resolution_state CHECK ((status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at >= created_at) OR (status != 'resolved' AND resolved_at IS NULL)),
    CONSTRAINT ck_incidents_severity_values CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    CONSTRAINT ck_incidents_status_values CHECK (status IN ('open', 'investigating', 'resolved')),
    CONSTRAINT ck_incidents_observation_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT ck_incidents_risk_score_range CHECK (risk_score BETWEEN 0 AND 100),
    CONSTRAINT ck_incidents_update_order CHECK (updated_at >= created_at),
    CONSTRAINT fk_incidents_source_device_id_devices FOREIGN KEY(source_device_id) REFERENCES devices (id) ON DELETE SET NULL
);

CREATE INDEX ix_incidents_source_device_id_created_at ON incidents (source_device_id, created_at);

CREATE INDEX ix_incidents_status_created_at ON incidents (status, created_at);

INSERT INTO alembic_version (version_num) VALUES ('0001') RETURNING version_num;

-- Running upgrade 0001 -> 0002

CREATE TABLE administrators (
    id INTEGER NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT 1 NOT NULL,
    created_at DATETIME NOT NULL,
    last_login_at DATETIME,
    CONSTRAINT pk_administrators PRIMARY KEY (id),
    CONSTRAINT ck_administrators_login_order CHECK (last_login_at IS NULL OR last_login_at >= created_at),
    CONSTRAINT ck_administrators_password_hash_present CHECK (length(password_hash) > 0),
    CONSTRAINT ck_administrators_username_format CHECK (username = lower(trim(username)) AND length(username) > 0),
    CONSTRAINT uq_administrators_username UNIQUE (username),
    CONSTRAINT ck_administrators_active_boolean CHECK (is_active IN (0, 1))
);

CREATE TABLE monitoring_runs (
    id INTEGER NOT NULL,
    started_at DATETIME NOT NULL,
    ended_at DATETIME,
    started_by_id INTEGER NOT NULL,
    stopped_by_id INTEGER,
    stop_reason VARCHAR(20),
    CONSTRAINT pk_monitoring_runs PRIMARY KEY (id),
    CONSTRAINT ck_monitoring_runs_stop_actor CHECK ((stop_reason = 'administrator' AND stopped_by_id IS NOT NULL) OR ((stop_reason IS NULL OR stop_reason != 'administrator') AND stopped_by_id IS NULL)),
    CONSTRAINT ck_monitoring_runs_stop_reason_values CHECK (stop_reason IN ('administrator', 'shutdown', 'failure', 'interrupted')),
    CONSTRAINT ck_monitoring_runs_end_state CHECK ((ended_at IS NULL AND stop_reason IS NULL AND stopped_by_id IS NULL) OR (ended_at IS NOT NULL AND stop_reason IS NOT NULL AND ended_at >= started_at)),
    CONSTRAINT fk_monitoring_runs_started_by_id_administrators FOREIGN KEY(started_by_id) REFERENCES administrators (id) ON DELETE RESTRICT,
    CONSTRAINT fk_monitoring_runs_stopped_by_id_administrators FOREIGN KEY(stopped_by_id) REFERENCES administrators (id) ON DELETE RESTRICT
);

CREATE INDEX ix_monitoring_runs_started_by_id ON monitoring_runs (started_by_id);

CREATE INDEX ix_monitoring_runs_stopped_by_id ON monitoring_runs (stopped_by_id);

CREATE UNIQUE INDEX uq_monitoring_runs_unfinished ON monitoring_runs ((1)) WHERE ended_at IS NULL;

CREATE TABLE _alembic_tmp_incidents (
    id INTEGER NOT NULL,
    source_device_id INTEGER,
    rule_code VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    risk_score INTEGER,
    severity VARCHAR(10),
    status VARCHAR(20) DEFAULT 'open' NOT NULL,
    evidence_json JSON NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    resolved_at DATETIME,
    monitoring_run_id INTEGER,
    CONSTRAINT pk_incidents PRIMARY KEY (id),
    CONSTRAINT ck_incidents_status_values CHECK (status IN ('open', 'investigating', 'resolved')),
    CONSTRAINT ck_incidents_update_order CHECK (updated_at >= created_at),
    CONSTRAINT fk_incidents_source_device_id_devices FOREIGN KEY(source_device_id) REFERENCES devices (id) ON DELETE SET NULL,
    CONSTRAINT ck_incidents_severity_values CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    CONSTRAINT ck_incidents_risk_score_range CHECK (risk_score BETWEEN 0 AND 100),
    CONSTRAINT ck_incidents_resolution_state CHECK ((status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at >= created_at) OR (status != 'resolved' AND resolved_at IS NULL)),
    CONSTRAINT ck_incidents_observation_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT fk_incidents_monitoring_run_id_monitoring_runs FOREIGN KEY(monitoring_run_id) REFERENCES monitoring_runs (id) ON DELETE RESTRICT,
    CONSTRAINT ck_incidents_evidence_object CHECK (json_valid(evidence_json) AND json_type(evidence_json) = 'object')
);

INSERT INTO _alembic_tmp_incidents (id, source_device_id, rule_code, source_ip, target_ip, first_seen_at, last_seen_at, risk_score, severity, status, evidence_json, created_at, updated_at, resolved_at) SELECT incidents.id, incidents.source_device_id, incidents.rule_code, incidents.source_ip, incidents.target_ip, incidents.first_seen_at, incidents.last_seen_at, incidents.risk_score, incidents.severity, incidents.status, incidents.evidence_json, incidents.created_at, incidents.updated_at, incidents.resolved_at
FROM incidents;

DROP TABLE incidents;

ALTER TABLE _alembic_tmp_incidents RENAME TO incidents;

CREATE INDEX ix_incidents_status_created_at ON incidents (status, created_at);

CREATE INDEX ix_incidents_source_device_id_created_at ON incidents (source_device_id, created_at);

CREATE INDEX ix_incidents_monitoring_run_id ON incidents (monitoring_run_id);

CREATE TABLE traffic_summaries (
    id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    monitoring_run_id INTEGER NOT NULL,
    window_start DATETIME NOT NULL,
    window_end DATETIME NOT NULL,
    bytes_sent INTEGER DEFAULT 0 NOT NULL,
    bytes_received INTEGER DEFAULT 0 NOT NULL,
    packets_sent INTEGER DEFAULT 0 NOT NULL,
    packets_received INTEGER DEFAULT 0 NOT NULL,
    connection_count INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT pk_traffic_summaries PRIMARY KEY (id),
    CONSTRAINT ck_traffic_summaries_bytes_received_nonnegative CHECK (typeof(bytes_received) = 'integer' AND bytes_received >= 0),
    CONSTRAINT ck_traffic_summaries_bytes_sent_nonnegative CHECK (typeof(bytes_sent) = 'integer' AND bytes_sent >= 0),
    CONSTRAINT ck_traffic_summaries_connection_count_nonnegative CHECK (typeof(connection_count) = 'integer' AND connection_count >= 0),
    CONSTRAINT ck_traffic_summaries_packets_received_nonnegative CHECK (typeof(packets_received) = 'integer' AND packets_received >= 0),
    CONSTRAINT ck_traffic_summaries_packets_sent_nonnegative CHECK (typeof(packets_sent) = 'integer' AND packets_sent >= 0),
    CONSTRAINT ck_traffic_summaries_window_order CHECK (window_end > window_start),
    CONSTRAINT fk_traffic_summaries_device_id_devices FOREIGN KEY(device_id) REFERENCES devices (id) ON DELETE RESTRICT,
    CONSTRAINT fk_traffic_summaries_monitoring_run_id_monitoring_runs FOREIGN KEY(monitoring_run_id) REFERENCES monitoring_runs (id) ON DELETE RESTRICT,
    CONSTRAINT uq_traffic_summaries_run_device_window UNIQUE (monitoring_run_id, device_id, window_start)
);

CREATE INDEX ix_traffic_summaries_device_id_window_start ON traffic_summaries (device_id, window_start);

CREATE INDEX ix_traffic_summaries_window_start ON traffic_summaries (window_start);

CREATE TABLE ai_analyses (
    id INTEGER NOT NULL,
    incident_id INTEGER NOT NULL,
    model VARCHAR(100) NOT NULL,
    prompt_version VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' NOT NULL,
    input_summary_json JSON NOT NULL,
    assessment_json JSON,
    requested_at DATETIME NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    error_message TEXT,
    CONSTRAINT pk_ai_analyses PRIMARY KEY (id),
    CONSTRAINT ck_ai_analyses_completion_state CHECK ((status IN ('pending', 'running') AND completed_at IS NULL) OR (status IN ('succeeded', 'failed', 'cancelled') AND completed_at IS NOT NULL)),
    CONSTRAINT ck_ai_analyses_assessment_object CHECK (assessment_json IS NULL OR (json_valid(assessment_json) AND json_type(assessment_json) = 'object')),
    CONSTRAINT ck_ai_analyses_input_object CHECK (json_valid(input_summary_json) AND json_type(input_summary_json) = 'object'),
    CONSTRAINT ck_ai_analyses_failure_error CHECK (status != 'failed' OR (error_message IS NOT NULL AND length(error_message) > 0)),
    CONSTRAINT ck_ai_analyses_running_started CHECK (status != 'running' OR started_at IS NOT NULL),
    CONSTRAINT ck_ai_analyses_success_result CHECK (status != 'succeeded' OR (started_at IS NOT NULL AND assessment_json IS NOT NULL)),
    CONSTRAINT ck_ai_analyses_status_values CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    CONSTRAINT ck_ai_analyses_completion_order CHECK (completed_at IS NULL OR (completed_at >= requested_at AND (started_at IS NULL OR completed_at >= started_at))),
    CONSTRAINT ck_ai_analyses_start_order CHECK (started_at IS NULL OR started_at >= requested_at),
    CONSTRAINT fk_ai_analyses_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE RESTRICT
);

CREATE INDEX ix_ai_analyses_incident_id_requested_at ON ai_analyses (incident_id, requested_at);

CREATE TABLE response_actions (
    id INTEGER NOT NULL,
    incident_id INTEGER,
    device_id INTEGER,
    ai_analysis_id INTEGER,
    request_key VARCHAR(100) NOT NULL,
    action_type VARCHAR(20) NOT NULL,
    target_mac VARCHAR(17) NOT NULL,
    target_ip VARCHAR(45),
    rate_limit_kbps INTEGER,
    reason TEXT NOT NULL,
    requested_by_id INTEGER,
    approval_status VARCHAR(20) DEFAULT 'pending' NOT NULL,
    decided_by_id INTEGER,
    decided_at DATETIME,
    execution_status VARCHAR(20) DEFAULT 'not_applied' NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    applied_at DATETIME,
    expires_at DATETIME,
    removed_at DATETIME,
    error_message TEXT,
    CONSTRAINT pk_response_actions PRIMARY KEY (id),
    CONSTRAINT ck_response_actions_rate_limit CHECK ((action_type = 'block' AND rate_limit_kbps IS NULL) OR (action_type = 'rate_limit' AND rate_limit_kbps IS NOT NULL AND typeof(rate_limit_kbps) = 'integer' AND rate_limit_kbps > 0)),
    CONSTRAINT ck_response_actions_decision_state CHECK ((approval_status = 'pending' AND decided_by_id IS NULL AND decided_at IS NULL) OR (approval_status IN ('approved', 'rejected') AND decided_by_id IS NOT NULL AND decided_at IS NOT NULL) OR (approval_status = 'cancelled' AND decided_at IS NOT NULL)),
    CONSTRAINT ck_response_actions_removal_state CHECK ((execution_status = 'removed' AND removed_at IS NOT NULL) OR (execution_status != 'removed' AND removed_at IS NULL)),
    CONSTRAINT ck_response_actions_action_values CHECK (action_type IN ('block', 'rate_limit')),
    CONSTRAINT ck_response_actions_approval_values CHECK (approval_status IN ('pending', 'approved', 'rejected', 'cancelled')),
    CONSTRAINT ck_response_actions_execution_approved CHECK (execution_status = 'not_applied' OR approval_status = 'approved'),
    CONSTRAINT ck_response_actions_execution_values CHECK (execution_status IN ('not_applied', 'applying', 'active', 'removing', 'removed', 'failed', 'unknown')),
    CONSTRAINT ck_response_actions_application_time CHECK (execution_status NOT IN ('active', 'removing', 'removed') OR applied_at IS NOT NULL),
    CONSTRAINT ck_response_actions_target_mac_format CHECK (target_mac GLOB '[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]'),
    CONSTRAINT ck_response_actions_application_order CHECK (applied_at IS NULL OR (decided_at IS NOT NULL AND applied_at >= decided_at)),
    CONSTRAINT ck_response_actions_decision_order CHECK (decided_at IS NULL OR decided_at >= created_at),
    CONSTRAINT ck_response_actions_expiry_order CHECK (expires_at IS NULL OR (expires_at > created_at AND (applied_at IS NULL OR expires_at > applied_at))),
    CONSTRAINT ck_response_actions_request_details CHECK (length(request_key) > 0 AND length(trim(reason)) > 0),
    CONSTRAINT ck_response_actions_removal_order CHECK (removed_at IS NULL OR removed_at >= applied_at),
    CONSTRAINT ck_response_actions_update_order CHECK (updated_at >= created_at),
    CONSTRAINT fk_response_actions_ai_analysis_id_ai_analyses FOREIGN KEY(ai_analysis_id) REFERENCES ai_analyses (id) ON DELETE RESTRICT,
    CONSTRAINT fk_response_actions_decided_by_id_administrators FOREIGN KEY(decided_by_id) REFERENCES administrators (id) ON DELETE RESTRICT,
    CONSTRAINT fk_response_actions_device_id_devices FOREIGN KEY(device_id) REFERENCES devices (id) ON DELETE SET NULL,
    CONSTRAINT fk_response_actions_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE RESTRICT,
    CONSTRAINT fk_response_actions_requested_by_id_administrators FOREIGN KEY(requested_by_id) REFERENCES administrators (id) ON DELETE RESTRICT,
    CONSTRAINT uq_response_actions_request_key UNIQUE (request_key)
);

CREATE INDEX ix_response_actions_ai_analysis_id ON response_actions (ai_analysis_id);

CREATE INDEX ix_response_actions_approval_status_created_at ON response_actions (approval_status, created_at);

CREATE INDEX ix_response_actions_decided_by_id ON response_actions (decided_by_id);

CREATE INDEX ix_response_actions_device_id ON response_actions (device_id);

CREATE INDEX ix_response_actions_execution_status_expires_at ON response_actions (execution_status, expires_at);

CREATE INDEX ix_response_actions_incident_id ON response_actions (incident_id);

CREATE INDEX ix_response_actions_requested_by_id ON response_actions (requested_by_id);

CREATE TABLE audit_events (
    id INTEGER NOT NULL,
    occurred_at DATETIME NOT NULL,
    actor_type VARCHAR(20) NOT NULL,
    administrator_id INTEGER,
    event_type VARCHAR(100) NOT NULL,
    outcome VARCHAR(10) NOT NULL,
    device_id INTEGER,
    incident_id INTEGER,
    monitoring_run_id INTEGER,
    ai_analysis_id INTEGER,
    response_action_id INTEGER,
    details_json JSON NOT NULL,
    CONSTRAINT pk_audit_events PRIMARY KEY (id),
    CONSTRAINT ck_audit_events_actor_identity CHECK ((actor_type = 'administrator' AND administrator_id IS NOT NULL) OR (actor_type = 'system' AND administrator_id IS NULL)),
    CONSTRAINT ck_audit_events_actor_values CHECK (actor_type IN ('administrator', 'system')),
    CONSTRAINT ck_audit_events_details_object CHECK (json_valid(details_json) AND json_type(details_json) = 'object'),
    CONSTRAINT ck_audit_events_outcome_values CHECK (outcome IN ('success', 'failure')),
    CONSTRAINT ck_audit_events_event_type_present CHECK (length(trim(event_type)) > 0),
    CONSTRAINT fk_audit_events_administrator_id_administrators FOREIGN KEY(administrator_id) REFERENCES administrators (id) ON DELETE RESTRICT,
    CONSTRAINT fk_audit_events_ai_analysis_id_ai_analyses FOREIGN KEY(ai_analysis_id) REFERENCES ai_analyses (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_device_id_devices FOREIGN KEY(device_id) REFERENCES devices (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_monitoring_run_id_monitoring_runs FOREIGN KEY(monitoring_run_id) REFERENCES monitoring_runs (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_response_action_id_response_actions FOREIGN KEY(response_action_id) REFERENCES response_actions (id) ON DELETE SET NULL
);

CREATE INDEX ix_audit_events_administrator_id ON audit_events (administrator_id);

CREATE INDEX ix_audit_events_ai_analysis_id ON audit_events (ai_analysis_id);

CREATE INDEX ix_audit_events_device_id ON audit_events (device_id);

CREATE INDEX ix_audit_events_event_type_occurred_at ON audit_events (event_type, occurred_at);

CREATE INDEX ix_audit_events_incident_id ON audit_events (incident_id);

CREATE INDEX ix_audit_events_monitoring_run_id ON audit_events (monitoring_run_id);

CREATE INDEX ix_audit_events_occurred_at ON audit_events (occurred_at);

CREATE INDEX ix_audit_events_response_action_id ON audit_events (response_action_id);

UPDATE alembic_version SET version_num='0002' WHERE alembic_version.version_num = '0001';
