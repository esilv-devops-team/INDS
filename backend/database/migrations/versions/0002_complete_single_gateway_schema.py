"""complete single gateway schema

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def _incidents_snapshot(*, expanded=False):
    """Frozen schema snapshots for SQLite batch rebuilds, including offline SQL."""
    metadata = sa.MetaData()
    sa.Table("devices", metadata, sa.Column("id", sa.Integer, primary_key=True))
    sa.Table("monitoring_runs", metadata, sa.Column("id", sa.Integer, primary_key=True))
    table = sa.Table(
        "incidents", metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source_device_id", sa.Integer),
        sa.Column("rule_code", sa.String(100), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("target_ip", sa.String(45), nullable=False),
        sa.Column("first_seen_at", sa.DateTime, nullable=False),
        sa.Column("last_seen_at", sa.DateTime, nullable=False),
        sa.Column("risk_score", sa.Integer),
        sa.Column("severity", sa.String(10)),
        sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'open'")),
        sa.Column("evidence_json", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("resolved_at", sa.DateTime),
        sa.ForeignKeyConstraint(["source_device_id"], ["devices.id"],
                                name="fk_incidents_source_device_id_devices", ondelete="SET NULL"),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_incidents_risk_score_range"),
        sa.CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')", name="ck_incidents_severity_values"),
        sa.CheckConstraint("status IN ('open', 'investigating', 'resolved')", name="ck_incidents_status_values"),
        sa.CheckConstraint("last_seen_at >= first_seen_at", name="ck_incidents_observation_order"),
        sa.CheckConstraint("updated_at >= created_at", name="ck_incidents_update_order"),
        sa.CheckConstraint("(status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at >= created_at) "
                           "OR (status != 'resolved' AND resolved_at IS NULL)", name="ck_incidents_resolution_state"),
    )
    table.primary_key.name = "pk_incidents"
    sa.Index("ix_incidents_status_created_at", table.c.status, table.c.created_at)
    sa.Index("ix_incidents_source_device_id_created_at", table.c.source_device_id, table.c.created_at)
    if expanded:
        table.append_column(sa.Column("monitoring_run_id", sa.Integer))
        table.append_constraint(sa.ForeignKeyConstraint(
            ["monitoring_run_id"], ["monitoring_runs.id"],
            name="fk_incidents_monitoring_run_id_monitoring_runs", ondelete="RESTRICT"))
        table.append_constraint(sa.CheckConstraint(
            "json_valid(evidence_json) AND json_type(evidence_json) = 'object'", name="ck_incidents_evidence_object"))
        sa.Index("ix_incidents_monitoring_run_id", table.c.monitoring_run_id)
    return table


def upgrade():
    op.create_table('administrators',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('is_active', sa.Boolean(create_constraint=True, name='active_boolean'), server_default=sa.text('1'), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_login_at', sa.DateTime(), nullable=True),
    sa.CheckConstraint('last_login_at IS NULL OR last_login_at >= created_at', name=op.f('ck_administrators_login_order')),
    sa.CheckConstraint('length(password_hash) > 0', name=op.f('ck_administrators_password_hash_present')),
    sa.CheckConstraint('username = lower(trim(username)) AND length(username) > 0', name=op.f('ck_administrators_username_format')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_administrators')),
    sa.UniqueConstraint('username', name=op.f('uq_administrators_username'))
    )
    op.create_table('monitoring_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('ended_at', sa.DateTime(), nullable=True),
    sa.Column('started_by_id', sa.Integer(), nullable=False),
    sa.Column('stopped_by_id', sa.Integer(), nullable=True),
    sa.Column('stop_reason', sa.String(length=20), nullable=True),
    sa.CheckConstraint("(stop_reason = 'administrator' AND stopped_by_id IS NOT NULL) OR ((stop_reason IS NULL OR stop_reason != 'administrator') AND stopped_by_id IS NULL)", name=op.f('ck_monitoring_runs_stop_actor')),
    sa.CheckConstraint("stop_reason IN ('administrator', 'shutdown', 'failure', 'interrupted')", name=op.f('ck_monitoring_runs_stop_reason_values')),
    sa.CheckConstraint('(ended_at IS NULL AND stop_reason IS NULL AND stopped_by_id IS NULL) OR (ended_at IS NOT NULL AND stop_reason IS NOT NULL AND ended_at >= started_at)', name=op.f('ck_monitoring_runs_end_state')),
    sa.ForeignKeyConstraint(['started_by_id'], ['administrators.id'], name=op.f('fk_monitoring_runs_started_by_id_administrators'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['stopped_by_id'], ['administrators.id'], name=op.f('fk_monitoring_runs_stopped_by_id_administrators'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_monitoring_runs'))
    )
    with op.batch_alter_table('monitoring_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_monitoring_runs_started_by_id'), ['started_by_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_monitoring_runs_stopped_by_id'), ['stopped_by_id'], unique=False)

    op.execute("CREATE UNIQUE INDEX uq_monitoring_runs_unfinished ON monitoring_runs ((1)) WHERE ended_at IS NULL")

    with op.batch_alter_table('incidents', copy_from=_incidents_snapshot()) as batch_op:
        batch_op.add_column(sa.Column('monitoring_run_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_incidents_monitoring_run_id'), ['monitoring_run_id'], unique=False)
        batch_op.create_foreign_key(batch_op.f('fk_incidents_monitoring_run_id_monitoring_runs'), 'monitoring_runs', ['monitoring_run_id'], ['id'], ondelete='RESTRICT')

        batch_op.create_check_constraint(op.f("ck_incidents_evidence_object"), "json_valid(evidence_json) AND json_type(evidence_json) = 'object'")

    op.create_table('traffic_summaries',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('monitoring_run_id', sa.Integer(), nullable=False),
    sa.Column('window_start', sa.DateTime(), nullable=False),
    sa.Column('window_end', sa.DateTime(), nullable=False),
    sa.Column('bytes_sent', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('bytes_received', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('packets_sent', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('packets_received', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('connection_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.CheckConstraint("typeof(bytes_received) = 'integer' AND bytes_received >= 0", name=op.f('ck_traffic_summaries_bytes_received_nonnegative')),
    sa.CheckConstraint("typeof(bytes_sent) = 'integer' AND bytes_sent >= 0", name=op.f('ck_traffic_summaries_bytes_sent_nonnegative')),
    sa.CheckConstraint("typeof(connection_count) = 'integer' AND connection_count >= 0", name=op.f('ck_traffic_summaries_connection_count_nonnegative')),
    sa.CheckConstraint("typeof(packets_received) = 'integer' AND packets_received >= 0", name=op.f('ck_traffic_summaries_packets_received_nonnegative')),
    sa.CheckConstraint("typeof(packets_sent) = 'integer' AND packets_sent >= 0", name=op.f('ck_traffic_summaries_packets_sent_nonnegative')),
    sa.CheckConstraint('window_end > window_start', name=op.f('ck_traffic_summaries_window_order')),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], name=op.f('fk_traffic_summaries_device_id_devices'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['monitoring_run_id'], ['monitoring_runs.id'], name=op.f('fk_traffic_summaries_monitoring_run_id_monitoring_runs'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_traffic_summaries')),
    sa.UniqueConstraint('monitoring_run_id', 'device_id', 'window_start', name='uq_traffic_summaries_run_device_window')
    )
    with op.batch_alter_table('traffic_summaries', schema=None) as batch_op:
        batch_op.create_index('ix_traffic_summaries_device_id_window_start', ['device_id', 'window_start'], unique=False)
        batch_op.create_index(batch_op.f('ix_traffic_summaries_window_start'), ['window_start'], unique=False)

    op.create_table('ai_analyses',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=False),
    sa.Column('model', sa.String(length=100), nullable=False),
    sa.Column('prompt_version', sa.String(length=100), nullable=False),
    sa.Column('status', sa.String(length=20), server_default=sa.text("'pending'"), nullable=False),
    sa.Column('input_summary_json', sa.JSON(none_as_null=True), nullable=False),
    sa.Column('assessment_json', sa.JSON(none_as_null=True), nullable=True),
    sa.Column('requested_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.CheckConstraint("(status IN ('pending', 'running') AND completed_at IS NULL) OR (status IN ('succeeded', 'failed', 'cancelled') AND completed_at IS NOT NULL)", name=op.f('ck_ai_analyses_completion_state')),
    sa.CheckConstraint("assessment_json IS NULL OR (json_valid(assessment_json) AND json_type(assessment_json) = 'object')", name=op.f('ck_ai_analyses_assessment_object')),
    sa.CheckConstraint("json_valid(input_summary_json) AND json_type(input_summary_json) = 'object'", name=op.f('ck_ai_analyses_input_object')),
    sa.CheckConstraint("status != 'failed' OR (error_message IS NOT NULL AND length(error_message) > 0)", name=op.f('ck_ai_analyses_failure_error')),
    sa.CheckConstraint("status != 'running' OR started_at IS NOT NULL", name=op.f('ck_ai_analyses_running_started')),
    sa.CheckConstraint("status != 'succeeded' OR (started_at IS NOT NULL AND assessment_json IS NOT NULL)", name=op.f('ck_ai_analyses_success_result')),
    sa.CheckConstraint("status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')", name=op.f('ck_ai_analyses_status_values')),
    sa.CheckConstraint('completed_at IS NULL OR (completed_at >= requested_at AND (started_at IS NULL OR completed_at >= started_at))', name=op.f('ck_ai_analyses_completion_order')),
    sa.CheckConstraint('started_at IS NULL OR started_at >= requested_at', name=op.f('ck_ai_analyses_start_order')),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_ai_analyses_incident_id_incidents'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_analyses'))
    )
    with op.batch_alter_table('ai_analyses', schema=None) as batch_op:
        batch_op.create_index('ix_ai_analyses_incident_id_requested_at', ['incident_id', 'requested_at'], unique=False)

    op.create_table('response_actions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('device_id', sa.Integer(), nullable=True),
    sa.Column('ai_analysis_id', sa.Integer(), nullable=True),
    sa.Column('request_key', sa.String(length=100), nullable=False),
    sa.Column('action_type', sa.String(length=20), nullable=False),
    sa.Column('target_mac', sa.String(length=17), nullable=False),
    sa.Column('target_ip', sa.String(length=45), nullable=True),
    sa.Column('rate_limit_kbps', sa.Integer(), nullable=True),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('requested_by_id', sa.Integer(), nullable=True),
    sa.Column('approval_status', sa.String(length=20), server_default=sa.text("'pending'"), nullable=False),
    sa.Column('decided_by_id', sa.Integer(), nullable=True),
    sa.Column('decided_at', sa.DateTime(), nullable=True),
    sa.Column('execution_status', sa.String(length=20), server_default=sa.text("'not_applied'"), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('applied_at', sa.DateTime(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('removed_at', sa.DateTime(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.CheckConstraint("(action_type = 'block' AND rate_limit_kbps IS NULL) OR (action_type = 'rate_limit' AND rate_limit_kbps IS NOT NULL AND typeof(rate_limit_kbps) = 'integer' AND rate_limit_kbps > 0)", name=op.f('ck_response_actions_rate_limit')),
    sa.CheckConstraint("(approval_status = 'pending' AND decided_by_id IS NULL AND decided_at IS NULL) OR (approval_status IN ('approved', 'rejected') AND decided_by_id IS NOT NULL AND decided_at IS NOT NULL) OR (approval_status = 'cancelled' AND decided_at IS NOT NULL)", name=op.f('ck_response_actions_decision_state')),
    sa.CheckConstraint("(execution_status = 'removed' AND removed_at IS NOT NULL) OR (execution_status != 'removed' AND removed_at IS NULL)", name=op.f('ck_response_actions_removal_state')),
    sa.CheckConstraint("action_type IN ('block', 'rate_limit')", name=op.f('ck_response_actions_action_values')),
    sa.CheckConstraint("approval_status IN ('pending', 'approved', 'rejected', 'cancelled')", name=op.f('ck_response_actions_approval_values')),
    sa.CheckConstraint("execution_status = 'not_applied' OR approval_status = 'approved'", name=op.f('ck_response_actions_execution_approved')),
    sa.CheckConstraint("execution_status IN ('not_applied', 'applying', 'active', 'removing', 'removed', 'failed', 'unknown')", name=op.f('ck_response_actions_execution_values')),
    sa.CheckConstraint("execution_status NOT IN ('active', 'removing', 'removed') OR applied_at IS NOT NULL", name=op.f('ck_response_actions_application_time')),
    sa.CheckConstraint("target_mac GLOB '[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]'", name=op.f('ck_response_actions_target_mac_format')),
    sa.CheckConstraint('applied_at IS NULL OR (decided_at IS NOT NULL AND applied_at >= decided_at)', name=op.f('ck_response_actions_application_order')),
    sa.CheckConstraint('decided_at IS NULL OR decided_at >= created_at', name=op.f('ck_response_actions_decision_order')),
    sa.CheckConstraint('expires_at IS NULL OR (expires_at > created_at AND (applied_at IS NULL OR expires_at > applied_at))', name=op.f('ck_response_actions_expiry_order')),
    sa.CheckConstraint('length(request_key) > 0 AND length(trim(reason)) > 0', name=op.f('ck_response_actions_request_details')),
    sa.CheckConstraint('removed_at IS NULL OR removed_at >= applied_at', name=op.f('ck_response_actions_removal_order')),
    sa.CheckConstraint('updated_at >= created_at', name=op.f('ck_response_actions_update_order')),
    sa.ForeignKeyConstraint(['ai_analysis_id'], ['ai_analyses.id'], name=op.f('fk_response_actions_ai_analysis_id_ai_analyses'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['decided_by_id'], ['administrators.id'], name=op.f('fk_response_actions_decided_by_id_administrators'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], name=op.f('fk_response_actions_device_id_devices'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_response_actions_incident_id_incidents'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['requested_by_id'], ['administrators.id'], name=op.f('fk_response_actions_requested_by_id_administrators'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_response_actions')),
    sa.UniqueConstraint('request_key', name=op.f('uq_response_actions_request_key'))
    )
    with op.batch_alter_table('response_actions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_response_actions_ai_analysis_id'), ['ai_analysis_id'], unique=False)
        batch_op.create_index('ix_response_actions_approval_status_created_at', ['approval_status', 'created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_response_actions_decided_by_id'), ['decided_by_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_response_actions_device_id'), ['device_id'], unique=False)
        batch_op.create_index('ix_response_actions_execution_status_expires_at', ['execution_status', 'expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_response_actions_incident_id'), ['incident_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_response_actions_requested_by_id'), ['requested_by_id'], unique=False)

    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('occurred_at', sa.DateTime(), nullable=False),
    sa.Column('actor_type', sa.String(length=20), nullable=False),
    sa.Column('administrator_id', sa.Integer(), nullable=True),
    sa.Column('event_type', sa.String(length=100), nullable=False),
    sa.Column('outcome', sa.String(length=10), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=True),
    sa.Column('incident_id', sa.Integer(), nullable=True),
    sa.Column('monitoring_run_id', sa.Integer(), nullable=True),
    sa.Column('ai_analysis_id', sa.Integer(), nullable=True),
    sa.Column('response_action_id', sa.Integer(), nullable=True),
    sa.Column('details_json', sa.JSON(none_as_null=True), nullable=False),
    sa.CheckConstraint("(actor_type = 'administrator' AND administrator_id IS NOT NULL) OR (actor_type = 'system' AND administrator_id IS NULL)", name=op.f('ck_audit_events_actor_identity')),
    sa.CheckConstraint("actor_type IN ('administrator', 'system')", name=op.f('ck_audit_events_actor_values')),
    sa.CheckConstraint("json_valid(details_json) AND json_type(details_json) = 'object'", name=op.f('ck_audit_events_details_object')),
    sa.CheckConstraint("outcome IN ('success', 'failure')", name=op.f('ck_audit_events_outcome_values')),
    sa.CheckConstraint('length(trim(event_type)) > 0', name=op.f('ck_audit_events_event_type_present')),
    sa.ForeignKeyConstraint(['administrator_id'], ['administrators.id'], name=op.f('fk_audit_events_administrator_id_administrators'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['ai_analysis_id'], ['ai_analyses.id'], name=op.f('fk_audit_events_ai_analysis_id_ai_analyses'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], name=op.f('fk_audit_events_device_id_devices'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_audit_events_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['monitoring_run_id'], ['monitoring_runs.id'], name=op.f('fk_audit_events_monitoring_run_id_monitoring_runs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['response_action_id'], ['response_actions.id'], name=op.f('fk_audit_events_response_action_id_response_actions'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_events_administrator_id'), ['administrator_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_ai_analysis_id'), ['ai_analysis_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_device_id'), ['device_id'], unique=False)
        batch_op.create_index('ix_audit_events_event_type_occurred_at', ['event_type', 'occurred_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_incident_id'), ['incident_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_monitoring_run_id'), ['monitoring_run_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_occurred_at'), ['occurred_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_events_response_action_id'), ['response_action_id'], unique=False)




def downgrade():
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_audit_events_response_action_id'))
        batch_op.drop_index(batch_op.f('ix_audit_events_occurred_at'))
        batch_op.drop_index(batch_op.f('ix_audit_events_monitoring_run_id'))
        batch_op.drop_index(batch_op.f('ix_audit_events_incident_id'))
        batch_op.drop_index('ix_audit_events_event_type_occurred_at')
        batch_op.drop_index(batch_op.f('ix_audit_events_device_id'))
        batch_op.drop_index(batch_op.f('ix_audit_events_ai_analysis_id'))
        batch_op.drop_index(batch_op.f('ix_audit_events_administrator_id'))

    op.drop_table('audit_events')
    with op.batch_alter_table('response_actions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_response_actions_requested_by_id'))
        batch_op.drop_index(batch_op.f('ix_response_actions_incident_id'))
        batch_op.drop_index('ix_response_actions_execution_status_expires_at')
        batch_op.drop_index(batch_op.f('ix_response_actions_device_id'))
        batch_op.drop_index(batch_op.f('ix_response_actions_decided_by_id'))
        batch_op.drop_index('ix_response_actions_approval_status_created_at')
        batch_op.drop_index(batch_op.f('ix_response_actions_ai_analysis_id'))

    op.drop_table('response_actions')
    with op.batch_alter_table('ai_analyses', schema=None) as batch_op:
        batch_op.drop_index('ix_ai_analyses_incident_id_requested_at')

    op.drop_table('ai_analyses')
    with op.batch_alter_table('incidents', copy_from=_incidents_snapshot(expanded=True)) as batch_op:
        batch_op.drop_constraint(batch_op.f('fk_incidents_monitoring_run_id_monitoring_runs'), type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_incidents_monitoring_run_id'))
        batch_op.drop_column('monitoring_run_id')

        batch_op.drop_constraint(op.f("ck_incidents_evidence_object"), type_="check")


    with op.batch_alter_table('traffic_summaries', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_traffic_summaries_window_start'))
        batch_op.drop_index('ix_traffic_summaries_device_id_window_start')

    op.drop_table('traffic_summaries')
    with op.batch_alter_table('monitoring_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_monitoring_runs_stopped_by_id'))
        batch_op.drop_index(batch_op.f('ix_monitoring_runs_started_by_id'))

    op.drop_table('monitoring_runs')
    op.drop_table('administrators')
