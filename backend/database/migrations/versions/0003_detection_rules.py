"""detection rules

Revision ID: 0003
Revises: 0002
"""

import json

from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None

DEFAULT_RULES = [
    ("TRAFFIC_SPIKE", "Per-device traffic exceeds a byte or packet rate.", "Medium", 300,
     {"window_minutes": 1, "max_bytes_per_minute": 104857600, "max_packets_per_minute": 100000}),
    ("ARP_SPOOFING", "An ARP claim conflicts with a protected IPv4 address of the network.", "High", 300,
     {"protected_bindings": {}}),
    ("PORT_SCAN", "A device tries many different ports on the same target in a short time.", "Medium", 300,
     {"distinct_ports": 20, "window_seconds": 60}),
]


def upgrade():
    op.create_table('detection_rules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rule_code', sa.String(length=50), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('enabled', sa.Boolean(create_constraint=True, name='enabled_boolean'), server_default=sa.text('1'), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('cooldown_seconds', sa.Integer(), nullable=False),
    sa.Column('settings_json', sa.JSON(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint("json_valid(settings_json) AND json_type(settings_json) = 'object'", name=op.f('ck_detection_rules_settings_object')),
    sa.CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')", name=op.f('ck_detection_rules_severity_values')),
    sa.CheckConstraint('cooldown_seconds > 0', name=op.f('ck_detection_rules_cooldown_positive')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_detection_rules')),
    sa.UniqueConstraint('rule_code', name=op.f('uq_detection_rules_rule_code'))
    )

    for code, description, severity, cooldown, settings in DEFAULT_RULES:
        op.execute(
            "INSERT INTO detection_rules (rule_code, description, enabled, severity, cooldown_seconds, settings_json, updated_at) "
            f"VALUES ('{code}', '{description}', 1, '{severity}', {cooldown}, '{json.dumps(settings)}', CURRENT_TIMESTAMP)"
        )


def downgrade():
    op.drop_table('detection_rules')