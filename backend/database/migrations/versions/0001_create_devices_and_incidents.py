"""create devices and incidents

Revision ID: 0001
Revises: None
"""

from alembic import op
import sqlalchemy as sa


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('devices',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('mac_address', sa.String(length=17), nullable=False),
    sa.Column('current_ip', sa.String(length=45), nullable=True),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('vendor', sa.String(length=255), nullable=True),
    sa.Column('is_trusted', sa.Boolean(create_constraint=True, name='trusted_boolean'), server_default=sa.text('0'), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.CheckConstraint("mac_address GLOB '[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]'", name=op.f('ck_devices_mac_format')),
    sa.CheckConstraint('last_seen_at >= first_seen_at', name=op.f('ck_devices_observation_order')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_devices')),
    sa.UniqueConstraint('mac_address', name=op.f('uq_devices_mac_address'))
    )
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_devices_last_seen_at'), ['last_seen_at'], unique=False)

    op.create_table('incidents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('source_device_id', sa.Integer(), nullable=True),
    sa.Column('rule_code', sa.String(length=100), nullable=False),
    sa.Column('source_ip', sa.String(length=45), nullable=False),
    sa.Column('target_ip', sa.String(length=45), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.Column('risk_score', sa.Integer(), nullable=True),
    sa.Column('severity', sa.String(length=10), nullable=True),
    sa.Column('status', sa.String(length=20), server_default=sa.text("'open'"), nullable=False),
    sa.Column('evidence_json', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.CheckConstraint("(status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at >= created_at) OR (status != 'resolved' AND resolved_at IS NULL)", name=op.f('ck_incidents_resolution_state')),
    sa.CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')", name=op.f('ck_incidents_severity_values')),
    sa.CheckConstraint("status IN ('open', 'investigating', 'resolved')", name=op.f('ck_incidents_status_values')),
    sa.CheckConstraint('last_seen_at >= first_seen_at', name=op.f('ck_incidents_observation_order')),
    sa.CheckConstraint('risk_score BETWEEN 0 AND 100', name=op.f('ck_incidents_risk_score_range')),
    sa.CheckConstraint('updated_at >= created_at', name=op.f('ck_incidents_update_order')),
    sa.ForeignKeyConstraint(['source_device_id'], ['devices.id'], name=op.f('fk_incidents_source_device_id_devices'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents'))
    )
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.create_index('ix_incidents_source_device_id_created_at', ['source_device_id', 'created_at'], unique=False)
        batch_op.create_index('ix_incidents_status_created_at', ['status', 'created_at'], unique=False)



def downgrade():
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_index('ix_incidents_status_created_at')
        batch_op.drop_index('ix_incidents_source_device_id_created_at')

    op.drop_table('incidents')
    with op.batch_alter_table('devices', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_devices_last_seen_at'))

    op.drop_table('devices')
