"""Store the operator's monitoring preference across service restarts."""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "monitoring_preference",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("enabled_by_id", sa.Integer(), nullable=True),
        sa.CheckConstraint("id = 1", name=op.f("ck_monitoring_preference_singleton")),
        sa.ForeignKeyConstraint(["enabled_by_id"], ["administrators.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(
        "INSERT INTO monitoring_preference (id, enabled_by_id) "
        "SELECT 1, CASE WHEN ended_at IS NULL OR stop_reason IN ('shutdown', 'interrupted') "
        "THEN started_by_id ELSE NULL END FROM monitoring_runs ORDER BY id DESC LIMIT 1"
    )


def downgrade():
    op.drop_table("monitoring_preference")
