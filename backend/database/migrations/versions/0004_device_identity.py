"""Track routed address provenance and separate activity from inventory sightings."""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("devices", sa.Column("ip_source", sa.String(20)))
    op.add_column("devices", sa.Column("ip_expires_at", sa.DateTime()))
    op.add_column("devices", sa.Column("last_active_at", sa.DateTime()))
    op.execute("UPDATE devices SET last_active_at = last_seen_at")


def downgrade():
    for column in ("last_active_at", "ip_expires_at", "ip_source"):
        op.drop_column("devices", column)
