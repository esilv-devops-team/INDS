"""Migrations use the same configuration and connection settings as the backend."""

from alembic import context

from backend.database.config import get_database_url
from backend.database.base import Base
from backend.database.session import create_database_engine
from backend.database import models  # noqa: F401 -- register model metadata


def run_migrations():
    if context.is_offline_mode():
        context.configure(
            url=get_database_url(), target_metadata=Base.metadata,
            literal_binds=True, render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    else:
        engine = create_database_engine()
        try:
            with engine.connect() as connection:
                context.configure(
                    connection=connection, target_metadata=Base.metadata, render_as_batch=True
                )
                with context.begin_transaction():
                    context.run_migrations()
        finally:
            engine.dispose()


run_migrations()
