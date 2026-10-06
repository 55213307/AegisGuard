from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.db.session import Base
import app.models  # noqa: F401  (registers every model on Base.metadata)

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# This database is shared with admin/backend, which owns customers/accounts/
# etc. and keeps its history in the default "alembic_version" table. This
# backend only ever migrates its own tables, tracked in a separate table.
VERSION_TABLE = "alembic_version_company"
COMPANY_OWNED_TABLES = {"employees", "endpoints", "security_events"}


def include_object(obj, name, type_, reflected, compare_to):
    if type_ == "table":
        return name in COMPANY_OWNED_TABLES
    table = getattr(obj, "table", None)
    return table is None or table.name in COMPANY_OWNED_TABLES


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=VERSION_TABLE,
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table=VERSION_TABLE,
            include_object=include_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
