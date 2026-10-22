"""maintenance window while an installer runs on a computer

The installer tells the portal when it starts, and for a while after that the
computer's events aren't scored or allowed to lock it: an installer runs
PowerShell, edits the registry and audit policy, which is exactly what the
behavioral model rates as never-seen admin tooling.

Revision ID: a7c3e1d9b420
Revises: f4b8d2a6c913
Create Date: 2026-10-23 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a7c3e1d9b420'
down_revision: Union[str, None] = 'f4b8d2a6c913'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('endpoints', sa.Column('maintenance_until', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('endpoints', 'maintenance_until')
