"""working hours the company declares for an employee

When set, the behavioral model starts from these hours instead of assuming a
default shift, and trusts them at once (an explicit statement from the
company). Both are local clock times as "HH:MM"; an end before the start means
the shift runs past midnight. Empty means "learn them from the activity".

Revision ID: c8e2a5b1d437
Revises: b3d9f0a7c251
Create Date: 2026-10-23 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c8e2a5b1d437'
down_revision: Union[str, None] = 'b3d9f0a7c251'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('employees', sa.Column('work_start', sa.String(length=5), nullable=True))
    op.add_column('employees', sa.Column('work_end', sa.String(length=5), nullable=True))


def downgrade() -> None:
    op.drop_column('employees', 'work_end')
    op.drop_column('employees', 'work_start')
