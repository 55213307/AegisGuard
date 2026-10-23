"""approved overtime window per employee

While an administrator has approved overtime for an employee, the time of day
and day of the week of that computer's activity are not held against it by the
behavioral model (what is run is still judged). The window is forward-looking:
it ends at overtime_until.

Revision ID: b3d9f0a7c251
Revises: a7c3e1d9b420
Create Date: 2026-10-23 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b3d9f0a7c251'
down_revision: Union[str, None] = 'a7c3e1d9b420'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('employees', sa.Column('overtime_until', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('employees', 'overtime_until')
