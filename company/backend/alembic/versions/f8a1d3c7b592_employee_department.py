"""the department an employee works in

The behavior model has to know whether a command prompt or a code editor is
ordinary for someone: it is for IT and security staff, and not for an office
clerk. The default, "auto", needs no one to say anything: the model starts
strict (as it always was) and learns each computer's own habits.

Revision ID: f8a1d3c7b592
Revises: e5c2a8f1b946
Create Date: 2026-10-25 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f8a1d3c7b592'
down_revision: Union[str, None] = 'e5c2a8f1b946'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('employees', sa.Column('department', sa.String(length=20), nullable=False, server_default='auto'))


def downgrade() -> None:
    op.drop_column('employees', 'department')
