"""drop employee role

Revision ID: afefb5eb5ab2
Revises: 4eb2347deec1
Create Date: 2026-10-03 16:05:44.247808

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'afefb5eb5ab2'
down_revision: Union[str, None] = '4eb2347deec1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column('employees', 'employee_role')


def downgrade() -> None:
    op.add_column('employees', sa.Column('employee_role', sa.VARCHAR(length=13), server_default='EMPLOYEE', nullable=False))
