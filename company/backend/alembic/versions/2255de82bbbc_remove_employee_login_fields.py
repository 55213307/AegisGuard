"""remove employee login fields

Revision ID: 2255de82bbbc
Revises: 3211a53dc90b
Create Date: 2026-10-03 16:37:18.839608

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '2255de82bbbc'
down_revision: Union[str, None] = '3211a53dc90b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column('employees', 'last_login_time')
    op.drop_column('employees', 'password_hash')
    op.drop_column('employees', 'must_change_password')


def downgrade() -> None:
    op.add_column('employees', sa.Column('must_change_password', sa.BOOLEAN(), server_default=sa.text('true'), autoincrement=False, nullable=False))
    op.add_column('employees', sa.Column('password_hash', sa.VARCHAR(length=255), server_default='', autoincrement=False, nullable=False))
    op.add_column('employees', sa.Column('last_login_time', postgresql.TIMESTAMP(timezone=True), autoincrement=False, nullable=True))
