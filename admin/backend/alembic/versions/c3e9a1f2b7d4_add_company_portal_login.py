"""add company portal login fields to accounts

Revision ID: c3e9a1f2b7d4
Revises: 4b1c4bdb889b
Create Date: 2026-09-30 12:00:00.000000

"""
import secrets
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3e9a1f2b7d4'
down_revision: Union[str, None] = '4b1c4bdb889b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('accounts', sa.Column('login_token', sa.String(length=64), nullable=True))
    op.add_column('accounts', sa.Column('password_hash', sa.String(length=255), nullable=True))
    op.add_column(
        'accounts',
        sa.Column('must_change_password', sa.Boolean(), server_default=sa.true(), nullable=False),
    )

    # Existing accounts get a login link now; they get no password — an admin
    # issues one with "Reset Password" (plaintext can't be recovered later).
    conn = op.get_bind()
    for (account_id,) in conn.execute(sa.text("SELECT id FROM accounts")).fetchall():
        conn.execute(
            sa.text("UPDATE accounts SET login_token = :token WHERE id = :id"),
            {"token": secrets.token_urlsafe(16), "id": account_id},
        )

    op.alter_column('accounts', 'login_token', nullable=False)
    op.create_index(op.f('ix_accounts_login_token'), 'accounts', ['login_token'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_accounts_login_token'), table_name='accounts')
    op.drop_column('accounts', 'must_change_password')
    op.drop_column('accounts', 'password_hash')
    op.drop_column('accounts', 'login_token')
