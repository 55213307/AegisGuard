"""remember deleted endpoints so their software can uninstall itself

When an employee is deleted the computer's endpoint goes with it, and its
upload token is no longer accepted. This table keeps just enough (endpoint id
and Wazuh agent id, which the token is derived from) to answer a genuine token
from that computer with an explicit uninstall instruction.

Revision ID: d6f1b9c4e382
Revises: c8e2a5b1d437
Create Date: 2026-10-23 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd6f1b9c4e382'
down_revision: Union[str, None] = 'c8e2a5b1d437'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'removed_endpoints',
        sa.Column('id', sa.Integer(), autoincrement=False, nullable=False),
        sa.Column('unique_id', sa.Integer(), nullable=False),
        sa.Column('wazuh_agent_id', sa.String(length=10), nullable=False),
        sa.Column('endpoint_name', sa.String(length=50), nullable=False),
        sa.Column('removed_time', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['unique_id'], ['customers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_removed_endpoints_unique_id'), 'removed_endpoints', ['unique_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_removed_endpoints_unique_id'), table_name='removed_endpoints')
    op.drop_table('removed_endpoints')
