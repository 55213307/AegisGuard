"""create endpoints table

Revision ID: 3211a53dc90b
Revises: afefb5eb5ab2
Create Date: 2026-10-03 16:16:07.683788

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3211a53dc90b'
down_revision: Union[str, None] = 'afefb5eb5ab2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('endpoints',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('unique_id', sa.Integer(), nullable=False),
    sa.Column('employee_id', sa.Integer(), nullable=False),
    sa.Column('endpoint_name', sa.String(length=50), nullable=False),
    sa.Column('wazuh_agent_id', sa.String(length=10), nullable=False),
    sa.Column('wazuh_agent_name', sa.String(length=128), nullable=False),
    sa.Column('created_time', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['employee_id'], ['employees.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['unique_id'], ['customers.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('employee_id'),
    sa.UniqueConstraint('wazuh_agent_id'),
    sa.UniqueConstraint('wazuh_agent_name')
    )
    op.create_index(op.f('ix_endpoints_unique_id'), 'endpoints', ['unique_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_endpoints_unique_id'), table_name='endpoints')
    op.drop_table('endpoints')
