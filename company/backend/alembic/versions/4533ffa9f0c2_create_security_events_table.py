"""create security_events table

Revision ID: 4533ffa9f0c2
Revises: 2255de82bbbc
Create Date: 2026-10-04 13:43:38.476196

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '4533ffa9f0c2'
down_revision: Union[str, None] = '2255de82bbbc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('security_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('unique_id', sa.Integer(), nullable=False),
    sa.Column('endpoint_id', sa.Integer(), nullable=False),
    sa.Column('wazuh_alert_id', sa.String(length=64), nullable=False),
    sa.Column('event_time', sa.DateTime(timezone=True), nullable=False),
    sa.Column('rule_id', sa.String(length=20), nullable=True),
    sa.Column('rule_level', sa.Integer(), nullable=False),
    sa.Column('rule_description', sa.String(length=500), nullable=True),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('event_type', sa.String(length=100), nullable=True),
    sa.Column('event_user', sa.String(length=120), nullable=True),
    sa.Column('windows_event_id', sa.String(length=20), nullable=True),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_time', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['unique_id'], ['customers.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('wazuh_alert_id')
    )
    op.create_index(op.f('ix_security_events_endpoint_id'), 'security_events', ['endpoint_id'], unique=False)
    op.create_index(op.f('ix_security_events_event_time'), 'security_events', ['event_time'], unique=False)
    op.create_index(op.f('ix_security_events_unique_id'), 'security_events', ['unique_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_security_events_unique_id'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_event_time'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_endpoint_id'), table_name='security_events')
    op.drop_table('security_events')
