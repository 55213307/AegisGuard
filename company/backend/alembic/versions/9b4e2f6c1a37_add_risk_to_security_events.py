"""add behavioral risk score to security_events

risk_score (0-100) and risk_reason come from the behavioral anomaly model
(app/services/ml). NULL means the event isn't a user action, or the endpoint
had no model when it arrived. The partial index serves "recent anomalies"
queries (risk_score >= 70, the alert threshold) without scanning every event.

Revision ID: 9b4e2f6c1a37
Revises: 7c1d9e3a5b20
Create Date: 2026-10-22 17:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '9b4e2f6c1a37'
down_revision: Union[str, None] = '7c1d9e3a5b20'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('security_events', sa.Column('risk_score', sa.Integer(), nullable=True))
    op.add_column('security_events', sa.Column('risk_reason', sa.String(length=200), nullable=True))
    op.create_index(
        'ix_security_events_anomaly',
        'security_events',
        ['unique_id', 'event_time'],
        postgresql_where=sa.text('risk_score >= 70'),
    )


def downgrade() -> None:
    op.drop_index('ix_security_events_anomaly', table_name='security_events')
    op.drop_column('security_events', 'risk_reason')
    op.drop_column('security_events', 'risk_score')
