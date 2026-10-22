"""lock employees' computers: reason, time and an audit trail

Locking an employee account now locks their monitored computer (the screen
agent shows a full-screen lock until the company unlocks it in the portal).
employees gets the reason and time of the current lock; lock_events records
every lock and unlock.

Revision ID: f4b8d2a6c913
Revises: e9a3c7b1d608
Create Date: 2026-10-23 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f4b8d2a6c913'
down_revision: Union[str, None] = 'e9a3c7b1d608'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('employees', sa.Column('lock_reason', sa.String(length=200), nullable=True))
    op.add_column('employees', sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        'lock_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('unique_id', sa.Integer(), nullable=False),
        sa.Column('employee_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=10), nullable=False),
        sa.Column('reason', sa.String(length=200), nullable=True),
        sa.Column('actor', sa.String(length=120), nullable=False),
        sa.Column('event_time', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['employee_id'], ['employees.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['unique_id'], ['customers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_lock_events_employee_id'), 'lock_events', ['employee_id'], unique=False)
    op.create_index(op.f('ix_lock_events_unique_id'), 'lock_events', ['unique_id'], unique=False)

    # Accounts that were already marked Locked (a portal-only flag until now)
    # get a lock time, so the "since" shown for them isn't empty.
    op.execute("UPDATE employees SET locked_at = now(), lock_reason = 'Locked by administrator' WHERE employee_status = 'LOCKED'")


def downgrade() -> None:
    op.drop_index(op.f('ix_lock_events_unique_id'), table_name='lock_events')
    op.drop_index(op.f('ix_lock_events_employee_id'), table_name='lock_events')
    op.drop_table('lock_events')
    op.drop_column('employees', 'locked_at')
    op.drop_column('employees', 'lock_reason')
