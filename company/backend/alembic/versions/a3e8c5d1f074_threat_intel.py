"""known-bad file hashes, URLs and domains

The table behind services/threat_intel.py: public lists of malware hashes and malicious or
phishing addresses, looked up by exact value. Shared by every company.

Revision ID: a3e8c5d1f074
Revises: f8a1d3c7b592
Create Date: 2026-11-06 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a3e8c5d1f074'
down_revision: Union[str, None] = 'f8a1d3c7b592'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'threat_intel',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=10), nullable=False),
        sa.Column('value', sa.String(length=1000), nullable=False),
        sa.Column('source', sa.String(length=40), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('added_time', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('kind', 'value', name='uq_threat_intel_kind_value'),
    )


def downgrade() -> None:
    op.drop_table('threat_intel')
