"""when the current setup window started

endpoints.maintenance_until says when events stop being left unchecked; the
portal also shows when that started, and with the window renewed by the
installer the start can't be worked out from the end any more.

Revision ID: e5c2a8f1b946
Revises: d6f1b9c4e382
Create Date: 2026-10-23 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e5c2a8f1b946'
down_revision: Union[str, None] = 'd6f1b9c4e382'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('endpoints', sa.Column('maintenance_from', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('endpoints', 'maintenance_from')
