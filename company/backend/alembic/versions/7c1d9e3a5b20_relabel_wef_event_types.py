"""relabel " Wef" event types by Windows event ID

Wazuh's WEF rules (67xxx) group logons, logoffs and process creation only as
"windows" / " WEF", so they were stored with the meaningless event type
" Wef". New alerts are labelled by Windows event ID (app/services/alerts.py);
this applies the same labels to rows ingested before that fix.

Revision ID: 7c1d9e3a5b20
Revises: 4533ffa9f0c2
Create Date: 2026-10-22 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '7c1d9e3a5b20'
down_revision: Union[str, None] = '4533ffa9f0c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Same mapping as alerts._WINDOWS_EVENT_LABELS, frozen here so the migration
# doesn't change if that code does.
_LABELS = {
    "4624": "Login Success",
    "4625": "Login Failed",
    "4634": "Logoff",
    "4647": "Logoff",
    "4672": "Special Privileges",
    "4688": "Process",
    "4720": "Account Created",
    "4726": "Account Deleted",
    "4738": "Account Changed",
    "4740": "Account Locked",
    "1102": "Audit Log Cleared",
}


def upgrade() -> None:
    conn = op.get_bind()
    for event_id, label in _LABELS.items():
        conn.execute(
            sa.text(
                "UPDATE security_events SET event_type = :label "
                "WHERE windows_event_id = :event_id AND TRIM(event_type) = 'Wef'"
            ),
            {"label": label, "event_id": event_id},
        )


def downgrade() -> None:
    # Data-only relabel; the old value carried no information, so there's
    # nothing meaningful to restore.
    pass
