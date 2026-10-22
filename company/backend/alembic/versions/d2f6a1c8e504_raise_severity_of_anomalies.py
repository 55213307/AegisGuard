"""raise the severity of events the behavioral model flagged

An anomaly is at least a Warning (risk >= 70) and a strong one Critical
(risk >= 90), so the severity filter, dashboard counts and alert colours
reflect it (see app/services/ml/scoring.severity_for_risk). New events get
this when they are scored; this applies it to events scored earlier. Never
lowers a severity.

Revision ID: d2f6a1c8e504
Revises: 9b4e2f6c1a37
Create Date: 2026-10-22 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd2f6a1c8e504'
down_revision: Union[str, None] = '9b4e2f6c1a37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("UPDATE security_events SET severity = 'Critical' WHERE risk_score >= 90 AND severity <> 'Critical'")
    op.execute(
        "UPDATE security_events SET severity = 'Warning' "
        "WHERE risk_score >= 70 AND risk_score < 90 AND severity = 'Info'"
    )


def downgrade() -> None:
    # The original severity came from the Wazuh rule level, which is still
    # stored, but a plain downgrade can't tell which rows were raised.
    pass
