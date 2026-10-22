"""rescore failed logons under the "three wrong passwords" rule

Failed logons used to be scored by the behavioral model, which had never seen
one and rated every single wrong password as a 90+ anomaly. They now follow a
rule (app/services/ml/scoring.py): an alert needs several failures on the same
computer within minutes. This clears the old scores, and the severity they
raised, so the next model training pass scores them again under the rule.

Revision ID: e9a3c7b1d608
Revises: d2f6a1c8e504
Create Date: 2026-10-22 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e9a3c7b1d608'
down_revision: Union[str, None] = 'd2f6a1c8e504'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Severity goes back to what the Wazuh rule level says (alerts.severity_for_level).
    op.execute(
        "UPDATE security_events SET risk_score = NULL, risk_reason = NULL, "
        "severity = CASE WHEN rule_level >= 12 THEN 'Critical' WHEN rule_level >= 7 THEN 'Warning' ELSE 'Info' END "
        "WHERE event_type = 'Login Failed' AND risk_score IS NOT NULL"
    )


def downgrade() -> None:
    pass
