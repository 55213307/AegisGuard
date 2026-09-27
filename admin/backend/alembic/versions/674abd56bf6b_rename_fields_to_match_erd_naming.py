"""rename fields to match ERD naming

Revision ID: 674abd56bf6b
Revises: 73b4d5ccf011
Create Date: 2026-09-27 15:10:40.810794

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '674abd56bf6b'
down_revision: Union[str, None] = '73b4d5ccf011'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # admin_users: straight renames, data preserved.
    op.alter_column('admin_users', 'username', new_column_name='login_username')
    op.alter_column('admin_users', 'created_at', new_column_name='created_time')
    op.drop_index('ix_admin_users_username', table_name='admin_users')
    op.create_index(op.f('ix_admin_users_login_username'), 'admin_users', ['login_username'], unique=True)

    # customers: fold area_code into contact_number, drop state (unused),
    # rename the rest.
    op.execute(
        "UPDATE customers SET contact_number = "
        "trim(concat_ws(' ', area_code, contact_number)) "
        "WHERE area_code IS NOT NULL"
    )
    op.drop_column('customers', 'area_code')
    op.drop_column('customers', 'state')
    op.alter_column('customers', 'contact_person', new_column_name='contact_name')
    op.alter_column('customers', 'activated_at', new_column_name='activated_time')
    # is_activated is superseded by the linked account's own status.
    op.drop_column('customers', 'is_activated')

    # accounts: role removed (one account per customer, no role distinction
    # needed), remarks removed (lives on customers.remark instead), rest
    # renamed to match the ERD / customers-table FK naming.
    op.drop_column('accounts', 'role')
    op.drop_column('accounts', 'remarks')
    op.alter_column('accounts', 'name', new_column_name='customer_name')
    op.alter_column('accounts', 'email', new_column_name='customer_email')
    op.alter_column('accounts', 'status', new_column_name='customer_status')
    op.alter_column('accounts', 'company_id', new_column_name='unique_id')
    op.alter_column('accounts', 'operator_id', new_column_name='admin_id')
    op.alter_column('accounts', 'submitted_at', new_column_name='submitted_time')
    op.alter_column('accounts', 'updated_at', new_column_name='update_time')

    op.drop_constraint('accounts_company_id_key', 'accounts', type_='unique')
    op.create_unique_constraint('accounts_unique_id_key', 'accounts', ['unique_id'])
    op.drop_index('ix_accounts_email', table_name='accounts')
    op.create_index(op.f('ix_accounts_customer_email'), 'accounts', ['customer_email'], unique=True)

    op.drop_constraint('accounts_company_id_fkey', 'accounts', type_='foreignkey')
    op.drop_constraint('accounts_operator_id_fkey', 'accounts', type_='foreignkey')
    op.create_foreign_key('accounts_unique_id_fkey', 'accounts', 'customers', ['unique_id'], ['id'])
    op.create_foreign_key('accounts_admin_id_fkey', 'accounts', 'admin_users', ['admin_id'], ['id'])

    # AccountRole enum's Python type is gone; its Postgres-side artifact (a
    # plain varchar under native_enum=False, no real enum type) needs nothing
    # dropped here — role was a String column, not a Postgres ENUM type.


def downgrade() -> None:
    op.drop_constraint('accounts_admin_id_fkey', 'accounts', type_='foreignkey')
    op.drop_constraint('accounts_unique_id_fkey', 'accounts', type_='foreignkey')
    op.create_foreign_key('accounts_operator_id_fkey', 'accounts', 'admin_users', ['operator_id'], ['id'])
    op.create_foreign_key('accounts_company_id_fkey', 'accounts', 'customers', ['company_id'], ['id'])

    op.drop_index(op.f('ix_accounts_customer_email'), table_name='accounts')
    op.create_index('ix_accounts_email', 'accounts', ['email'], unique=True)
    op.drop_constraint('accounts_unique_id_key', 'accounts', type_='unique')
    op.create_unique_constraint('accounts_company_id_key', 'accounts', ['company_id'])

    op.alter_column('accounts', 'update_time', new_column_name='updated_at')
    op.alter_column('accounts', 'submitted_time', new_column_name='submitted_at')
    op.alter_column('accounts', 'admin_id', new_column_name='operator_id')
    op.alter_column('accounts', 'unique_id', new_column_name='company_id')
    op.alter_column('accounts', 'customer_status', new_column_name='status')
    op.alter_column('accounts', 'customer_email', new_column_name='email')
    op.alter_column('accounts', 'customer_name', new_column_name='name')
    op.add_column('accounts', sa.Column('remarks', sa.String(length=500), nullable=True))
    op.add_column('accounts', sa.Column(
        'role',
        sa.Enum('COMPANY_ADMIN', 'SECURITY_ANALYST', 'VIEWER', name='accountrole', native_enum=False),
        nullable=False,
        server_default='COMPANY_ADMIN',
    ))
    op.alter_column('accounts', 'role', server_default=None)

    op.add_column('customers', sa.Column('is_activated', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.alter_column('customers', 'is_activated', server_default=None)
    op.alter_column('customers', 'activated_time', new_column_name='activated_at')
    op.alter_column('customers', 'contact_name', new_column_name='contact_person')
    op.add_column('customers', sa.Column('state', sa.String(length=120), nullable=True))
    op.add_column('customers', sa.Column('area_code', sa.String(length=10), nullable=True))

    op.drop_index(op.f('ix_admin_users_login_username'), table_name='admin_users')
    op.create_index('ix_admin_users_username', 'admin_users', ['username'], unique=True)
    op.alter_column('admin_users', 'created_time', new_column_name='created_at')
    op.alter_column('admin_users', 'login_username', new_column_name='username')
