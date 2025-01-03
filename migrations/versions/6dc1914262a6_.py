"""empty message

Revision ID: 6dc1914262a6
Revises: 
Create Date: 2024-12-30 21:36:33.605390

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6dc1914262a6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('church',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('address', sa.String(length=255), nullable=False),
    sa.Column('phone_number', sa.String(length=20), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('otp',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('otp', sa.String(length=6), nullable=False),
    sa.Column('expiry', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=128), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('residence', sa.String(length=255), nullable=True),
    sa.Column('phone_number', sa.String(length=20), nullable=True),
    sa.Column('occupation', sa.String(length=100), nullable=True),
    sa.Column('member_number', sa.String(length=50), nullable=True),
    sa.Column('church_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['church_id'], ['church.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('member_number'),
    sa.UniqueConstraint('username')
    )
    op.create_table('cash_disbursement_journal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('disbursement_date', sa.Date(), nullable=False),
    sa.Column('cheque_no', sa.String(length=50), nullable=False),
    sa.Column('p_voucher_no', sa.String(length=50), nullable=True),
    sa.Column('to_whom_paid', sa.String(length=100), nullable=False),
    sa.Column('payment_type', sa.String(length=255), nullable=True),
    sa.Column('cashbook', sa.String(length=250), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('account_class', sa.String(length=50), nullable=False),
    sa.Column('account_type', sa.String(length=50), nullable=False),
    sa.Column('parent_account', sa.String(length=150), nullable=False),
    sa.Column('account_credited', sa.String(length=100), nullable=False),
    sa.Column('account_debited', sa.String(length=100), nullable=True),
    sa.Column('cash', sa.Float(), nullable=False),
    sa.Column('bank', sa.Float(), nullable=False),
    sa.Column('total', sa.Float(), nullable=False),
    sa.Column('sub_accounts', sa.JSON(), nullable=True),
    sa.Column('created_by', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('created_by', 'cheque_no', name='unique_receipt_per_user')
    )
    op.create_table('cash_receipt_journal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('receipt_date', sa.Date(), nullable=False),
    sa.Column('receipt_no', sa.String(length=50), nullable=False),
    sa.Column('ref_no', sa.String(length=50), nullable=True),
    sa.Column('from_whom_received', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('account_class', sa.String(length=100), nullable=False),
    sa.Column('account_type', sa.String(length=100), nullable=False),
    sa.Column('receipt_type', sa.String(length=50), nullable=False),
    sa.Column('account_debited', sa.String(length=100), nullable=True),
    sa.Column('account_credited', sa.String(length=100), nullable=True),
    sa.Column('bank', sa.String(length=100), nullable=True),
    sa.Column('cash', sa.Float(), nullable=False),
    sa.Column('total', sa.Float(), nullable=False),
    sa.Column('parent_account', sa.String(length=150), nullable=False),
    sa.Column('cashbook', sa.String(length=250), nullable=False),
    sa.Column('created_by', sa.Integer(), nullable=False),
    sa.Column('sub_accounts', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['created_by'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('created_by', 'receipt_no', name='unique_receipt_per_user')
    )
    op.create_table('chart_of_accounts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('parent_account', sa.String(length=150), nullable=False),
    sa.Column('account_name', sa.String(length=100), nullable=False),
    sa.Column('account_type', sa.String(length=50), nullable=False),
    sa.Column('sub_account_details', sa.JSON(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('invoice_issued',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('invoice_number', sa.String(length=50), nullable=False),
    sa.Column('date_issued', sa.Date(), nullable=False),
    sa.Column('account_class', sa.String(length=100), nullable=False),
    sa.Column('account_type', sa.String(length=100), nullable=False),
    sa.Column('amount', sa.Integer(), nullable=False),
    sa.Column('parent_account', sa.String(length=150), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('coa_id', sa.Integer(), nullable=False),
    sa.Column('account_debited', sa.String(length=100), nullable=True),
    sa.Column('account_credited', sa.String(length=100), nullable=True),
    sa.Column('grn_number', sa.String(length=20), nullable=True),
    sa.Column('sub_accounts', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['coa_id'], ['chart_of_accounts.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'invoice_number', name='unique_invoice_per_user')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('invoice_issued')
    op.drop_table('chart_of_accounts')
    op.drop_table('cash_receipt_journal')
    op.drop_table('cash_disbursement_journal')
    op.drop_table('user')
    op.drop_table('otp')
    op.drop_table('church')
    # ### end Alembic commands ###