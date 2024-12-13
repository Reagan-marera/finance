from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the database
db = SQLAlchemy()

# User model with role-based access
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default='User')  # 'CEO' or 'User'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} - {self.role}>'

# Chart of Accounts (COA) model
class ChartOfAccounts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_code = db.Column(db.String(50), unique=True, nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    sub_account_details = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<ChartOfAccounts {self.account_code} - {self.account_name}>'

# Invoice Issued model
class InvoiceIssued(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    date_issued = db.Column(db.String(50), nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    coa_id = db.Column(db.Integer, db.ForeignKey('chart_of_accounts.id'), nullable=False)

    coa = db.relationship('ChartOfAccounts', backref='invoices_issued')

    def __repr__(self):
        return f'<InvoiceIssued {self.invoice_number} - {self.customer_name}>'

# General Journal model
class GeneralJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(50), nullable=False)
    coa_id = db.Column(db.Integer, db.ForeignKey('chart_of_accounts.id'), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    debit = db.Column(db.Float, nullable=False)
    credit = db.Column(db.Float, nullable=False)

    coa = db.relationship('ChartOfAccounts', backref='general_journals')

    def __repr__(self):
        return f'<GeneralJournal {self.date} - {self.coa.account_name}>'

# Cash Receipt Journal model
class CashReceiptJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_date = db.Column(db.String(50), nullable=False)
    receipt_no = db.Column(db.String(50), unique=True, nullable=False)
    ref_no = db.Column(db.String(50), nullable=True)
    from_whom_received = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    receipt_type = db.Column(db.String(250), nullable=False)
    account_class = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    account_debited = db.Column(db.String(50), nullable=False)
    cash = db.Column(db.Float, nullable=False)
    bank = db.Column(db.Float, nullable=False)
    total = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<CashReceiptJournal {self.receipt_date} - {self.from_whom_received}>'

# Cash Disbursement Journal model
class CashDisbursementJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    disbursement_date = db.Column(db.String(50), nullable=False)
    cheque_no = db.Column(db.String(50), unique=True, nullable=False)
    p_voucher_no = db.Column(db.String(50), nullable=True)
    to_whom_paid = db.Column(db.String(100), nullable=False)
    payment_type = db.Column(db.String(255), nullable=True)
    cashbook = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    account_class = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    account_credited = db.Column(db.String(50), nullable=False)
    cash = db.Column(db.Float, nullable=False)
    bank = db.Column(db.Float, nullable=False)
    total = db.Column(db.Float, nullable=False)
    vote_total = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<CashDisbursementJournal {self.disbursement_date} - {self.to_whom_paid}>'
