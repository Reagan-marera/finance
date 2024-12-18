from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the database
db = SQLAlchemy()

# User model with role-based access
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='User')  # Options: 'CEO' or 'User'
    # Password methods
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Relationship to CashDisbursementJournal, CashReceiptJournal, and InvoiceIssued
    cash_disbursements = db.relationship('CashDisbursementJournal', back_populates='created_by_user')
    cash_receipts = db.relationship('CashReceiptJournal', back_populates='created_by_user')
    invoices = db.relationship('InvoiceIssued', back_populates='user')

    def __repr__(self):
        return f'<User {self.username} - {self.role}>'

# Chart of Accounts (COA) model
class ChartOfAccounts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_account = db.Column(db.String(150), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)  # E.g., Asset, Liability, Equity
    sub_account_details = db.Column(db.String(255), nullable=True)
    
    # Foreign key to link to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('chart_of_accounts', lazy=True))

    def __repr__(self):
        return f'<ChartOfAccounts {self.parent_account} - {self.account_name}>'

class InvoiceIssued(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(50), nullable=False)
    date_issued = db.Column(db.Date, nullable=False)
    account_class = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    parent_account = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key linking to User table
    coa_id = db.Column(db.Integer, db.ForeignKey('chart_of_accounts.id'), nullable=False)
    chart_of_account = db.relationship('ChartOfAccounts', backref=db.backref('invoices', lazy=True))
    user = db.relationship('User', back_populates='invoices')

    account_debited = db.Column(db.String(100), nullable=False)
    account_credited = db.Column(db.String(100), nullable=False)
    invoice_type = db.Column(db.String(50), nullable=True)
    grn_number = db.Column(db.String(20), nullable=True)
    sub_accounts = db.Column(db.JSON, nullable=True)

    # Add composite unique constraint on user_id and invoice_number
    __table_args__ = (
        db.UniqueConstraint('user_id', 'invoice_number', name='unique_invoice_per_user'),
    )

    def __repr__(self):
        return f'<InvoiceIssued {self.invoice_number}>'
from sqlalchemy import UniqueConstraint

# Cash Receipt Journal model (updated)
class CashReceiptJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_date = db.Column(db.Date, nullable=False)
    receipt_no = db.Column(db.String(50), nullable=False)  # Remove unique constraint
    ref_no = db.Column(db.String(50), nullable=True)
    from_whom_received = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    account_class = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(100), nullable=False)
    receipt_type = db.Column(db.String(50), nullable=False)
    account_debited = db.Column(db.String(100), nullable=False)
    account_credited = db.Column(db.String(100), nullable=False)
    bank = db.Column(db.String(100), nullable=True)  # Nullable for bank field
    cash = db.Column(db.Float, nullable=False)
    total = db.Column(db.Float, nullable=False)
    parent_account = db.Column(db.String(150), nullable=False)
    
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by_user = db.relationship('User', back_populates='cash_receipts')
    sub_accounts = db.Column(db.JSON, nullable=True)  # Store sub-accounts as a JSON field

    __table_args__ = (
        UniqueConstraint('created_by', 'receipt_no', name='unique_receipt_per_user'),
    )

    def __repr__(self):
        return f'<CashReceiptJournal {self.receipt_no}>'

    def save(self):
        # Ensure that cash and bank are numeric before calculation
        if not isinstance(self.cash, (int, float)) or not isinstance(self.bank, (int, float)):
            raise ValueError("Cash and Bank values must be numeric.")
        
        # Calculate total before saving
        self.total = self.cash + self.bank
        db.session.add(self)
        db.session.commit()


# Cash Disbursement Journal model
class CashDisbursementJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    disbursement_date = db.Column(db.Date, nullable=False)
    cheque_no = db.Column(db.String(50), nullable=False)  # Removed unique constraint
    p_voucher_no = db.Column(db.String(50), nullable=True)
    to_whom_paid = db.Column(db.String(100), nullable=False)
    payment_type = db.Column(db.String(255), nullable=True)
    cashbook = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    account_class = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    parent_account = db.Column(db.String(150), nullable=False)
    account_credited = db.Column(db.String(100), nullable=False)
    account_debited = db.Column(db.String(100), nullable=False)

    cash = db.Column(db.Float, nullable=False, default=0.0)
    bank = db.Column(db.Float, nullable=False, default=0.0)  # Updated to Float for numeric values
    total = db.Column(db.Float, nullable=False, default=0.0)  # Added total column with a default value
    sub_accounts = db.Column(db.JSON, nullable=True)
    
    # Foreign key to User
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by_user = db.relationship('User', back_populates='cash_disbursements')

    def __repr__(self):
        return f'<CashDisbursementJournal {self.cheque_no}>'

    def save(self):
        # Ensure that cash and bank are numeric before calculation
        if not isinstance(self.cash, (int, float)) or not isinstance(self.bank, (int, float)):
            raise ValueError("Cash and Bank values must be numeric.")
        
        # Calculate total before saving
        self.total = self.cash + self.bank
        db.session.add(self)
        db.session.commit()

    # Adding a UniqueConstraint for the combination of created_by and cheque_no
    __table_args__ = (
        UniqueConstraint('created_by', 'cheque_no', name='unique_receipt_per_user'),
    )

# OTP Model
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<OTP {self.email}>'
