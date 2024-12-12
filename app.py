from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from models import db, User, ChartOfAccounts, InvoiceIssued, GeneralJournal, CashReceiptJournal, CashDisbursementJournal

# Initialize the Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///financial_reporting.db'  # Use your actual database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
CORS(app)
jwt = JWTManager(app)
# Register route for user registration
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400

    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# Login route
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        token = create_access_token(identity=user.username)
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Invalid username or password'}), 401

# CRUD for Chart of Accounts
@app.route('/chart-of-accounts', methods=['GET', 'POST'])
@jwt_required()
def manage_chart_of_accounts():
    if request.method == 'GET':
        accounts = ChartOfAccounts.query.all()
        return jsonify([{
            'id': acc.id,
            'account_code': acc.account_code,
            'account_name': acc.account_name,
            'account_type': acc.account_type,
            'category': acc.category,
            'sub_account_details': acc.sub_account_details
        } for acc in accounts])

    elif request.method == 'POST':
        data = request.get_json()
        new_account = ChartOfAccounts(
            account_code=data['account_code'],
            account_name=data['account_name'],
            account_type=data['account_type'],
            category=data.get('category'),
            sub_account_details=data.get('sub_account_details')
        )
        db.session.add(new_account)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts created successfully'}), 201

@app.route('/chart-of-accounts/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_chart_of_accounts(id):
    account = ChartOfAccounts.query.get_or_404(id)
    if request.method == 'PUT':
        data = request.get_json()
        account.account_code = data.get('account_code', account.account_code)
        account.account_name = data.get('account_name', account.account_name)
        account.account_type = data.get('account_type', account.account_type)
        account.category = data.get('category', account.category)
        account.sub_account_details = data.get('sub_account_details', account.sub_account_details)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(account)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts deleted successfully'})

# CRUD for InvoiceIssued
@app.route('/invoices', methods=['GET', 'POST'])
@jwt_required()
def manage_invoices():
    if request.method == 'GET':
        invoices = InvoiceIssued.query.all()
        return jsonify([{
            'id': inv.id,
            'invoice_number': inv.invoice_number,
            'date_issued': inv.date_issued,
            'customer_name': inv.customer_name,
            'account_type': inv.account_type,
            'amount': inv.amount,
            'coa_id': inv.coa_id
        } for inv in invoices])

    elif request.method == 'POST':
        data = request.get_json()
        new_invoice = InvoiceIssued(
            invoice_number=data['invoice_number'],
            date_issued=data['date_issued'],
            customer_name=data['customer_name'],
            account_type=data['account_type'],
            amount=data['amount'],
            coa_id=data['coa_id']
        )
        db.session.add(new_invoice)
        db.session.commit()
        return jsonify({'message': 'Invoice created successfully'}), 201

@app.route('/invoices/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_invoice(id):
    invoice = InvoiceIssued.query.get_or_404(id)
    if request.method == 'PUT':
        data = request.get_json()
        invoice.invoice_number = data.get('invoice_number', invoice.invoice_number)
        invoice.date_issued = data.get('date_issued', invoice.date_issued)
        invoice.customer_name = data.get('customer_name', invoice.customer_name)
        invoice.account_type = data.get('account_type', invoice.account_type)
        invoice.amount = data.get('amount', invoice.amount)
        invoice.coa_id = data.get('coa_id', invoice.coa_id)
        db.session.commit()
        return jsonify({'message': 'Invoice updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(invoice)
        db.session.commit()
        return jsonify({'message': 'Invoice deleted successfully'})

# CRUD for GeneralJournal
@app.route('/general-journals', methods=['GET', 'POST'])
@jwt_required()
def manage_general_journals():
    if request.method == 'GET':
        journals = GeneralJournal.query.all()
        return jsonify([{
            'id': journal.id,
            'date': journal.date,
            'coa_id': journal.coa_id,
            'description': journal.description,
            'debit': journal.debit,
            'credit': journal.credit
        } for journal in journals])

    elif request.method == 'POST':
        data = request.get_json()
        new_journal = GeneralJournal(
            date=data['date'],
            coa_id=data['coa_id'],
            description=data.get('description'),
            debit=data['debit'],
            credit=data['credit']
        )
        db.session.add(new_journal)
        db.session.commit()
        return jsonify({'message': 'General Journal entry created successfully'}), 201

@app.route('/general-journals/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_general_journal(id):
    journal = GeneralJournal.query.get_or_404(id)
    if request.method == 'PUT':
        data = request.get_json()
        journal.date = data.get('date', journal.date)
        journal.coa_id = data.get('coa_id', journal.coa_id)
        journal.description = data.get('description', journal.description)
        journal.debit = data.get('debit', journal.debit)
        journal.credit = data.get('credit', journal.credit)
        db.session.commit()
        return jsonify({'message': 'General Journal entry updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(journal)
        db.session.commit()
        return jsonify({'message': 'General Journal entry deleted successfully'})

# CRUD for CashReceiptJournal
@app.route('/cash-receipt-journals', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_receipt_journals():
    if request.method == 'GET':
        journals = CashReceiptJournal.query.all()
        return jsonify([{
            'id': journal.id,
            'receipt_date': journal.receipt_date,
            'receipt_no': journal.receipt_no,
            'ref_no': journal.ref_no,
            'from_whom_received': journal.from_whom_received,
            'description': journal.description,
            'account_class': journal.account_class,
            'account_type': journal.account_type,
            'account_debited': journal.account_debited,
            'cash': journal.cash,
            'bank': journal.bank,
            'total': journal.total
        } for journal in journals])

    elif request.method == 'POST':
        data = request.get_json()
        new_journal = CashReceiptJournal(
            receipt_date=data['receipt_date'],
            receipt_no=data['receipt_no'],
            ref_no=data.get('ref_no'),
            from_whom_received=data['from_whom_received'],
            description=data.get('description'),
            account_class=data['account_class'],
            account_type=data['account_type'],
            account_debited=data['account_debited'],
            cash=data['cash'],
            bank=data['bank'],
            total=data['total']
        )
        db.session.add(new_journal)
        db.session.commit()
        return jsonify({'message': 'Cash Receipt Journal entry created successfully'}), 201

@app.route('/cash-receipt-journals/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_cash_receipt_journal(id):
    journal = CashReceiptJournal.query.get_or_404(id)
    if request.method == 'PUT':
        data = request.get_json()
        journal.receipt_date = data.get('receipt_date', journal.receipt_date)
        journal.receipt_no = data.get('receipt_no', journal.receipt_no)
        journal.ref_no = data.get('ref_no', journal.ref_no)
        journal.from_whom_received = data.get('from_whom_received', journal.from_whom_received)
        journal.description = data.get('description', journal.description)
        journal.account_class = data.get('account_class', journal.account_class)
        journal.account_type = data.get('account_type', journal.account_type)
        journal.account_debited = data.get('account_debited', journal.account_debited)
        journal.cash = data.get('cash', journal.cash)
        journal.bank = data.get('bank', journal.bank)
        journal.total = data.get('total', journal.total)
        db.session.commit()
        return jsonify({'message': 'Cash Receipt Journal entry updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(journal)
        db.session.commit()
        return jsonify({'message': 'Cash Receipt Journal entry deleted successfully'})

# CRUD for CashDisbursementJournal
@app.route('/cash-disbursement-journals', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_disbursement_journals():
    if request.method == 'GET':
        journals = CashDisbursementJournal.query.all()
        return jsonify([{
            'id': journal.id,
            'disbursement_date': journal.disbursement_date,
            'cheque_no': journal.cheque_no,
            'p_voucher_no': journal.p_voucher_no,
            'to_whom_paid': journal.to_whom_paid,
            'description': journal.description,
            'account_class': journal.account_class,
            'account_type': journal.account_type,
            'account_credited': journal.account_credited,
            'cash': journal.cash,
            'bank': journal.bank,
            'total': journal.total,
            'vote_total': journal.vote_total
        } for journal in journals])

    elif request.method == 'POST':
        data = request.get_json()
        new_journal = CashDisbursementJournal(
            disbursement_date=data['disbursement_date'],
            cheque_no=data['cheque_no'],
            p_voucher_no=data.get('p_voucher_no'),
            to_whom_paid=data['to_whom_paid'],
            description=data.get('description'),
            account_class=data['account_class'],
            account_type=data['account_type'],
            account_credited=data['account_credited'],
            cash=data['cash'],
            bank=data['bank'],
            total=data['total'],
            vote_total=data['vote_total']
        )
        db.session.add(new_journal)
        db.session.commit()
        return jsonify({'message': 'Cash Disbursement Journal entry created successfully'}), 201

@app.route('/cash-disbursement-journals/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_cash_disbursement_journal(id):
    journal = CashDisbursementJournal.query.get_or_404(id)
    if request.method == 'PUT':
        data = request.get_json()
        journal.disbursement_date = data.get('disbursement_date', journal.disbursement_date)
        journal.cheque_no = data.get('cheque_no', journal.cheque_no)
        journal.p_voucher_no = data.get('p_voucher_no', journal.p_voucher_no)
        journal.to_whom_paid = data.get('to_whom_paid', journal.to_whom_paid)
        journal.description = data.get('description', journal.description)
        journal.account_class = data.get('account_class', journal.account_class)
        journal.account_type = data.get('account_type', journal.account_type)
        journal.account_credited = data.get('account_credited', journal.account_credited)
        journal.cash = data.get('cash', journal.cash)
        journal.bank = data.get('bank', journal.bank)
        journal.total = data.get('total', journal.total)
        journal.vote_total = data.get('vote_total', journal.vote_total)
        db.session.commit()
        return jsonify({'message': 'Cash Disbursement Journal entry updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(journal)
        db.session.commit()
        return jsonify({'message': 'Cash Disbursement Journal entry deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)
