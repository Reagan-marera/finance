from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, ChartOfAccounts, InvoiceIssued, GeneralJournal, CashReceiptJournal, CashDisbursementJournal

# Initialize the Flask app
app = Flask(__name__)

# Configure SQLite database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///financial_reporting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize the database after app configuration
db.init_app(app)

# Initialize extensions
migrate = Migrate(app, db)
CORS(app)
jwt = JWTManager(app)

# User registration route
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    # Check if the user already exists
    user = User.query.filter_by(username=data['username']).first()
    if user:
        return jsonify({'message': 'Username already exists'}), 400

    # Create a new user
    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Login route
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Protected route to get the user's info (JWT protected)
@app.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({
        'username': user.username,
        'email': user.email
    })

# InvoiceIssued route - GET all and POST new invoice issued
@app.route('/invoice-issued', methods=['GET', 'POST'])
@jwt_required()
def manage_invoice_issued():
    if request.method == 'GET':
        invoices = InvoiceIssued.query.all()
        return jsonify([{
            'id': inv.id,
            'invoice_number': inv.invoice_number,
            'date_issued': inv.date_issued,
            'customer_name': inv.customer_name,
            'amount': inv.amount,
            'coa_id': inv.coa_id,  # Including ChartOfAccounts reference
            'account_name': inv.coa.account_name  # Accessing the name of the linked account
        } for inv in invoices])

    elif request.method == 'POST':
        data = request.get_json()

        # Ensure COA ID exists in the ChartOfAccounts table
        coa = ChartOfAccounts.query.get(data['coa_id'])
        if not coa:
            return jsonify({'message': 'Invalid Chart of Accounts ID'}), 400

        new_invoice = InvoiceIssued(
            invoice_number=data['invoice_number'],
            date_issued=data['date_issued'],
            customer_name=data['customer_name'],
            amount=data['amount'],
            coa_id=data['coa_id']  # Store the reference to ChartOfAccounts
        )
        db.session.add(new_invoice)
        db.session.commit()
        return jsonify({'message': 'Invoice issued created successfully'}), 201

# GeneralJournal route - GET all and POST new journal entry
@app.route('/general-journal', methods=['GET', 'POST'])
@jwt_required()
def manage_general_journal():
    if request.method == 'GET':
        entries = GeneralJournal.query.all()
        return jsonify([{
            'id': entry.id,
            'date': entry.date,
            'coa_id': entry.coa_id,  # Including ChartOfAccounts reference
            'debit': entry.debit,
            'credit': entry.credit,
            'description': entry.description,
            'account_name': entry.coa.account_name  # Accessing the name of the linked account
        } for entry in entries])

    elif request.method == 'POST':
        data = request.get_json()

        # Ensure COA ID exists in the ChartOfAccounts table
        coa = ChartOfAccounts.query.get(data['coa_id'])
        if not coa:
            return jsonify({'message': 'Invalid Chart of Accounts ID'}), 400

        new_entry = GeneralJournal(
            date=data['date'],
            coa_id=data['coa_id'],  # Store the reference to ChartOfAccounts
            debit=data['debit'],
            credit=data['credit'],
            description=data.get('description', '')
        )
        db.session.add(new_entry)
        db.session.commit()
        return jsonify({'message': 'General journal entry created successfully'}), 201

# CashReceiptJournal route - GET all and POST new receipt
@app.route('/cash-receipt-journal', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_receipt_journal():
    if request.method == 'GET':
        receipts = CashReceiptJournal.query.all()
        return jsonify([{
            'id': receipt.id,
            'receipt_date': receipt.receipt_date,
            'amount_received': receipt.amount_received,
            'customer_name': receipt.customer_name
        } for receipt in receipts])

    elif request.method == 'POST':
        data = request.get_json()
        new_receipt = CashReceiptJournal(
            receipt_date=data['receipt_date'],
            amount_received=data['amount_received'],
            customer_name=data['customer_name']
        )
        db.session.add(new_receipt)
        db.session.commit()
        return jsonify({'message': 'Cash receipt journal created successfully'}), 201

# CashDisbursementJournal route - GET all and POST new disbursement
@app.route('/cash-disbursement-journal', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_disbursement_journal():
    if request.method == 'GET':
        disbursements = CashDisbursementJournal.query.all()
        return jsonify([{
            'id': disbursement.id,
            'disbursement_date': disbursement.disbursement_date,
            'amount_paid': disbursement.amount_paid,
            'supplier_name': disbursement.supplier_name
        } for disbursement in disbursements])

    elif request.method == 'POST':
        data = request.get_json()
        new_disbursement = CashDisbursementJournal(
            disbursement_date=data['disbursement_date'],
            amount_paid=data['amount_paid'],
            supplier_name=data['supplier_name']
        )
        db.session.add(new_disbursement)
        db.session.commit()
        return jsonify({'message': 'Cash disbursement journal created successfully'}), 201

if __name__ == '__main__':
    app.run(debug=True)
