from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from models import db, User, OTP, ChartOfAccounts, InvoiceIssued, CashReceiptJournal, CashDisbursementJournal
from functools import wraps
from werkzeug.security import generate_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import random
import string
from datetime import date
# Initialize the Flask app
app = Flask(__name__)

# Configure the app
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///financial_reporting.db'  # Use your actual database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize Mail and extensions
mail = Mail(app)  # Fixed: Create Mail instance and initialize
db.init_app(app)
migrate = Migrate(app, db)
CORS(app)
jwt = JWTManager(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'marierareagan@gmail.com'  
app.config['MAIL_PASSWORD'] = 'uxzu zvnq zwlt sydn ' 
app.config['MAIL_TIMEOUT'] = 60  # Increase the timeout to 60 seconds

  # Enable debugging for detailed logs


def role_required(role):
    def wrapper(fn):
        @wraps(fn)  
        @jwt_required()
        def decorated(*args, **kwargs):
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if not current_user or current_user.role != role:
                return jsonify({'message': 'Access forbidden: Insufficient privileges'}), 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper
def parse_date(date_str):
    """Parse a date string in 'YYYY-MM-DD' format to a date object."""
    try:
        return date.fromisoformat(date_str)
    except ValueError:
        return None

@app.route('/request_reset_password', methods=['POST'])
def request_reset_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Log the email for debugging
    print(f"Received email: {email}")

    user = User.query.filter(User.email.ilike(email)).first()  # Use case-insensitive search
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    otp = generate_otp()
    store_otp(email, otp)

    username = user.username  
    msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[email])
    msg.body = f"""
    Hello, {username}

    Here's the verification code to reset your password:

    {otp}

    To reset your password, enter this verification code when prompted.

    This code will expire in 5 minutes.

    If you did not request this password reset, please ignore this email.
    """
    mail.send(msg)

    return jsonify({"message": "OTP sent to your email"}), 200

@app.route('/get_user_role_by_email', methods=['POST'])
def get_user_role_by_email():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    return jsonify({'role': user.role}), 200
 
@app.route('/check_email_exists', methods=['POST'])
def check_email_exists():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'Email exists'}), 200
    else:
        return jsonify({'error': 'Email not found'}), 404

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    otp_entry = OTP.query.filter_by(email=email).first()

    if not otp_entry:
        return jsonify({"error": "OTP not requested or does not exist"}), 404

    if datetime.utcnow() > otp_entry.expiry:
        return jsonify({
            "error": "OTP expired",
            "message": "Did time run out? Request a new OTP.",
            "request_new_otp": True
        }), 400

    if otp_entry.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    return jsonify({"message": "OTP is valid"}), 200  # Fixed return statement

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not email or not otp or not new_password:
        return jsonify({"error": "Missing email, OTP or new password"}), 400

    otp_entry = OTP.query.filter_by(email=email).first()
    if not otp_entry:
        return jsonify({"error": "OTP not requested"}), 404

    if datetime.utcnow() > otp_entry.expiry:
        return jsonify({"error": "OTP expired"}), 400

    if otp_entry.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    db.session.delete(otp_entry)
    db.session.commit()

    return jsonify({"message": "Password reset successfully"}), 200

@app.route('/request_new_otp', methods=['POST'])
def request_new_otp():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    otp = generate_otp()
    store_otp(email, otp)

    username = user.username  
    msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[email])
    msg.body = f"""
    Hello, {username}

    Here's the verification code to reset your password:

    {otp}

    To reset your password, enter this verification code when prompted.

    This code will expire in 5 minutes.

    If you did not request this password reset, please ignore this email.
    """
    mail.send(msg)

    return jsonify({"message": "New OTP sent to your email"}), 200

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def store_otp(email, otp):
    expiry = datetime.utcnow() + timedelta(minutes=5)
    otp_entry = OTP.query.filter_by(email=email).first()
    if otp_entry:
        otp_entry.otp = otp
        otp_entry.expiry = expiry
    else:
        otp_entry = OTP(email=email, otp=otp, expiry=expiry)
        db.session.add(otp_entry)
    db.session.commit()

# Register route for user registration
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400

    user = User(username=data['username'], email=data['email'], role=data.get('role', 'User'))
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
        return jsonify({'token': token, 'role': user.role}), 200
    return jsonify({'message': 'Invalid username or password'}), 401



# CEO-specific routes
@app.route('/users', methods=['GET'])
@role_required('CEO')
def get_all_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    } for user in users])

@app.route('/users/<int:id>', methods=['DELETE'])
@role_required('CEO')
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

# Route to get all transactions
@app.route('/transactions', methods=['GET'])
@role_required('CEO')
def get_all_transactions():
    # Query all required models
    invoices = InvoiceIssued.query.all()
    cash_receipts = CashReceiptJournal.query.all()
    cash_disbursements = CashDisbursementJournal.query.all()

    # Prepare the transactions dictionary
    transactions = {
        'invoices_issued': [{
            'id': invoice.id,
            'invoice_number': invoice.invoice_number,
            'date_issued': invoice.date_issued,
            'amount': invoice.amount,
            'account_class': invoice.account_class,
            'account_type': invoice.account_type,
            'account_debited': invoice.account_debited,
            'account_credited': invoice.account_credited,
            'invoice_type': invoice.invoice_type,
            'grn_number': invoice.grn_number,
            'parent_account': invoice.parent_account  # Added parent_account
        } for invoice in invoices],
        
        'cash_receipts': [{
            'id': receipt.id,
            'receipt_date': receipt.receipt_date,
            'receipt_no': receipt.receipt_no,
            'from_whom_received': receipt.from_whom_received,
            'description': receipt.description,
            'account_class': receipt.account_class,
            'account_type': receipt.account_type,
            'receipt_type': receipt.receipt_type,
            'account_debited': receipt.account_debited,
            'account_credited': receipt.account_credited,
            'cash': receipt.cash,
            'total': receipt.total,
            'parent_account': receipt.parent_account  # Added parent_account
        } for receipt in cash_receipts],
        
        'cash_disbursements': [{
            'id': disbursement.id,
            'disbursement_date': disbursement.disbursement_date,
            'cheque_no': disbursement.cheque_no,
            'to_whom_paid': disbursement.to_whom_paid,
            'payment_type': disbursement.payment_type,
            'description': disbursement.description,
            'account_class': disbursement.account_class,
            'account_type': disbursement.account_type,
            'account_debited': disbursement.account_debited,
            'account_credited': disbursement.account_credited,
            'cash': disbursement.cash,
            'bank': disbursement.bank,
            'vote_total': disbursement.vote_total,
            'parent_account': disbursement.parent_account  # Added parent_account
        } for disbursement in cash_disbursements]
    }

    return jsonify(transactions)


# Route to manage the chart of accounts (GET and POST)
@app.route('/chart-of-accounts', methods=['GET', 'POST'])
@jwt_required()
def manage_chart_of_accounts():
    if request.method == 'GET':
        accounts = ChartOfAccounts.query.all()
        return jsonify([{
            'id': acc.id,
            'parent_account': acc.parent_account,
            'account_name': acc.account_name,
            'account_type': acc.account_type,
            'sub_account_details': acc.sub_account_details
        } for acc in accounts])

    elif request.method == 'POST':
        data = request.get_json()

        # Get the current user_id from the JWT
        current_user_id = get_jwt_identity()  # Assuming JWT contains the user identity

        new_account = ChartOfAccounts(
            parent_account=data['parent_account'],  # Ensuring parent_account is passed
            account_name=data['account_name'],
            account_type=data['account_type'],
            sub_account_details=data.get('sub_account_details'),
            user_id=current_user_id  # Assign the user_id
        )

        db.session.add(new_account)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts created successfully'}), 201


# Route to update or delete chart of accounts (PUT and DELETE)
@app.route('/chart-of-accounts/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_chart_of_accounts(id):
    account = ChartOfAccounts.query.get_or_404(id)
    if request.method == 'PUT':
        data = request.get_json()
        account.parent_account = data.get('parent_account', account.parent_account)  # Fixed to check parent_account
        account.account_name = data.get('account_name', account.account_name)
        account.account_type = data.get('account_type', account.account_type)
        account.sub_account_details = data.get('sub_account_details', account.sub_account_details)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(account)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts deleted successfully'})

# Route to manage invoices (GET and POST)
@app.route('/invoices', methods=['GET', 'POST'])
@jwt_required()
def manage_invoices():
    try:
        current_user = get_jwt_identity()  # Extract `coa_id` from the JWT

        if request.method == 'GET':
            # Fetch invoices associated with the user's `coa_id`
            invoices = InvoiceIssued.query.filter_by(coa_id=current_user).all()
            return jsonify([{
                'id': inv.id,
                'invoice_number': inv.invoice_number,
                'date_issued': inv.date_issued,
                'account_type': inv.account_type,
                'amount': inv.amount,
                'coa_id': inv.coa_id,
                'account_class': inv.account_class,
                'account_debited': inv.account_debited,
                'account_credited': inv.account_credited,
                'grn_number': inv.grn_number,
                'invoice_type': inv.invoice_type,  # Include invoice_type in response
                'parent_account': inv.parent_account  # Include parent_account in response
            } for inv in invoices]), 200

        elif request.method == 'POST':
            data = request.get_json()

            # Validate required fields
            required_fields = ['invoice_number', 'date_issued', 'account_type', 'amount', 'account_class', 'account_debited', 'account_credited', 'invoice_type', 'parent_account']
            missing_fields = [field for field in required_fields if field not in data or not data[field]]
            if missing_fields:
                return jsonify({'error': f'Missing or empty fields: {", ".join(missing_fields)}'}), 400

            # Convert date_issued from string to Python date object
            try:
                date_issued = datetime.strptime(data['date_issued'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Please use YYYY-MM-DD.'}), 400

            # Check if the invoice number already exists
            if InvoiceIssued.query.filter_by(invoice_number=data['invoice_number']).first():
                return jsonify({'error': 'Invoice number already exists'}), 400

            # Create and save the new invoice
            new_invoice = InvoiceIssued(
    invoice_number=data['invoice_number'],
    date_issued=date_issued,  
    account_type=data['account_type'],
    amount=float(data['amount']),
    account_class=data['account_class'],
    account_debited=data['account_debited'],
    account_credited=data['account_credited'],
    grn_number=data.get('grn_number'),
    invoice_type=data['invoice_type'],  # Add invoice_type here
    coa_id=current_user,  # Use `coa_id` from the token
    parent_account=data['parent_account']  # Include parent_account
)

            db.session.add(new_invoice)
            db.session.commit()

            return jsonify({'message': 'Invoice created successfully'}), 201

    except Exception as e:
        app.logger.error(f"Error managing invoices: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500


# Route to update or delete a specific invoice (PUT and DELETE)
@app.route('/invoices/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_invoice(id):
    try:
        current_user = get_jwt_identity()  # Extract `coa_id` from the JWT
        invoice = InvoiceIssued.query.get_or_404(id)

        # Ensure the invoice belongs to the current user (coa_id)
        if invoice.coa_id != current_user:
            return jsonify({'error': 'Unauthorized access to invoice'}), 403

        if request.method == 'PUT':
            data = request.get_json()

            # Update invoice fields only if provided
            invoice.invoice_number = data.get('invoice_number', invoice.invoice_number)
            if 'date_issued' in data:
                try:
                    invoice.date_issued = datetime.strptime(data['date_issued'], '%Y-%m-%d').date()  # Convert to date
                except ValueError:
                    return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400
            invoice.account_type = data.get('account_type', invoice.account_type)
            invoice.amount = float(data.get('amount', invoice.amount))
            invoice.account_class = data.get('account_class', invoice.account_class)
            invoice.account_debited = data.get('account_debited', invoice.account_debited)
            invoice.account_credited = data.get('account_credited', invoice.account_credited)
            invoice.grn_number = data.get('grn_number', invoice.grn_number)  # Update GRN number if provided
            invoice.invoice_type = data.get('invoice_type', invoice.invoice_type)  # Update invoice type
            invoice.parent_account = data.get('parent_account', invoice.parent_account)  # Update parent_account if provided

            db.session.commit()
            return jsonify({'message': 'Invoice updated successfully'}), 200

        elif request.method == 'DELETE':
            db.session.delete(invoice)
            db.session.commit()
            return jsonify({'message': 'Invoice deleted successfully'}), 200

    except Exception as e:
        app.logger.error(f"Error processing invoice {id}: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500
   
@app.route('/cash-receipt-journals', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_receipt_journals():
    try:
        current_user = get_jwt_identity()  # Get the current user's ID
        app.logger.info(f"JWT Identity (current_user): {current_user}")

        if request.method == 'POST':
            data = request.get_json()
            app.logger.info(f"Received data: {data}")

            # Validate required fields
            required_fields = [
                'receipt_date', 'receipt_no', 'from_whom_received',
                'account_class', 'account_type', 'receipt_type',
                'account_debited', 'account_credited', 'cash', 'bank', 'parent_account'
            ]
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400

            # Validate receipt_date format
            try:
                receipt_date = datetime.strptime(data['receipt_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

            # Check for duplicate receipt_no
            if CashReceiptJournal.query.filter_by(receipt_no=data['receipt_no']).first():
                return jsonify({'error': f'Receipt number {data["receipt_no"]} already exists.'}), 400

            # Validate numeric fields
            try:
                cash = float(data['cash'])
                bank = float(data['bank'])
            except ValueError:
                return jsonify({'error': 'Cash and Bank must be numeric values.'}), 400

            # Calculate the total field
            total = cash + bank

            # Create a new CashReceiptJournal entry
            new_journal = CashReceiptJournal(
                receipt_date=receipt_date,
                receipt_no=data['receipt_no'],
                ref_no=data.get('ref_no'),
                from_whom_received=data['from_whom_received'],
                description=data.get('description'),
                account_class=data['account_class'],
                account_type=data['account_type'],
                receipt_type=data['receipt_type'],
                account_debited=data['account_debited'],
                account_credited=data['account_credited'],
                cash=cash,
                bank=bank,
                total=total,
                parent_account=data['parent_account'],
                created_by=current_user
            )
            db.session.add(new_journal)
            db.session.commit()

            return jsonify({'message': 'Journal entry created successfully'}), 201

        elif request.method == 'GET':
            # Fetch all journals created by the current user
            journals = CashReceiptJournal.query.filter_by(created_by=current_user).all()
            result = [
                {
                    'id': journal.id,
                    'receipt_date': journal.receipt_date.strftime('%Y-%m-%d'),
                    'receipt_no': journal.receipt_no,
                    'ref_no': journal.ref_no,
                    'from_whom_received': journal.from_whom_received,
                    'description': journal.description,
                    'account_class': journal.account_class,
                    'account_type': journal.account_type,
                    'receipt_type': journal.receipt_type,
                    'account_debited': journal.account_debited,
                    'account_credited': journal.account_credited,
                    'cash': journal.cash,
                    'bank': journal.bank,
                    'parent_account': journal.parent_account,
                    'total': journal.total,
                }
                for journal in journals
            ]

            return jsonify(result), 200

    except Exception as e:
        app.logger.error(f"Error managing cash receipt journals: {e}", exc_info=True)
        db.session.rollback()  # Rollback any pending transactions
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@app.route('/cash-receipt-journals/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_cash_receipt_journal(id):
    try:
        journal = CashReceiptJournal.query.get(id)

        if not journal:
            return jsonify({"error": "Journal not found"}), 404

        current_user = get_jwt_identity()
        if journal.created_by != current_user:
            return jsonify({"error": "Unauthorized access"}), 403

        if request.method == 'PUT':
            data = request.get_json()

            # Validate and update fields
            if 'receipt_no' in data and data['receipt_no'] != journal.receipt_no:
                if CashReceiptJournal.query.filter_by(receipt_no=data['receipt_no']).first():
                    return jsonify({'error': f'Receipt number {data["receipt_no"]} already exists.'}), 400

            if 'receipt_date' in data:
                try:
                    journal.receipt_date = datetime.strptime(data['receipt_date'], '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

            # Update all provided fields
            journal.receipt_no = data.get('receipt_no', journal.receipt_no)
            journal.ref_no = data.get('ref_no', journal.ref_no)
            journal.from_whom_received = data.get('from_whom_received', journal.from_whom_received)
            journal.description = data.get('description', journal.description)
            journal.account_class = data.get('account_class', journal.account_class)
            journal.account_type = data.get('account_type', journal.account_type)
            journal.account_debited = data.get('account_debited', journal.account_debited)
            journal.account_credited = data.get('account_credited', journal.account_credited)
            journal.cash = data.get('cash', journal.cash)
            journal.bank = data.get('bank', journal.bank)
            journal.parent_account = data.get('parent_account', journal.parent_account)  # Update parent_account if provided

            journal.save()

            return jsonify({'message': 'Journal entry updated successfully'}), 200

        elif request.method == 'DELETE':
            db.session.delete(journal)
            db.session.commit()
            return jsonify({"message": "Journal entry deleted successfully"}), 200

    except Exception as e:
        app.logger.error(f"Error updating/deleting cash receipt journal: {e}")
        return jsonify({"error": "An error occurred while processing your request"}), 500
    
    
@app.route('/cash-disbursement-journals', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_disbursement_journals():
    current_user = get_jwt_identity()  # Ensure we have the current user's identity
    print("Current User:", current_user)  # Debugging

    # Get the current user's ID
    user_id = current_user.get('id') if isinstance(current_user, dict) else current_user

    if request.method == 'GET':
        # Retrieve journals specific to the current user
        journals = CashDisbursementJournal.query.filter_by(created_by=user_id).all()
        return jsonify([{
            'id': journal.id,
            'disbursement_date': journal.disbursement_date.isoformat(),
            'cheque_no': journal.cheque_no,
            'p_voucher_no': journal.p_voucher_no,
            'to_whom_paid': journal.to_whom_paid,
            'description': journal.description,
            'account_class': journal.account_class,
            'account_type': journal.account_type,
            'account_credited': journal.account_credited,
            'account_debited': journal.account_debited,
            'parent_account': journal.parent_account,  # Include parent_account in the response
            'cashbook': journal.cashbook,
            'payment_type': journal.payment_type,
            'cash': journal.cash,
            'bank': journal.bank,
            'total': journal.total,  # Include the total field in the response
            'created_by_user': journal.created_by_user.username if journal.created_by_user else 'Unknown'  # Safely handle None
        } for journal in journals])

    elif request.method == 'POST':
        data = request.get_json()

        # Validate and parse date
        disbursement_date = parse_date(data.get('disbursement_date'))
        if not disbursement_date:
            return jsonify({"error": "Invalid date format. Please use 'YYYY-MM-DD'."}), 400

        # Debugging: Print received data
        print(f"Received Data: {data}")

        # Validate accounts in COA
        account_credited = data['account_credited']
        print(f"Searching for account credited: {account_credited} for user {user_id}")
        coa_entry_credited = ChartOfAccounts.query.filter_by(user_id=user_id, account_name=account_credited).first()

        account_debited = data['account_debited']
        print(f"Searching for account debited: {account_debited} for user {user_id}")
        coa_entry_debited = ChartOfAccounts.query.filter_by(user_id=user_id, account_name=account_debited).first()

        # Check if accounts exist in COA
        if not coa_entry_credited:
            print(f"COA Entry Credited not found for account: {account_credited}")
        if not coa_entry_debited:
            print(f"COA Entry Debited not found for account: {account_debited}")

        if not coa_entry_credited or not coa_entry_debited:
            return jsonify({'error': 'Invalid account credited or debited. Account does not exist in Chart of Accounts'}), 400

        # Include parent_account field here
        parent_account = data.get('parent_account')

        # Create a new CashDisbursementJournal entry
        new_journal = CashDisbursementJournal(
            disbursement_date=disbursement_date,
            cheque_no=data['cheque_no'],
            p_voucher_no=data.get('p_voucher_no'),
            to_whom_paid=data['to_whom_paid'],
            description=data.get('description'),  # Optional field
            account_class=data['account_class'],
            account_type=data['account_type'],
            payment_type=data['payment_type'],
            cashbook=data['cashbook'],
            account_credited=account_credited,
            account_debited=account_debited,
            cash=data['cash'],
            bank=data['bank'],
            parent_account=parent_account,  # Include parent_account when creating a new journal
            created_by=user_id  # Associate the journal entry with the current user
        )

        # Calculate total before saving
        new_journal.total = new_journal.cash + new_journal.bank

        db.session.add(new_journal)
        db.session.commit()
        return jsonify({'message': 'Cash Disbursement Journal entry created successfully'}), 201

@app.route('/cash-disbursement-journals/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_cash_disbursement_journals(id):
    current_user = get_jwt_identity()  # Ensure we have the current user's identity

    # Debugging: Verify current_user data
    print("Current User:", current_user)

    # Get the current user's ID
    user_id = current_user.get('id') if isinstance(current_user, dict) else current_user

    # Fetch the journal entry and ensure it belongs to the current user
    journal = CashDisbursementJournal.query.filter_by(id=id, created_by=user_id).first()
    if not journal:
        return jsonify({'error': 'Journal entry not found or you do not have permission to modify this entry'}), 404

    if request.method == 'PUT':
        # Update the journal entry
        data = request.get_json()

        # Validate the account credited exists in the COA for the user
        account_credited = data.get('account_credited', journal.account_credited)
        coa_entry_credited = ChartOfAccounts.query.filter_by(user_id=user_id, account_name=account_credited).first()

        # Validate the account debited exists in the COA for the user
        account_debited = data.get('account_debited', journal.account_debited)
        coa_entry_debited = ChartOfAccounts.query.filter_by(user_id=user_id, account_name=account_debited).first()

        if not coa_entry_credited or not coa_entry_debited:
            return jsonify({'error': 'Invalid account credited or debited. Account does not exist in Chart of Accounts'}), 400

        # Include parent_account field in the update
        parent_account = data.get('parent_account', journal.parent_account)

        # Update fields
        journal.disbursement_date = data.get('disbursement_date', journal.disbursement_date)
        journal.cheque_no = data.get('cheque_no', journal.cheque_no)
        journal.p_voucher_no = data.get('p_voucher_no', journal.p_voucher_no)
        journal.to_whom_paid = data.get('to_whom_paid', journal.to_whom_paid)
        journal.description = data.get('description', journal.description)
        journal.account_class = data.get('account_class', journal.account_class)
        journal.account_type = data.get('account_type', journal.account_type)
        journal.payment_type = data.get('payment_type', journal.payment_type)
        journal.cashbook = data.get('cashbook', journal.cashbook)
        journal.account_credited = account_credited
        journal.account_debited = account_debited
        journal.cash = data.get('cash', journal.cash)
        journal.bank = data.get('bank', journal.bank)
        journal.parent_account = parent_account  # Update parent_account field

        # Recalculate the total after any changes
        journal.total = journal.cash + journal.bank

        db.session.commit()
        return jsonify({'message': 'Cash Disbursement Journal entry updated successfully'})

    elif request.method == 'DELETE':
        # Delete the journal entry
        db.session.delete(journal)
        db.session.commit()
        return jsonify({'message': 'Cash Disbursement Journal entry deleted successfully'})
 
@app.route('/usertransactions', methods=['GET'])
@jwt_required()
def get_user_transactions():
    # Get the current user's ID from the JWT
    current_user_id = get_jwt_identity()

    # Query transactions for the current user only
    invoices = InvoiceIssued.query.filter_by(user_id=current_user_id).all()
    cash_receipts = CashReceiptJournal.query.filter_by(created_by=current_user_id).all()  # Use 'created_by' instead of 'user_id'
    cash_disbursements = CashDisbursementJournal.query.filter_by(created_by=current_user_id).all()  # Same for CashDisbursementJournal

    # Prepare the transactions dictionary
    transactions = {
        'invoices_issued': [{
            'id': invoice.id,
            'invoice_number': invoice.invoice_number,
            'date_issued': invoice.date_issued,
            'amount': invoice.amount,
            'account_class': invoice.account_class,
            'account_type': invoice.account_type,
            'account_debited': invoice.account_debited,
            'account_credited': invoice.account_credited,
            'invoice_type': invoice.invoice_type,
            'grn_number': invoice.grn_number,
            'parent_account': invoice.parent_account  # Added parent_account
        } for invoice in invoices],
        
        'cash_receipts': [{
            'id': receipt.id,
            'receipt_date': receipt.receipt_date,
            'receipt_no': receipt.receipt_no,
            'from_whom_received': receipt.from_whom_received,
            'description': receipt.description,
            'account_class': receipt.account_class,
            'account_type': receipt.account_type,
            'receipt_type': receipt.receipt_type,
            'account_debited': receipt.account_debited,
            'account_credited': receipt.account_credited,
            'cash': receipt.cash,
            'total': receipt.total,
            'parent_account': receipt.parent_account  # Added parent_account
        } for receipt in cash_receipts],
        
        'cash_disbursements': [{
            'id': disbursement.id,
            'disbursement_date': disbursement.disbursement_date,
            'cheque_no': disbursement.cheque_no,
            'to_whom_paid': disbursement.to_whom_paid,
            'payment_type': disbursement.payment_type,
            'description': disbursement.description,
            'account_class': disbursement.account_class,
            'account_type': disbursement.account_type,
            'account_debited': disbursement.account_debited,
            'account_credited': disbursement.account_credited,
            'cash': disbursement.cash,
            'bank': disbursement.bank,
            'parent_account': disbursement.parent_account  # Added parent_account
        } for disbursement in cash_disbursements]
    }

    return jsonify(transactions)

if __name__ == '__main__':
    app.run(debug=True)