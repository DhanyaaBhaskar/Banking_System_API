from flask import Flask, request, jsonify
import secrets
import os
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
import bcrypt

from database import get_db_connection, init_db


app = Flask(__name__)

# Load environment variables
load_dotenv()

# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

jwt = JWTManager(app)
# -------------------------------------------------
# JWT ERROR HANDLERS
# -------------------------------------------------

@jwt.expired_token_loader
def expired_token(jwt_header, jwt_payload):
    return jsonify({
        "error": "Token has expired"
    }), 401


@jwt.invalid_token_loader
def invalid_token(error):
    return jsonify({
        "error": "Invalid token"
    }), 401


@jwt.unauthorized_loader
def missing_token(error):
    return jsonify({
        "error": "Authorization token is required"
    }), 401


# Initialize database
init_db()
    
# -------------------------------------------------
# HOME
# -------------------------------------------------

@app.route("/")
def home():
    return jsonify({
        "message": "Banking System API is running successfully!"
    })


# -------------------------------------------------
# SIGNUP
# -------------------------------------------------

@app.route("/signup", methods=["POST"])
def signup():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    # Validate input
    if not name or not email or not password:
        return jsonify({
            "error": "Name, email and password are required"
        }), 400
    email = email.strip().lower()
    name = name.strip()

    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({
            "error": "Enter a valid email address"
        }), 400
    # Password length validation
    if len(password) < 6:
        return jsonify({
            "error": "Password must be at least 6 characters"
        }), 400

    conn = get_db_connection()

    # Check whether email already exists
    existing_user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing_user:
        conn.close()

        return jsonify({
            "error": "Email already registered"
        }), 409

    # Hash password
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    # Create customer
    conn.execute(
        """
        INSERT INTO users (name, email, password, role)
        VALUES (?, ?, ?, ?)
        """,
        (
            name,
            email,
            hashed_password.decode("utf-8"),
            "customer"
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "User registered successfully"
    }), 201


# -------------------------------------------------
# LOGIN
# -------------------------------------------------

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT id, name, email, password, role
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    conn.close()

    if not user:
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    # Check password
    password_correct = bcrypt.checkpw(
        password.encode("utf-8"),
        user["password"].encode("utf-8")
    )

    if not password_correct:
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    # JWT identity
    access_token = create_access_token(
        identity=str(user["id"])
    )

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200


# -------------------------------------------------
# TEST PROTECTED ROUTE
# -------------------------------------------------

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():

    user_id = get_jwt_identity()

    return jsonify({
        "message": "You are authenticated!",
        "user_id": user_id
    }), 200

# -------------------------------------------------
# CREATE BANK ACCOUNT
# -------------------------------------------------

@app.route("/account/create", methods=["POST"])
@jwt_required()
def create_account():

    user_id = get_jwt_identity()

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    account_type = data.get("account_type")

    # Validate account type
    if account_type not in ["Savings", "Current"]:
        return jsonify({
            "error": "Account type must be Savings or Current"
        }), 400

    conn = get_db_connection()

    # Check whether user exists
    user = conn.execute(
        "SELECT id, name, email FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        conn.close()

        return jsonify({
            "error": "User not found"
        }), 404

    # Generate unique account number
    while True:

        account_number = str(
            secrets.randbelow(9000000000) + 1000000000
        )

        existing_account = conn.execute(
            """
            SELECT id
            FROM accounts
            WHERE account_number = ?
            """,
            (account_number,)
        ).fetchone()

        if not existing_account:
            break

    # Create account
    cursor = conn.execute(
        """
        INSERT INTO accounts
        (user_id, account_number, account_type, balance, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user_id,
            account_number,
            account_type,
            0,
            "active"
        )
    )

    conn.commit()

    account_id = cursor.lastrowid

    conn.close()

    return jsonify({
        "message": "Bank account created successfully",
        "account": {
            "id": account_id,
            "account_number": account_number,
            "account_holder": user["name"],
            "email": user["email"],
            "account_type": account_type,
            "balance": 0,
            "status": "active"
        }
    }), 201
# -------------------------------------------------
# VIEW MY ACCOUNT
# -------------------------------------------------

@app.route("/account/me", methods=["GET"])
@jwt_required()
def get_my_account():

    user_id = get_jwt_identity()

    conn = get_db_connection()

    accounts = conn.execute(
        """
        SELECT
            accounts.id,
            accounts.account_number,
            users.name AS account_holder,
            users.email,
            accounts.account_type,
            accounts.balance,
            accounts.status
        FROM accounts
        JOIN users
            ON accounts.user_id = users.id
        WHERE accounts.user_id = ?
        """,
        (user_id,)
    ).fetchall()

    conn.close()

    if not accounts:
        return jsonify({
            "message": "No bank account found"
        }), 404

    account_list = []

    for account in accounts:
        account_list.append({
            "id": account["id"],
            "account_number": account["account_number"],
            "account_holder": account["account_holder"],
            "email": account["email"],
            "account_type": account["account_type"],
            "balance": account["balance"],
            "status": account["status"]
        })

    return jsonify({
        "accounts": account_list
    }), 200
# -------------------------------------------------
# ADMIN - VIEW ACCOUNT BY ID
# -------------------------------------------------

@app.route("/account/<int:account_id>", methods=["GET"])
@jwt_required()
def get_account_by_id(account_id):

    user_id = get_jwt_identity()

    conn = get_db_connection()

    # Check whether logged-in user is admin
    admin = conn.execute(
        """
        SELECT role
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not admin or admin["role"] != "admin":
        conn.close()

        return jsonify({
            "error": "Admin access required"
        }), 403

    account = conn.execute(
        """
        SELECT
            accounts.id,
            accounts.account_number,
            users.name AS account_holder,
            users.email,
            accounts.account_type,
            accounts.balance,
            accounts.status
        FROM accounts
        JOIN users
            ON accounts.user_id = users.id
        WHERE accounts.id = ?
        """,
        (account_id,)
    ).fetchone()

    conn.close()

    if not account:
        return jsonify({
            "error": "Account not found"
        }), 404

    return jsonify({
        "account": {
            "id": account["id"],
            "account_number": account["account_number"],
            "account_holder": account["account_holder"],
            "email": account["email"],
            "account_type": account["account_type"],
            "balance": account["balance"],
            "status": account["status"]
        }
    }), 200
# -------------------------------------------------
# DEPOSIT MONEY
# -------------------------------------------------

@app.route("/deposit", methods=["POST"])
@jwt_required()
def deposit():

    user_id = get_jwt_identity()

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    account_number = data.get("account_number")
    amount = data.get("amount")

    # Validate account number
    if not account_number:
        return jsonify({
            "error": "Account number is required"
        }), 400

    # Validate amount
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return jsonify({
            "error": "Amount must be a valid number"
        }), 400

    if amount <= 0:
        return jsonify({
            "error": "Deposit amount must be greater than zero"
        }), 400

    conn = get_db_connection()

    # Find the account
    account = conn.execute(
        """
        SELECT id, user_id, account_number, balance, status
        FROM accounts
        WHERE account_number = ?
        """,
        (account_number,)
    ).fetchone()

    if not account:
        conn.close()

        return jsonify({
            "error": "Account not found"
        }), 404

    # Check account ownership
    if str(account["user_id"]) != str(user_id):
        conn.close()

        return jsonify({
            "error": "You can deposit only into your own account"
        }), 403

    # Check account status
    if account["status"] != "active":
        conn.close()

        return jsonify({
            "error": "Account is blocked"
        }), 403

    # Calculate new balance
    new_balance = account["balance"] + amount

    # Update balance
    conn.execute(
        """
        UPDATE accounts
        SET balance = ?
        WHERE id = ?
        """,
        (new_balance, account["id"])
    )

    # Record transaction
    conn.execute(
        """
        INSERT INTO transactions
        (from_account, to_account, amount, type)
        VALUES (?, ?, ?, ?)
        """,
        (
            None,
            account["id"],
            amount,
            "deposit"
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Deposit successful",
        "account_number": account["account_number"],
        "deposited_amount": amount,
        "new_balance": new_balance
    }), 200
# -------------------------------------------------
# WITHDRAW MONEY
# -------------------------------------------------

@app.route("/withdraw", methods=["POST"])
@jwt_required()
def withdraw():

    user_id = get_jwt_identity()

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    account_number = data.get("account_number")
    amount = data.get("amount")

    # Validate account number
    if not account_number:
        return jsonify({
            "error": "Account number is required"
        }), 400

    # Validate amount
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return jsonify({
            "error": "Amount must be a valid number"
        }), 400

    if amount <= 0:
        return jsonify({
            "error": "Withdrawal amount must be greater than zero"
        }), 400

    conn = get_db_connection()

    # Find account
    account = conn.execute(
        """
        SELECT id, user_id, account_number, balance, status
        FROM accounts
        WHERE account_number = ?
        """,
        (account_number,)
    ).fetchone()

    if not account:
        conn.close()

        return jsonify({
            "error": "Account not found"
        }), 404

    # Check account ownership
    if str(account["user_id"]) != str(user_id):
        conn.close()

        return jsonify({
            "error": "You can withdraw only from your own account"
        }), 403

    # Check account status
    if account["status"] != "active":
        conn.close()

        return jsonify({
            "error": "Account is blocked"
        }), 403

    # Check sufficient balance
    if amount > account["balance"]:
        conn.close()

        return jsonify({
            "error": "Insufficient balance",
            "current_balance": account["balance"],
            "requested_amount": amount
        }), 400

    # Calculate new balance
    new_balance = account["balance"] - amount

    # Update balance
    conn.execute(
        """
        UPDATE accounts
        SET balance = ?
        WHERE id = ?
        """,
        (new_balance, account["id"])
    )

    # Record transaction
    conn.execute(
        """
        INSERT INTO transactions
        (from_account, to_account, amount, type)
        VALUES (?, ?, ?, ?)
        """,
        (
            account["id"],
            None,
            amount,
            "withdraw"
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Withdrawal successful",
        "account_number": account["account_number"],
        "withdrawn_amount": amount,
        "new_balance": new_balance
    }), 200
# -------------------------------------------------
# TRANSFER MONEY
# -------------------------------------------------

@app.route("/transfer", methods=["POST"])
@jwt_required()
def transfer():

    user_id = get_jwt_identity()

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    sender_account_number = data.get("sender_account_number")
    receiver_account_number = data.get("receiver_account_number")
    amount = data.get("amount")

    # Validate account numbers
    if not sender_account_number or not receiver_account_number:
        return jsonify({
            "error": "Sender and receiver account numbers are required"
        }), 400

    # Prevent transfer to same account
    if sender_account_number == receiver_account_number:
        return jsonify({
            "error": "Sender and receiver accounts cannot be the same"
        }), 400

    # Validate amount
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return jsonify({
            "error": "Amount must be a valid number"
        }), 400

    if amount <= 0:
        return jsonify({
            "error": "Transfer amount must be greater than zero"
        }), 400

    conn = get_db_connection()

    # Find sender account
    sender = conn.execute(
        """
        SELECT id, user_id, account_number, balance, status
        FROM accounts
        WHERE account_number = ?
        """,
        (sender_account_number,)
    ).fetchone()

    if not sender:
        conn.close()

        return jsonify({
            "error": "Sender account not found"
        }), 404

    # Check sender ownership
    if str(sender["user_id"]) != str(user_id):
        conn.close()

        return jsonify({
            "error": "You can transfer only from your own account"
        }), 403

    # Check sender status
    if sender["status"] != "active":
        conn.close()

        return jsonify({
            "error": "Sender account is blocked"
        }), 403

    # Find receiver account
    receiver = conn.execute(
        """
        SELECT id, account_number, balance, status
        FROM accounts
        WHERE account_number = ?
        """,
        (receiver_account_number,)
    ).fetchone()

    if not receiver:
        conn.close()

        return jsonify({
            "error": "Receiver account not found"
        }), 404

    # Check receiver status
    if receiver["status"] != "active":
        conn.close()

        return jsonify({
            "error": "Receiver account is blocked"
        }), 403

    # Check sufficient balance
    if amount > sender["balance"]:
        conn.close()

        return jsonify({
            "error": "Insufficient balance",
            "current_balance": sender["balance"],
            "requested_amount": amount
        }), 400

    # Calculate new balances
    sender_new_balance = sender["balance"] - amount
    receiver_new_balance = receiver["balance"] + amount

    # Update sender
    conn.execute(
        """
        UPDATE accounts
        SET balance = ?
        WHERE id = ?
        """,
        (sender_new_balance, sender["id"])
    )

    # Update receiver
    conn.execute(
        """
        UPDATE accounts
        SET balance = ?
        WHERE id = ?
        """,
        (receiver_new_balance, receiver["id"])
    )

    # Record transfer
    conn.execute(
        """
        INSERT INTO transactions
        (from_account, to_account, amount, type)
        VALUES (?, ?, ?, ?)
        """,
        (
            sender["id"],
            receiver["id"],
            amount,
            "transfer"
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Transfer successful",
        "from_account": sender["account_number"],
        "to_account": receiver["account_number"],
        "transferred_amount": amount,
        "sender_new_balance": sender_new_balance
    }), 200
# -------------------------------------------------
# GET MY TRANSACTIONS
# -------------------------------------------------

@app.route("/transactions", methods=["GET"])
@jwt_required()
def get_transactions():

    user_id = get_jwt_identity()

    # Optional filters
    transaction_type = request.args.get("type")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    conn = get_db_connection()

    # Get all accounts belonging to logged-in user
    user_accounts = conn.execute(
        """
        SELECT id
        FROM accounts
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchall()

    if not user_accounts:
        conn.close()

        return jsonify({
            "message": "No accounts found"
        }), 404

    account_ids = [account["id"] for account in user_accounts]

    # Create placeholders for SQL IN clause
    placeholders = ",".join(["?"] * len(account_ids))

    query = f"""
        SELECT
            t.id,
            t.amount,
            t.type,
            t.timestamp,
            t.from_account,
            t.to_account,
            fa.account_number AS from_account_number,
            ta.account_number AS to_account_number
        FROM transactions t
        LEFT JOIN accounts fa
            ON t.from_account = fa.id
        LEFT JOIN accounts ta
            ON t.to_account = ta.id
        WHERE (
            t.from_account IN ({placeholders})
            OR
            t.to_account IN ({placeholders})
        )
    """

    params = account_ids + account_ids

    # Filter by transaction type
    if transaction_type:
        if transaction_type not in [
            "deposit",
            "withdraw",
            "transfer"
        ]:
            conn.close()

            return jsonify({
                "error": "Invalid transaction type"
            }), 400

        query += " AND t.type = ?"
        params.append(transaction_type)

    # Filter by start date
    if start_date:
        query += " AND DATE(t.timestamp) >= DATE(?)"
        params.append(start_date)

    # Filter by end date
    if end_date:
        query += " AND DATE(t.timestamp) <= DATE(?)"
        params.append(end_date)

    query += " ORDER BY t.timestamp DESC"

    transactions = conn.execute(
        query,
        params
    ).fetchall()

    conn.close()

    transaction_list = []

    for transaction in transactions:

        transaction_list.append({
            "id": transaction["id"],
            "type": transaction["type"],
            "amount": transaction["amount"],
            "from_account": transaction["from_account_number"],
            "to_account": transaction["to_account_number"],
            "timestamp": transaction["timestamp"]
        })

    return jsonify({
        "transactions": transaction_list
    }), 200
# -------------------------------------------------
# GET TRANSACTIONS BY ACCOUNT
# -------------------------------------------------

@app.route("/transactions/<int:account_id>", methods=["GET"])
@jwt_required()
def get_account_transactions(account_id):

    user_id = get_jwt_identity()

    conn = get_db_connection()

    # Check account ownership
    account = conn.execute(
        """
        SELECT id, account_number, user_id
        FROM accounts
        WHERE id = ?
        """,
        (account_id,)
    ).fetchone()

    if not account:
        conn.close()

        return jsonify({
            "error": "Account not found"
        }), 404

    if str(account["user_id"]) != str(user_id):
        conn.close()

        return jsonify({
            "error": "You can view transactions only for your own account"
        }), 403

    transactions = conn.execute(
        """
        SELECT
            t.id,
            t.amount,
            t.type,
            t.timestamp,
            fa.account_number AS from_account_number,
            ta.account_number AS to_account_number
        FROM transactions t
        LEFT JOIN accounts fa
            ON t.from_account = fa.id
        LEFT JOIN accounts ta
            ON t.to_account = ta.id
        WHERE
            t.from_account = ?
            OR
            t.to_account = ?
        ORDER BY t.timestamp DESC
        """,
        (account_id, account_id)
    ).fetchall()

    conn.close()

    transaction_list = []

    for transaction in transactions:

        transaction_list.append({
            "id": transaction["id"],
            "type": transaction["type"],
            "amount": transaction["amount"],
            "from_account": transaction["from_account_number"],
            "to_account": transaction["to_account_number"],
            "timestamp": transaction["timestamp"]
        })

    return jsonify({
        "account_number": account["account_number"],
        "transactions": transaction_list
    }), 200
# -------------------------------------------------
# CREATE ADMIN
# -------------------------------------------------

@app.route("/admin/create", methods=["POST"])
def create_admin():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body is required"
        }), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({
            "error": "Name, email and password are required"
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "Password must be at least 6 characters"
        }), 400

    conn = get_db_connection()

    existing_user = conn.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing_user:
        conn.close()

        return jsonify({
            "error": "Email already registered"
        }), 409

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    conn.execute(
        """
        INSERT INTO users (name, email, password, role)
        VALUES (?, ?, ?, ?)
        """,
        (
            name,
            email,
            hashed_password.decode("utf-8"),
            "admin"
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Admin created successfully"
    }), 201
# -------------------------------------------------
# ADMIN - VIEW ALL USERS
# -------------------------------------------------

@app.route("/admin/users", methods=["GET"])
@jwt_required()
def admin_users():

    user_id = get_jwt_identity()

    conn = get_db_connection()

    admin = conn.execute(
        """
        SELECT role
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not admin or admin["role"] != "admin":
        conn.close()

        return jsonify({
            "error": "Admin access required"
        }), 403

    users = conn.execute(
        """
        SELECT id, name, email, role
        FROM users
        ORDER BY id
        """
    ).fetchall()

    conn.close()

    user_list = []

    for user in users:
        user_list.append({
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        })

    return jsonify({
        "users": user_list
    }), 200
# -------------------------------------------------
# ADMIN - VIEW ALL ACCOUNTS
# -------------------------------------------------

@app.route("/admin/accounts", methods=["GET"])
@jwt_required()
def admin_accounts():

    user_id = get_jwt_identity()

    conn = get_db_connection()

    admin = conn.execute(
        """
        SELECT role
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not admin or admin["role"] != "admin":
        conn.close()

        return jsonify({
            "error": "Admin access required"
        }), 403

    accounts = conn.execute(
        """
        SELECT
            accounts.id,
            accounts.account_number,
            users.name AS account_holder,
            users.email,
            accounts.account_type,
            accounts.balance,
            accounts.status
        FROM accounts
        JOIN users
            ON accounts.user_id = users.id
        ORDER BY accounts.id
        """
    ).fetchall()

    conn.close()

    account_list = []

    for account in accounts:
        account_list.append({
            "id": account["id"],
            "account_number": account["account_number"],
            "account_holder": account["account_holder"],
            "email": account["email"],
            "account_type": account["account_type"],
            "balance": account["balance"],
            "status": account["status"]
        })

    return jsonify({
        "accounts": account_list
    }), 200
# -------------------------------------------------
# ADMIN - VIEW ALL TRANSACTIONS
# -------------------------------------------------

@app.route("/admin/transactions", methods=["GET"])
@jwt_required()
def admin_transactions():

    user_id = get_jwt_identity()

    conn = get_db_connection()

    admin = conn.execute(
        """
        SELECT role
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not admin or admin["role"] != "admin":
        conn.close()

        return jsonify({
            "error": "Admin access required"
        }), 403

    transactions = conn.execute(
        """
        SELECT
            t.id,
            t.amount,
            t.type,
            t.timestamp,
            fa.account_number AS from_account,
            ta.account_number AS to_account
        FROM transactions t
        LEFT JOIN accounts fa
            ON t.from_account = fa.id
        LEFT JOIN accounts ta
            ON t.to_account = ta.id
        ORDER BY t.timestamp DESC
        """
    ).fetchall()

    conn.close()

    transaction_list = []

    for transaction in transactions:
        transaction_list.append({
            "id": transaction["id"],
            "type": transaction["type"],
            "amount": transaction["amount"],
            "from_account": transaction["from_account"],
            "to_account": transaction["to_account"],
            "timestamp": transaction["timestamp"]
        })

    return jsonify({
        "transactions": transaction_list
    }), 200
# -------------------------------------------------
# RUN APPLICATION
# -------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)