# 🏦 Banking System REST API

Secure Banking System REST API built with Flask, SQLite, JWT authentication and bcrypt.

The API provides user authentication, bank account management, deposits, withdrawals, money transfers, transaction history and admin management.

---

## 🚀 Technologies Used

- Python
- Flask
- SQLite
- Flask-JWT-Extended
- bcrypt
- REST API
- Postman

---

## ✨ Features

### 🔐 Authentication

- User registration
- User login
- JWT-based authentication
- Secure password hashing using bcrypt
- Protected API endpoints

### 🏦 Account Management

- Create Savings account
- Create Current account
- View own accounts
- View account details
- Automatic unique account number generation

### 💰 Banking Operations

- Deposit money
- Withdraw money
- Transfer money between accounts
- Balance validation
- Insufficient balance protection
- Active/blocked account validation

### 📋 Transaction Management

- View transaction history
- View transactions for a specific account
- Filter transactions by type
- Filter transactions by date

### 👨‍💼 Admin

- Create admin
- View all users
- View all accounts
- View all transactions
- Role-based authorization

---

# 📁 Project Structure

```text
Banking_System_API/
│
├── venv/
│
├── app.py
├── database.py
├── banking.db
├── requirements.txt
└── README.md
