import sqlite3

DATABASE = "banking.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db_connection()

    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer'
                CHECK(role IN ('customer', 'admin'))
        )
    """)

    # Accounts table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT NOT NULL UNIQUE,
            account_type TEXT NOT NULL
                CHECK(account_type IN ('Savings', 'Current')),
            balance REAL NOT NULL DEFAULT 0
                CHECK(balance >= 0),
            status TEXT NOT NULL DEFAULT 'active'
                CHECK(status IN ('active', 'blocked')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Transactions table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account INTEGER,
            to_account INTEGER,
            amount REAL NOT NULL CHECK(amount > 0),
            type TEXT NOT NULL
                CHECK(type IN ('deposit', 'withdraw', 'transfer')),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (from_account) REFERENCES accounts(id),
            FOREIGN KEY (to_account) REFERENCES accounts(id)
        )
    """)

    conn.commit()
    conn.close()

    print("Database initialized successfully!")


if __name__ == "__main__":
    init_db()