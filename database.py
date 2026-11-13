import sqlite3
import datetime
import os

DB_NAME = 'threat_logs.db'


def get_db_connection():
    """Create a connection to the SQLite cybersecurity database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Enables dictionary-like access to rows
    return conn


def init_db():
    """Initialize threat logs and user tables with robust schema validation."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                raw_features TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL DEFAULT 'user',
                password TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        print(f"[+] SQLite Database initialized successfully: {DB_NAME}")
    except Exception as e:
        print(f"[-] SQLite Database initialization error: {e}")
    finally:
        cursor.close()
        conn.close()


def log_threat(
    src_ip, dst_ip, protocol, threat_type,
    severity, confidence_score, raw_features=""
):
    """Record a detected threat in the SQLite database."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO threat_logs (
                timestamp, src_ip, dst_ip, protocol,
                threat_type, severity, confidence_score, raw_features
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp, src_ip, dst_ip, protocol,
            threat_type, severity, float(confidence_score),
            str(raw_features)
        ))
        conn.commit()
    except Exception as e:
        print(f"[-] SQLite Database insertion error: {e}")
    finally:
        cursor.close()
        conn.close()


def fetch_recent_threats(limit=50):
    """Fetch the most recent threat logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM threat_logs ORDER BY id DESC LIMIT ?",
            (int(limit),)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        cursor.close()
        conn.close()


def register_user(username: str, email: str, password: str, role: str = "user") -> bool:
    """Register a new user into the database. Returns True if successful, False if duplicate."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, role, password) VALUES (?, ?, ?, ?)",
            (username.strip(), email.strip().lower(), role, password)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        cursor.close()
        conn.close()


def get_all_registered_users():
    """Fetch a list of all registered user emails for alert broadcasts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT email FROM users WHERE email IS NOT NULL AND email != ''")
        rows = cursor.fetchall()
        return [row['email'].strip() for row in rows if row['email'] and "@" in str(row['email'])]
    finally:
        cursor.close()
        conn.close()


def update_user_password(email: str, new_password: str) -> bool:
    """Update a user's password based on their email address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (new_password, email.strip().lower())
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"[-] Password update error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


# Automatically initialize database schema on module import
init_db()