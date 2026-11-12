import sqlite3
import datetime
import os

# Define robust absolute database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "threat_logs.db")


def get_db_connection():
    """Create a connection to the SQLite database with row factory enabled."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize threat logs and user tables with robust schema validation and auto-migration."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create threat_logs table if it doesn't exist
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

    # Check if 'users' table exists and has the correct 'password' column
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    table_exists = cursor.fetchone()

    if table_exists:
        cursor.execute("PRAGMA table_info(users);")
        columns = [col[1] for col in cursor.fetchall()]
        # If 'password' column is missing, drop and recreate cleanly
        if "password" not in columns:
            cursor.execute("DROP TABLE users;")
            table_exists = None

    # Create users table with correct schema if it doesn't exist or was dropped
    if not table_exists:
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL DEFAULT 'user',
                password TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

    conn.commit()
    conn.close()
    print(f"[+] Database initialized successfully: {DB_NAME}")


def log_threat(
    src_ip, dst_ip, protocol, threat_type,
    severity, confidence_score, raw_features=""
):
    """Record a detected threat in the database."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db_connection()
        conn.execute('''
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
        conn.close()
    except Exception as e:
        print(f"[-] Database insertion error: {e}")


def fetch_recent_threats(limit=50):
    """Fetch the most recent threat logs."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM threat_logs ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return rows
    finally:
        conn.close()


def register_user(username: str, email: str, password: str, role: str = "user") -> bool:
    """Register a new user into the database. Automatically assigns admin role to the official alert email."""
    clean_email = email.strip().lower()
    if clean_email == "warisansecurityalerts@gmail.com":
        role = "admin"

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, email, role, password) VALUES (?, ?, ?, ?)",
            (username.strip(), clean_email, role, password)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_all_registered_users() -> list[str]:
    """Fetch a list of all registered user emails for alert broadcasts."""
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT email FROM users WHERE email IS NOT NULL AND email != ''").fetchall()
        return [row["email"] for row in rows]
    finally:
        conn.close()


# Automatically initialize and validate database on module import
init_db()