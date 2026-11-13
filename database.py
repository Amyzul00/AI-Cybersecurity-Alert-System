import pymysql
import datetime
import os

# Database configuration parameters for MySQL
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = ''
DB_NAME = 'cybersecurity_db'


def get_db_connection():
    """Create a connection to the MySQL cybersecurity database."""
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    return conn


def init_db():
    """Initialize threat logs and user tables with robust schema validation."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Create threat_logs table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp VARCHAR(50) NOT NULL,
                src_ip VARCHAR(50) NOT NULL,
                dst_ip VARCHAR(50) NOT NULL,
                protocol VARCHAR(20) NOT NULL,
                threat_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                confidence_score FLOAT NOT NULL,
                raw_features TEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')

        # Create users table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL UNIQUE,
                email VARCHAR(150) NOT NULL UNIQUE,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                password VARCHAR(255) NOT NULL DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        ''')
        conn.commit()
        print(f"[+] MySQL Database initialized successfully: {DB_NAME}")
    except Exception as e:
        print(f"[-] MySQL Database initialization error: {e}")
    finally:
        cursor.close()
        conn.close()


def log_threat(
    src_ip, dst_ip, protocol, threat_type,
    severity, confidence_score, raw_features=""
):
    """Record a detected threat in the MySQL database."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO threat_logs (
                timestamp, src_ip, dst_ip, protocol,
                threat_type, severity, confidence_score, raw_features
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            timestamp, src_ip, dst_ip, protocol,
            threat_type, severity, float(confidence_score),
            str(raw_features)
        ))
        conn.commit()
    except Exception as e:
        print(f"[-] MySQL Database insertion error: {e}")
    finally:
        cursor.close()
        conn.close()


def fetch_recent_threats(limit=50):
    """Fetch the most recent threat logs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM threat_logs ORDER BY id DESC LIMIT %s",
            (int(limit),)
        )
        rows = cursor.fetchall()
        return rows
    finally:
        cursor.close()
        conn.close()


def register_user(username: str, email: str, password: str, role: str = "user") -> bool:
    """Register a new user into the database. Returns True if successful, False if duplicate."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, role, password) VALUES (%s, %s, %s, %s)",
            (username.strip(), email.strip().lower(), role, password)
        )
        conn.commit()
        return True
    except pymysql.err.IntegrityError:
        return False
    finally:
        cursor.close()
        conn.close()


def get_all_registered_users():
    """Fetch a list of all registered user emails for alert broadcasts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT email FROM users")
        rows = cursor.fetchall()
        # Extract emails into a list
        return [row['email'] for row in rows if row['email']]
    finally:
        cursor.close()
        conn.close()


# Automatically initialize database schema on module import
init_db()