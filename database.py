import datetime
import json
import os
import sqlite3
import time
from pathlib import Path
import pandas as pd

DB_NAME = "threat_logs.db"
USERS_BACKUP_FILE = Path("users_backup.json")


def get_db_connection():
    """Create a connection to the SQLite cybersecurity database."""
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # Enables dictionary-like access to rows
    return conn


def _sync_users_backup(cursor):
    """Persist current users table rows to a JSON backup file."""
    try:
        cursor.execute(
            "SELECT username, email, role, password, COALESCE(login_count, 0) AS login_count, last_login, created_at FROM users ORDER BY id ASC"
        )
        rows = [dict(r) for r in cursor.fetchall()]
        USERS_BACKUP_FILE.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[-] Failed to sync users backup JSON: {e}")


def _restore_users_from_backup(cursor):
    """Restore users from JSON backup into SQLite if missing (e.g., after container reset)."""
    if not USERS_BACKUP_FILE.exists():
        return
    try:
        saved_users = json.loads(USERS_BACKUP_FILE.read_text(encoding="utf-8"))
        if not isinstance(saved_users, list):
            return
        for u in saved_users:
            uname = (u.get("username") or "").strip()
            uemail = (u.get("email") or "").strip().lower()
            urole = (u.get("role") or "user").strip().lower()
            upass = u.get("password") or ""
            lcount = int(u.get("login_count") or 0)
            llogin = u.get("last_login")
            if not uname or not uemail:
                continue
            cursor.execute("SELECT id FROM users WHERE LOWER(TRIM(email)) = ?", (uemail,))
            if not cursor.fetchone():
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO users (username, email, role, password, login_count, last_login)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (uname, uemail, urole, upass, lcount, llogin),
                )
    except Exception as e:
        print(f"[-] Failed to restore users backup JSON: {e}")


def init_db():
    """Initialize threat logs, users, and latency benchmarking tables with schema validation and default seeding."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
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
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL DEFAULT 'user',
                password TEXT NOT NULL DEFAULT '',
                login_count INTEGER DEFAULT 0,
                last_login TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS latency_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_log_id INTEGER,
                recorded_at TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                collection_ms REAL NOT NULL,
                extraction_ms REAL NOT NULL,
                buffering_ms REAL NOT NULL,
                inference_ms REAL NOT NULL,
                db_logging_ms REAL NOT NULL,
                dashboard_update_ms REAL NOT NULL,
                email_delivery_ms REAL,
                e2e_dashboard_ms REAL NOT NULL,
                e2e_email_ms REAL,
                FOREIGN KEY (threat_log_id) REFERENCES threat_logs(id)
            )
        """)

        # --- AUTO-MIGRATE MISSING COLUMNS FOR EXISTING DEPLOYMENTS ---
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if "login_count" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0")
        if "last_login" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login TEXT")

        # --- SEED DEFAULT USERS (PREVENTS ACCOUNT LOSS ON RESTART) ---
        default_users = [
            ("Admin", "warisansecurityalerts@gmail.com", "admin", "Admin123"),
            ("Ameyzul", "ikmalmeyzul@gmail.com", "user", "Ameyzul123"),
            ("zul", "sendermalwaree@gmail.com", "user", "zul123"),
        ]

        for uname, uemail, urole, upass in default_users:
            clean_email = uemail.strip().lower()
            cursor.execute("SELECT id FROM users WHERE LOWER(TRIM(email)) = ?", (clean_email,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT OR IGNORE INTO users (username, email, role, password, login_count) VALUES (?, ?, ?, ?, 0)",
                    (uname, clean_email, urole, upass),
                )

        # --- RESTORE ANY PREVIOUSLY REGISTERED USERS FROM JSON SNAPSHOT ---
        _restore_users_from_backup(cursor)
        conn.commit()
        _sync_users_backup(cursor)
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
    """
    Record a detected threat in the SQLite database.
    Returns (threat_log_id, db_logging_ms) for end-to-end latency instrumentation.
    """
    t_start = time.perf_counter_ns()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()
    row_id = None
    try:
        cursor.execute("""
            INSERT INTO threat_logs (
                timestamp, src_ip, dst_ip, protocol,
                threat_type, severity, confidence_score, raw_features
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, src_ip, dst_ip, protocol,
            threat_type, severity, float(confidence_score),
            str(raw_features)
        ))
        conn.commit()
        row_id = cursor.lastrowid
    except Exception as e:
        print(f"[-] SQLite Database insertion error: {e}")
    finally:
        cursor.close()
        conn.close()

    db_logging_ms = (time.perf_counter_ns() - t_start) / 1_000_000.0
    return row_id, round(db_logging_ms, 4)


def log_pipeline_latency(
    threat_log_id: int,
    threat_type: str,
    t0_capture_ns: int,
    t1_collect_ns: int,
    t2_extract_ns: int,
    t3_buffer_ns: int,
    t4_infer_ns: int,
    t5_db_ns: int,
    t6_dashboard_ns: int,
    t7_email_ns: int = None
):
    """
    Compute stage-by-stage latencies (in ms) from monotonic nanosecond timestamps
    and persist them to the latency_metrics table.
    """
    ns_to_ms = lambda start, end: round((end - start) / 1_000_000.0, 4)

    collection_ms = ns_to_ms(t0_capture_ns, t1_collect_ns)
    extraction_ms = ns_to_ms(t1_collect_ns, t2_extract_ns)
    buffering_ms = ns_to_ms(t2_extract_ns, t3_buffer_ns)
    inference_ms = ns_to_ms(t3_buffer_ns, t4_infer_ns)
    db_logging_ms = ns_to_ms(t4_infer_ns, t5_db_ns)
    dashboard_update_ms = ns_to_ms(t5_db_ns, t6_dashboard_ns)
    e2e_dashboard_ms = ns_to_ms(t0_capture_ns, t6_dashboard_ns)

    email_delivery_ms = ns_to_ms(t5_db_ns, t7_email_ns) if t7_email_ns else None
    e2e_email_ms = ns_to_ms(t0_capture_ns, t7_email_ns) if t7_email_ns else None

    recorded_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO latency_metrics (
                threat_log_id, recorded_at, threat_type,
                collection_ms, extraction_ms, buffering_ms,
                inference_ms, db_logging_ms, dashboard_update_ms,
                email_delivery_ms, e2e_dashboard_ms, e2e_email_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            threat_log_id, recorded_at, threat_type,
            collection_ms, extraction_ms, buffering_ms,
            inference_ms, db_logging_ms, dashboard_update_ms,
            email_delivery_ms, e2e_dashboard_ms, e2e_email_ms
        ))
        conn.commit()
    except Exception as e:
        print(f"[-] Latency metric logging error: {e}")
    finally:
        cursor.close()
        conn.close()


def get_latency_summary() -> pd.DataFrame:
    """
    Aggregate Mean, Median (p50), and 95th Percentile (p95) latency across all
    recorded threat events for Table 8 dissertation reporting.
    """
    conn = get_db_connection()
    try:
        df = pd.read_sql_query("SELECT * FROM latency_metrics", conn)
        if df.empty:
            return pd.DataFrame()

        stages = [
            ("1. Data Collection", "collection_ms"),
            ("2. Feature Extraction", "extraction_ms"),
            ("3. Window Buffering", "buffering_ms"),
            ("4. Deep LSTM Inference", "inference_ms"),
            ("5. Database Logging", "db_logging_ms"),
            ("6. Dashboard Update", "dashboard_update_ms"),
            ("7. SMTP Email Delivery", "email_delivery_ms"),
            ("Total End-to-End (Dashboard)", "e2e_dashboard_ms"),
            ("Total End-to-End (Email)", "e2e_email_ms"),
        ]

        summary_rows = []
        for label, col in stages:
            series = df[col].dropna()
            if not series.empty:
                summary_rows.append({
                    "Pipeline Stage": label,
                    "Samples (N)": len(series),
                    "Mean (ms)": round(series.mean(), 2),
                    "Median p50 (ms)": round(series.median(), 2),
                    "p95 (ms)": round(series.quantile(0.95), 2),
                })
        return pd.DataFrame(summary_rows)
    finally:
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
    clean_user = (username or "").strip()
    clean_email = (email or "").strip().lower()
    clean_role = (role or "user").strip().lower()
    if not clean_user or not clean_email or not password:
        return False

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id FROM users WHERE LOWER(TRIM(username)) = LOWER(?) OR LOWER(TRIM(email)) = LOWER(?)",
            (clean_user, clean_email),
        )
        if cursor.fetchone():
            return False

        cursor.execute(
            "INSERT INTO users (username, email, role, password, login_count) VALUES (?, ?, ?, ?, 0)",
            (clean_user, clean_email, clean_role, password)
        )
        conn.commit()
        _sync_users_backup(cursor)
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
        cursor.execute("SELECT email FROM users WHERE email IS NOT NULL AND TRIM(email) != ''")
        rows = cursor.fetchall()
        return [row["email"].strip().lower() for row in rows if row["email"] and "@" in str(row["email"])]
    finally:
        cursor.close()
        conn.close()


def increment_user_login(email: str):
    """Increment user login count and record current timestamp upon successful authentication."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ident = (email or "").strip()
        cursor.execute(
            """
            UPDATE users
            SET login_count = COALESCE(login_count, 0) + 1,
                last_login = ?
            WHERE LOWER(TRIM(email)) = LOWER(?) OR LOWER(TRIM(username)) = LOWER(?)
            """,
            (current_time, ident, ident)
        )
        conn.commit()
        _sync_users_backup(cursor)
        conn.commit()
    except Exception as e:
        print(f"[-] Failed to update login count: {e}")
    finally:
        cursor.close()
        conn.close()


def get_all_user_accounts():
    """Fetch a DataFrame of all registered user accounts, roles, login counts, and timestamps for admin audits."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, email, role, COALESCE(login_count, 0), last_login FROM users ORDER BY id ASC")
        rows = cursor.fetchall()
        return pd.DataFrame(rows, columns=["Username", "Email", "Role", "Login Count", "Last Login"])
    except Exception as e:
        print(f"[-] Failed to fetch user accounts: {e}")
        return pd.DataFrame(columns=["Username", "Email", "Role", "Login Count", "Last Login"])
    finally:
        cursor.close()
        conn.close()


def delete_user_account(identifier: str) -> tuple[bool, str]:
    """Delete a registered user account by email or username and sync users_backup.json."""
    clean_id = (identifier or "").strip()
    if not clean_id:
        return False, "Please select or enter a valid account."

    if clean_id.lower() == "warisansecurityalerts@gmail.com":
        return False, "The primary admin account (warisansecurityalerts@gmail.com) cannot be deleted."

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE LOWER(TRIM(email)) = LOWER(?) OR LOWER(TRIM(username)) = LOWER(?)",
            (clean_id, clean_id),
        )
        row = cursor.fetchone()
        if not row:
            return False, "Account not found in database."

        if (row["email"] or "").strip().lower() == "warisansecurityalerts@gmail.com":
            return False, "The primary admin account (warisansecurityalerts@gmail.com) cannot be deleted."

        cursor.execute("DELETE FROM users WHERE id = ?", (row["id"],))
        conn.commit()
        _sync_users_backup(cursor)
        conn.commit()
        return True, f"Deleted account '{row['username']}' ({row['email']})."
    except Exception as e:
        return False, f"Failed to delete account: {e}"
    finally:
        cursor.close()
        conn.close()


def update_user_password(email: str, new_password: str) -> bool:
    """Update a user's password based on their email address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        clean_email = (email or "").strip().lower()
        cursor.execute(
            "UPDATE users SET password = ? WHERE LOWER(TRIM(email)) = ?",
            (new_password, clean_email)
        )
        updated = cursor.rowcount > 0
        if updated:
            conn.commit()
            _sync_users_backup(cursor)
            conn.commit()
        return updated
    except Exception as e:
        print(f"[-] Password update error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


# Automatically initialize database schema on module import
init_db()