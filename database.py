import sqlite3
import datetime
import os

DB_NAME = "threat_logs.db"

def init_db():
    """Initialize the SQLite database schema."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create threat_logs table
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
    
    conn.commit()
    conn.close()
    print(f"[+] Database initialized successfully: {DB_NAME}")

def log_threat(src_ip, dst_ip, protocol, threat_type, severity, confidence_score, raw_features=""):
    """
    Thread-safe helper to record detected threats into the database.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_logs (timestamp, src_ip, dst_ip, protocol, threat_type, severity, confidence_score, raw_features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, protocol, threat_type, severity, float(confidence_score), str(raw_features)))
        
        conn.commit()
        conn.close()
        print(f"[ALERT LOGGED] {timestamp} | {src_ip} -> {dst_ip} | {threat_type} ({severity}) | Score: {confidence_score:.2f}")
    except Exception as e:
        print(f"[-] Database insertion error: {e}")

def fetch_recent_threats(limit=50):
    """Fetch the most recent N threat logs."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    init_db()