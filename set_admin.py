import sqlite3

conn = sqlite3.connect("threat_logs.db")
cursor = conn.cursor()

# Promote your active local account to admin
cursor.execute(
    "UPDATE users SET role = 'admin' WHERE email = ?",
    ("ikmalmeyzul@gmail.com",),
)

# Optional: If you also want to insert the alert Gmail account as an admin locally
cursor.execute(
    """
    INSERT OR IGNORE INTO users (username, email, role, password) 
    VALUES ('WarisanAlerts', 'warisansecurityalerts@gmail.com', 'admin', 'dummy_pass')
"""
)
cursor.execute(
    "UPDATE users SET role = 'admin' WHERE email = ?",
    ("warisansecurityalerts@gmail.com",),
)

conn.commit()

print("Updated users in database:")
for row in cursor.execute("SELECT id, username, email, role FROM users"):
    print(row)

conn.close()