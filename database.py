import sqlite3
from datetime import datetime, timezone, timedelta
from config import Config

def get_db(db_path=None):
    """Establishes a connection to the SQLite database with Row factory."""
    path = db_path or Config.DATABASE_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=None):
    """Initializes the database schema with necessary tables and indexes."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                two_factor_secret TEXT DEFAULT NULL,
                two_factor_enabled INTEGER DEFAULT 0,
                failed_login_count INTEGER DEFAULT 0,
                locked_until TIMESTAMP DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login_at TIMESTAMP DEFAULT NULL
            )
        """)
        
        # Audit Logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        
        # Indexes for fast and safe lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id)")
        
        conn.commit()

# --- Parameterized Database Access Functions (SQL Injection Immunity) ---

def get_user_by_id(user_id, db_path=None):
    """Fetch user safely by ID using parameterized query."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()

def get_user_by_username(username, db_path=None):
    """Fetch user safely by username using parameterized query."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))
        return cursor.fetchone()

def get_user_by_email(email, db_path=None):
    """Fetch user safely by email using parameterized query."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,))
        return cursor.fetchone()

def get_user_by_identifier(identifier, db_path=None):
    """Fetch user safely by either username or email using parameterized query."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
            (identifier, identifier)
        )
        return cursor.fetchone()

def create_user(username, email, password_hash, db_path=None):
    """Insert a new user safely using parameterized query."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
        return cursor.lastrowid

def update_2fa_secret(user_id, secret, db_path=None):
    """Store temporary or verified 2FA secret for user."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET two_factor_secret = ? WHERE id = ?", (secret, user_id))
        conn.commit()

def enable_2fa(user_id, secret, db_path=None):
    """Enable 2FA and persist secret."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?",
            (secret, user_id)
        )
        conn.commit()

def disable_2fa(user_id, db_path=None):
    """Disable 2FA and clear secret."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0 WHERE id = ?",
            (user_id,)
        )
        conn.commit()

def record_login_success(user_id, db_path=None):
    """Reset failed attempts and record last login timestamp."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
            (now, user_id)
        )
        conn.commit()

def record_login_failure(user_id, db_path=None):
    """Increment failed attempts count and lock account if threshold exceeded."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT failed_login_count FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        
        failed_count = (row['failed_login_count'] or 0) + 1
        locked_until = None
        
        if failed_count >= Config.MAX_FAILED_LOGIN_ATTEMPTS:
            locked_until_dt = datetime.now(timezone.utc) + timedelta(minutes=Config.LOCKOUT_DURATION_MINUTES)
            locked_until = locked_until_dt.isoformat()
            
        cursor.execute(
            "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?",
            (failed_count, locked_until, user_id)
        )
        conn.commit()
        return {'failed_count': failed_count, 'locked_until': locked_until}

def is_account_locked(user_id, db_path=None):
    """Check if an account is currently locked out due to brute-force attempts."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT locked_until FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row or not row['locked_until']:
            return False, None
        
        locked_until_dt = datetime.fromisoformat(row['locked_until'])
        now = datetime.now(timezone.utc)
        if now < locked_until_dt:
            remaining_mins = int((locked_until_dt - now).total_seconds() // 60) + 1
            return True, remaining_mins
        else:
            # Lock has expired; reset
            cursor.execute("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = ?", (user_id,))
            conn.commit()
            return False, None

def log_audit(user_id, username, action, ip_address, user_agent, db_path=None):
    """Log security event in audit table."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (user_id, username, action, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)",
            (user_id, username, action, ip_address, user_agent)
        )
        conn.commit()

def get_audit_logs(user_id=None, limit=20, db_path=None):
    """Retrieve audit records safely with parameterization."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        if user_id:
            cursor.execute(
                "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                (user_id, limit)
            )
        else:
            cursor.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        return cursor.fetchall()
