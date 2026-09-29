import re
import secrets
import hmac
import base64
from io import BytesIO
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import bcrypt
import pyotp
import qrcode
from config import Config

# --- Password Hashing & Verification (bcrypt) ---

def hash_password(plain_password: str) -> str:
    """
    Hashes a plaintext password using bcrypt with a cryptographically secure salt.
    Truncates/guards at 128 characters to prevent algorithm DoS.
    """
    if not isinstance(plain_password, str):
        raise ValueError("Password must be a string")
    # bcrypt max input length is 72 bytes
    pw_bytes = plain_password[:128].encode('utf-8')
    salt = bcrypt.gensalt(rounds=Config.BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(pw_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a bcrypt hash in constant-time.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        pw_bytes = plain_password[:128].encode('utf-8')
        hash_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(pw_bytes, hash_bytes)
    except Exception:
        return False

# --- Input Validation & Sanitization ---

USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,30}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

def validate_username(username: str):
    """Validates username length and characters (alphanumeric and underscore only)."""
    if not username or not isinstance(username, str):
        return False, "Username is required."
    username = username.strip()
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not USERNAME_REGEX.match(username):
        return False, "Username can only contain letters, numbers, and underscores."
    return True, ""

def validate_email(email: str):
    """Validates email address format and length."""
    if not email or not isinstance(email, str):
        return False, "Email is required."
    email = email.strip()
    if len(email) > 254:
        return False, "Email is too long (maximum 254 characters)."
    if not EMAIL_REGEX.match(email):
        return False, "Invalid email format."
    return True, ""

def validate_password_complexity(password: str):
    """
    Enforces strong password policy:
    - Minimum 8 characters, maximum 128
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    errors = []
    if not password or not isinstance(password, str):
        return False, ["Password is required."]
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if len(password) > 128:
        errors.append("Password cannot exceed 128 characters.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least one number (0-9).")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\];/~]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*...).")
        
    return len(errors) == 0, errors

# --- Two-Factor Authentication (TOTP - RFC 6238) ---

def generate_2fa_secret() -> str:
    """Generates a secure random 32-character base32 secret for TOTP."""
    return pyotp.random_base32()

def get_2fa_uri(username: str, secret: str) -> str:
    """Creates standard otpauth:// URI for authenticator applications."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=Config.TOTP_ISSUER_NAME)

def generate_qr_code_base64(provisioning_uri: str) -> str:
    """Generates a QR code image as a Base64 data URI string for embedding directly in HTML."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=7,
        border=3,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    img_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_b64}"

def verify_2fa_code(secret: str, code: str) -> bool:
    """
    Verifies a 6-digit TOTP code against the secret key.
    Allows valid_window=1 (30s tolerance for clock drift).
    """
    if not secret or not code:
        return False
    code = code.strip().replace(' ', '')
    if not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

# --- CSRF Protection Helper ---

def generate_csrf_token() -> str:
    """Generates a secure hex token for CSRF protection."""
    return secrets.token_hex(32)

def constant_time_compare(val1: str, val2: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if not val1 or not val2:
        return False
    return hmac.compare_digest(str(val1), str(val2))

# --- IP-Based Rate Limiting for Login Protection ---

class IPRateLimiter:
    """In-memory sliding window rate limiter per IP address."""
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.ip_records = defaultdict(list)
    
    def is_allowed(self, ip_address: str) -> bool:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window_seconds)
        # Purge timestamps older than cutoff
        self.ip_records[ip_address] = [
            t for t in self.ip_records[ip_address] if t > cutoff
        ]
        if len(self.ip_records[ip_address]) >= self.max_requests:
            return False
        self.ip_records[ip_address].append(now)
        return True

ip_limiter = IPRateLimiter(max_requests=15, window_seconds=60)
