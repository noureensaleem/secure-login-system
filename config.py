import os
from datetime import timedelta

class Config:
    """Application configuration and security settings."""
    # Secret key for cryptographically signing sessions and CSRF tokens
    SECRET_KEY = os.environ.get('SECRET_KEY', 'sec-login-sys-key-7f9a2b5e-4c8d-4a1e-8e3d-5b2c1f0a9e8d')
    
    # Base directory and database file location
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'secure_login.db'))
    
    # Session Security Parameters
    # Prevents JavaScript access to cookies (mitigates session hijacking via XSS)
    SESSION_COOKIE_HTTPONLY = True
    # Restricts cookie sharing on cross-site requests (mitigates CSRF)
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Set to True when served over HTTPS in production
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    # Session expiration (inactivity timeout)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Rate Limiting & Account Lockout Defense
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    
    # Password Hashing Work Factor (bcrypt rounds)
    BCRYPT_ROUNDS = 12
    
    # 2FA Settings
    TOTP_ISSUER_NAME = 'SecureAuth App'
