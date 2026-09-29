import os
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, 
    session, flash, abort, make_response
)
from config import Config
import database
import security

app = Flask(__name__)
app.config.from_object(Config)

# Ensure database tables exist on boot
database.init_db()

# --- Helper: Authentication Guard ---

def login_required(f):
    """Decorator to protect views requiring an authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

# --- CSRF Protection Context & Hooks ---

@app.context_processor
def inject_csrf_token():
    """Provides csrf_token() helper for templates."""
    def get_csrf_token():
        if '_csrf_token' not in session:
            session['_csrf_token'] = security.generate_csrf_token()
        return session['_csrf_token']
    return dict(csrf_token=get_csrf_token)

@app.before_request
def csrf_protect():
    """Verifies CSRF token on all state-changing POST requests."""
    if app.config.get('TESTING') and not app.config.get('CSRF_PROTECT_TESTING', False):
        return
    if request.method == 'POST':
        # Retrieve CSRF token from form or header
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        session_token = session.get('_csrf_token')
        
        if not token or not session_token or not security.constant_time_compare(token, session_token):
            flash('Invalid or expired security token. Please try again.', 'danger')
            # If from login or register, reload the page safely
            if request.endpoint in ('login', 'register', 'verify_2fa', 'setup_2fa', 'disable_2fa'):
                return redirect(request.url)
            abort(403)

@app.after_request
def set_security_headers(response):
    """Applies industry-standard security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response

# --- Client IP Utility ---

def get_client_ip():
    """Accurately extracts client IP address, respecting reverse proxies if configured."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

# --- Routes ---

@app.route('/')
def index():
    """Redirects authenticated users to dashboard, guests to login."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration with strict validation and password hashing."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # 1. Input Validation
        valid_u, u_err = security.validate_username(username)
        if not valid_u:
            flash(u_err, 'danger')
            return render_template('register.html', username=username, email=email)
            
        valid_e, e_err = security.validate_email(email)
        if not valid_e:
            flash(e_err, 'danger')
            return render_template('register.html', username=username, email=email)
            
        valid_p, p_errs = security.validate_password_complexity(password)
        if not valid_p:
            for err in p_errs:
                flash(err, 'danger')
            return render_template('register.html', username=username, email=email)
            
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', username=username, email=email)
            
        # 2. Check Uniqueness (Parameterized queries protect against SQLi)
        if database.get_user_by_username(username):
            flash('Username is already registered. Please choose another.', 'danger')
            return render_template('register.html', username=username, email=email)
            
        if database.get_user_by_email(email):
            flash('Email address is already registered. Please log in.', 'danger')
            return render_template('register.html', username=username, email=email)
            
        # 3. Hash Password using bcrypt with secure salt
        pwd_hash = security.hash_password(password)
        
        # 4. Create User Record
        user_id = database.create_user(username, email, pwd_hash)
        
        # 5. Audit Log
        ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')[:200]
        database.log_audit(user_id, username, 'REGISTER_SUCCESS', ip, user_agent)
        
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user authentication, rate-limiting, and 2FA redirection."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')
        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')[:200]
        
        # Rate-limiting check by IP
        if not security.ip_limiter.is_allowed(client_ip):
            flash('Too many login attempts from this network. Please wait a minute before trying again.', 'danger')
            return render_template('login.html', identifier=identifier)
            
        if not identifier or not password:
            flash('Please enter both your username/email and password.', 'danger')
            return render_template('login.html', identifier=identifier)
            
        # Parameterized query lookup (Safe from SQL Injection)
        user = database.get_user_by_identifier(identifier)
        
        if user:
            # Check Account Lockout
            is_locked, remaining_mins = database.is_account_locked(user['id'])
            if is_locked:
                database.log_audit(user['id'], user['username'], 'LOGIN_BLOCKED_LOCKED_ACCOUNT', client_ip, user_agent)
                flash(f'Account is temporarily locked due to excessive failed attempts. Please try again in {remaining_mins} minute(s).', 'danger')
                return render_template('login.html', identifier=identifier)
                
            # Verify Password with bcrypt constant-time check
            if security.verify_password(password, user['password_hash']):
                # Successful credentials!
                database.record_login_success(user['id'])
                
                # Check if Two-Factor Authentication is enabled
                if user['two_factor_enabled']:
                    # Initiate 2FA verification step
                    session.clear()
                    session['2fa_pending'] = True
                    session['2fa_user_id'] = user['id']
                    session['_csrf_token'] = security.generate_csrf_token()
                    database.log_audit(user['id'], user['username'], 'LOGIN_CREDENTIALS_VERIFIED_AWAITING_2FA', client_ip, user_agent)
                    return redirect(url_for('verify_2fa'))
                    
                # Full Login: Regenerate session to prevent session fixation
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['_csrf_token'] = security.generate_csrf_token()
                session.permanent = True
                
                database.log_audit(user['id'], user['username'], 'LOGIN_SUCCESS', client_ip, user_agent)
                flash(f'Welcome back, {user["username"]}!', 'success')
                
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                # Password mismatch
                fail_data = database.record_login_failure(user['id'])
                database.log_audit(user['id'], user['username'], 'LOGIN_FAILED_BAD_PASSWORD', client_ip, user_agent)
                
                if fail_data and fail_data['locked_until']:
                    flash(f'Account has been locked for {Config.LOCKOUT_DURATION_MINUTES} minutes due to {Config.MAX_FAILED_LOGIN_ATTEMPTS} consecutive failed attempts.', 'danger')
                else:
                    attempts_left = Config.MAX_FAILED_LOGIN_ATTEMPTS - (fail_data['failed_count'] if fail_data else 0)
                    flash(f'Invalid credentials. {max(0, attempts_left)} attempts remaining before account lockout.', 'danger')
                return render_template('login.html', identifier=identifier)
        else:
            # User not found: do not disclose whether user exists
            database.log_audit(None, identifier[:50], 'LOGIN_FAILED_UNKNOWN_USER', client_ip, user_agent)
            flash('Invalid credentials. Please verify your details.', 'danger')
            return render_template('login.html', identifier=identifier)
            
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Handles second-factor OTP challenge for users with 2FA enabled."""
    if not session.get('2fa_pending') or not session.get('2fa_user_id'):
        flash('No pending two-factor authentication challenge.', 'warning')
        return redirect(url_for('login'))
        
    user_id = session['2fa_user_id']
    user = database.get_user_by_id(user_id)
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')[:200]
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        
        if security.verify_2fa_code(user['two_factor_secret'], otp_code):
            # 2FA passed: establish full session
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['_csrf_token'] = security.generate_csrf_token()
            session.permanent = True
            
            database.log_audit(user['id'], user['username'], '2FA_LOGIN_SUCCESS', client_ip, user_agent)
            flash('Two-Factor Authentication verified successfully. Welcome!', 'success')
            return redirect(url_for('dashboard'))
        else:
            database.log_audit(user['id'], user['username'], '2FA_VERIFICATION_FAILED', client_ip, user_agent)
            flash('Invalid or expired 6-digit code. Please check your authenticator app and try again.', 'danger')
            return render_template('verify_2fa.html', username=user['username'])
            
    return render_template('verify_2fa.html', username=user['username'])

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Enrolls user in TOTP Two-Factor Authentication with QR Code."""
    user = database.get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')[:200]
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        secret = session.get('pending_2fa_secret')
        
        if not secret:
            flash('Enrollment session expired. Please start over.', 'warning')
            return redirect(url_for('setup_2fa'))
            
        if security.verify_2fa_code(secret, otp_code):
            database.enable_2fa(user['id'], secret)
            session.pop('pending_2fa_secret', None)
            database.log_audit(user['id'], user['username'], '2FA_ENABLED', client_ip, user_agent)
            flash('Two-Factor Authentication is now enabled for your account!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 6-digit code. Please verify the code in your authenticator app and try again.', 'danger')
            uri = security.get_2fa_uri(user['username'], secret)
            qr_base64 = security.generate_qr_code_base64(uri)
            return render_template('setup_2fa.html', qr_base64=qr_base64, secret=secret, formatted_secret=' '.join([secret[i:i+4] for i in range(0, len(secret), 4)]))
            
    # GET: generate new pending secret and QR code
    secret = security.generate_2fa_secret()
    session['pending_2fa_secret'] = secret
    uri = security.get_2fa_uri(user['username'], secret)
    qr_base64 = security.generate_qr_code_base64(uri)
    formatted_secret = ' '.join([secret[i:i+4] for i in range(0, len(secret), 4)])
    
    return render_template(
        'setup_2fa.html',
        qr_base64=qr_base64,
        secret=secret,
        formatted_secret=formatted_secret,
        already_enabled=bool(user['two_factor_enabled'])
    )

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disables 2FA after password confirmation."""
    user = database.get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
        
    password = request.form.get('password', '')
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')[:200]
    
    if not security.verify_password(password, user['password_hash']):
        flash('Incorrect password. Could not disable Two-Factor Authentication.', 'danger')
        return redirect(url_for('dashboard'))
        
    database.disable_2fa(user['id'])
    database.log_audit(user['id'], user['username'], '2FA_DISABLED', client_ip, user_agent)
    flash('Two-Factor Authentication has been successfully disabled.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Protected dashboard displaying user account details, 2FA status, and audit logs."""
    user = database.get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    audit_logs = database.get_audit_logs(user_id=user['id'], limit=10)
    return render_template('dashboard.html', user=user, audit_logs=audit_logs)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Securely clears user session and logs audit trail."""
    user_id = session.get('user_id')
    username = session.get('username', 'Anonymous')
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')[:200]
    
    if user_id:
        database.log_audit(user_id, username, 'LOGOUT', client_ip, user_agent)
        
    session.clear()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('login'))

# --- Error Handlers ---

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('base.html', error_title="403 - Access Forbidden", error_message="Your request was blocked due to invalid security credentials or CSRF verification failure."), 403

@app.errorhandler(404)
def not_found_error(e):
    return render_template('base.html', error_title="404 - Page Not Found", error_message="The page you are looking for does not exist."), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('base.html', error_title="500 - Server Error", error_message="An unexpected security exception or server error occurred."), 500

if __name__ == '__main__':
    # Run development server
    app.run(host='127.0.0.1', port=5000, debug=True)
