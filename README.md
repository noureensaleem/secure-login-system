# 🛡️ Secure Login System Web Application

A production-ready, security-hardened authentication web application built using **Python 3.12**, **Flask**, and **SQLite3**. 

This project fulfills all criteria of the **Secure Login System** specification, implementing enterprise-grade cryptographic standards, parameterized query defenses against SQL injection, session lifecycle management, and optional **Two-Factor Authentication (2FA / TOTP)** compatible with Google Authenticator and Authy.

---

## 📋 Key Features & Requirements Matrix

| Requirement | Implementation Detail | Status |
| :--- | :--- | :---: |
| **Password Hashing** | Industry-standard crypt with cryptographically random salt and 12 work factor rounds. Constant-time hash verification against timing attacks. | ✅ **Implemented** |
| **Input Validation** | Server-side & client-side validation for usernames (alphanumeric whitelist), email (RFC regex), and 5-point password complexity enforcement. | ✅ **Implemented** |
| **SQL Injection Defense** | 100% Parameterized queries using prepared statements (? placeholders). Immune to SQLi payloads. | ✅ **Implemented** |
| **Session Management** | HttpOnly and SameSite=Lax cookies, session regeneration on login (prevents session fixation), inactivity expiration, and secure logout. | ✅ **Implemented** |
| **Two-Factor Auth (2FA)** | Time-based One-Time Passwords (TOTP - RFC 6238) with live QR Code scanning and manual secret key fallback. Two-stage login authentication. | ✅ **Implemented** |
| **Brute-Force Protection** | Automatic account lockout after 5 consecutive failed login attempts (15-minute window) + IP-based sliding window rate limiter. | ✅ **Implemented** |
| **Security Audit Trail** | Detailed logging of authentication events (Registration, Login Success/Fail, 2FA Activation, Logout) with timestamps and IP addresses. | ✅ **Implemented** |
| **Security Headers** | Enforces Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and X-XSS-Protection. | ✅ **Implemented** |

---

## 🏗️ Architecture & Project Structure

`
secure_login_system/
├── app.py                  # Main Flask application, routes, session lifecycle, security middleware
├── config.py               # Security parameters, session cookie flags, lockout thresholds
├── database.py             # SQLite schema, parameterized query abstraction, audit logging
├── security.py             # bcrypt hashing, input validation, TOTP 2FA, QR code generation, CSRF
├── requirements.txt        # Application dependencies
├── test_auth.py            # Comprehensive automated test suite (13 test cases)
├── static/
│   ├── css/
│   │   └── style.css       # Clean, modern, responsive authentication UI stylesheet
│   └── js/
│       └── main.js         # Real-time password strength meter, visibility toggles, OTP handling
└── templates/
    ├── base.html           # Base layout with navbar, alerts, and security badges
    ├── login.html          # Login view with rate-limit and brute-force notices
    ├── register.html       # Registration view with dynamic password strength meter
    ├── verify_2fa.html     # Second-factor 6-digit OTP challenge view
    ├── setup_2fa.html      # 2FA enrollment page displaying QR code and backup secrets
    └── dashboard.html      # Protected user dashboard, session stats, and audit log table
`

---

## 🔐 Security Deep Dive

### 1. Password Security (bcrypt)
- Passwords are never stored in plaintext.
- We utilize crypt.gensalt(rounds=12) which dynamically incorporates high-entropy salts to render precomputed rainbow table attacks impossible.
- Passwords are verified using crypt.checkpw(), ensuring a constant-time comparison that eliminates timing side-channel attacks.

### 2. SQL Injection Immunity
- Direct string interpolation (e.g. "SELECT * FROM users WHERE username = '{username}'") is completely avoided.
- Every query utilizes SQLite parameterized execution with tuples:
  `python
  cursor.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))
  `
- Any SQL meta-characters (', ", --, ;, UNION) provided in inputs are treated strictly as literal data strings.

### 3. Session Management & Session Fixation Protection
- When an unauthenticated user establishes a session and subsequently logs in, session.clear() is called immediately to regenerate session identifiers, preventing session fixation attacks.
- Cookies are configured with:
  - HttpOnly = True: Restricts JavaScript document.cookie access (mitigating XSS session theft).
  - SameSite = 'Lax': Disallows third-party cross-site request cookie forwarding.
  - PERMANENT_SESSION_LIFETIME = 30 minutes: Enforces automatic inactivity expiration.
- The /logout route invalidates the session and logs the audit event.

### 4. Two-Factor Authentication (2FA / TOTP)
- Implements the RFC 6238 Time-based One-Time Password standard using pyotp.
- Generates a base32 secret and an otpauth:// URI.
- Generates a QR code image as an inline Base64 data URI (data:image/png;base64,...), eliminating disk writes or third-party image tracking.
- Authenticator apps supported: Google Authenticator, Microsoft Authenticator, Authy, 1Password.

### 5. Brute-Force & Credential Stuffing Defense
- Accounts are locked for 15 minutes after 5 failed password attempts.
- An in-memory sliding-window IP rate limiter restricts excessive requests per client.
- Login failure messages use generic phrasing (*"Invalid credentials"*) to prevent username enumeration.

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.10+ (Python 3.12 recommended)
- pip

### Step 1: Install Dependencies
Open your terminal or PowerShell and navigate to the project directory:
`powershell
cd C:\Users\noure\.gemini\antigravity\scratch\secure_login_system
py -3 -m pip install -r requirements.txt
`

### Step 2: Run the Automated Test Suite
Verify that all 13 security and functional tests pass:
`powershell
py -3 -m unittest test_auth.py -v
`

Expected output:
`	ext
test_csrf_protection_rejection ... ok
test_full_registration_and_login_flow ... ok
test_protected_route_requires_login ... ok
test_security_headers_present ... ok
test_two_factor_auth_workflow ... ok
test_account_lockout_mechanism ... ok
test_sql_injection_payloads_in_queries ... ok
test_user_creation_and_retrieval ... ok
test_bcrypt_hashing_and_salting ... ok
test_email_validation ... ok
test_password_complexity ... ok
test_totp_2fa_lifecycle ... ok
test_username_validation ... ok

----------------------------------------------------------------------
Ran 13 tests in ~6s

OK
`

### Step 3: Start the Web Application
`powershell
py -3 app.py
`
The server will start at:
👉 **http://127.0.0.1:5000**

---

## 🧪 Testing & Demonstration Scenarios

### Scenario A: User Registration & Strong Password Policy
1. Open http://127.0.0.1:5000/register.
2. Try typing a weak password like secret. Observe the real-time checklist and progress bar indicating missing criteria.
3. Enter a compliant password: Secur3P@ssw0rd!.
4. Submit the registration form. The password is now salted and hashed with bcrypt.

### Scenario B: SQL Injection Defense Test
1. In the login page, enter ' OR '1'='1 in the username/email field.
2. Enter any password and submit.
3. Notice that the application handles the input safely as literal characters and returns an *"Invalid credentials"* message without crashing or granting unauthorized access.

### Scenario C: Two-Factor Authentication Setup
1. Log in to the dashboard.
2. Click **"Enable 2FA Now"**.
3. Scan the QR code using Google Authenticator on your mobile device (or copy the manual key).
4. Enter the 6-digit code shown in the app to activate 2FA.
5. Log out, then log in again:
   - Step 1: Enter username and password.
   - Step 2: Enter the 6-digit OTP code to complete login.

### Scenario D: Account Lockout Defense
1. Attempt to log in with an incorrect password 5 consecutive times for the same account.
2. On the 5th attempt, the account will be locked out for 15 minutes.
3. Subsequent login attempts are blocked, even if the correct password is entered during the lockout window.

### Scenario E: Security Audit Trail
1. Log in to the user dashboard.
2. Scroll to the **Account Security Audit Trail** table.
3. Review recorded security events including REGISTER_SUCCESS, LOGIN_SUCCESS, 2FA_ENABLED, and timestamps.

---

## 📄 License & Credits
Developed for the **Secure Login System** Task (Team Emogi / emogi.in).
