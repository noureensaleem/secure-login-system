import unittest
import os
import re
import tempfile
import pyotp
from datetime import datetime, timezone, timedelta

# Set temporary database path for tests before importing modules
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix='.db')
os.close(temp_db_fd)
os.environ['DATABASE_PATH'] = temp_db_path
os.environ['SECRET_KEY'] = 'test-secret-key-super-secure-1234567890'

import database
import security
from app import app

class TestSecurityCore(unittest.TestCase):
    """Unit tests for cryptographic functions, validation, and 2FA."""

    def test_bcrypt_hashing_and_salting(self):
        password = "SecurePassword123!"
        hash1 = security.hash_password(password)
        hash2 = security.hash_password(password)

        # Hashes must start with bcrypt prefix ($)
        self.assertTrue(hash1.startswith('$'))
        self.assertTrue(hash2.startswith('$'))

        # Salt ensures identical passwords produce different hashes
        self.assertNotEqual(hash1, hash2)

        # Constant-time verification
        self.assertTrue(security.verify_password(password, hash1))
        self.assertTrue(security.verify_password(password, hash2))
        self.assertFalse(security.verify_password("WrongPassword123!", hash1))
        self.assertFalse(security.verify_password("", hash1))

    def test_username_validation(self):
        # Valid usernames
        self.assertTrue(security.validate_username("alex_123")[0])
        self.assertTrue(security.validate_username("admin_user")[0])

        # Invalid usernames
        self.assertFalse(security.validate_username("al")[0])  # too short (<3)
        self.assertFalse(security.validate_username("a" * 31)[0])  # too long (>30)
        self.assertFalse(security.validate_username("alex hunter")[0])  # spaces
        self.assertFalse(security.validate_username("alex<script>")[0])  # XSS chars
        self.assertFalse(security.validate_username("alex' OR '1'='1")[0])  # SQLi attempt
        self.assertFalse(security.validate_username("")[0])

    def test_email_validation(self):
        # Valid emails
        self.assertTrue(security.validate_email("user@example.com")[0])
        self.assertTrue(security.validate_email("user.name+tag@sub.domain.co")[0])

        # Invalid emails
        self.assertFalse(security.validate_email("plainaddress")[0])
        self.assertFalse(security.validate_email("@missingusername.com")[0])
        self.assertFalse(security.validate_email("user@.com")[0])
        self.assertFalse(security.validate_email("")[0])

    def test_password_complexity(self):
        # Meets all criteria: >=8 chars, uppercase, lowercase, number, special char
        valid, errs = security.validate_password_complexity("ComplexP@ss1")
        self.assertTrue(valid)
        self.assertEqual(len(errs), 0)

        # Missing uppercase
        self.assertFalse(security.validate_password_complexity("complexp@ss1")[0])
        # Missing lowercase
        self.assertFalse(security.validate_password_complexity("COMPLEXP@SS1")[0])
        # Missing digit
        self.assertFalse(security.validate_password_complexity("ComplexP@ssWord")[0])
        # Missing special character
        self.assertFalse(security.validate_password_complexity("ComplexPass123")[0])
        # Too short (<8 chars)
        self.assertFalse(security.validate_password_complexity("Cp1!")[0])

    def test_totp_2fa_lifecycle(self):
        # Secret generation
        secret = security.generate_2fa_secret()
        self.assertEqual(len(secret), 32)

        # URI and QR Code generation
        uri = security.get_2fa_uri("testuser", secret)
        self.assertTrue(uri.startswith('otpauth://totp/'))
        self.assertIn("testuser", uri)

        qr_b64 = security.generate_qr_code_base64(uri)
        self.assertTrue(qr_b64.startswith('data:image/png;base64,'))

        # OTP Code generation and verification
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        # Valid code should pass
        self.assertTrue(security.verify_2fa_code(secret, current_code))
        # Wrong code should fail
        self.assertFalse(security.verify_2fa_code(secret, "000000"))
        self.assertFalse(security.verify_2fa_code(secret, "abc123"))


class TestDatabaseAndSQLiImmunity(unittest.TestCase):
    """Tests database operations and verifies immunity to SQL Injection attacks."""

    @classmethod
    def setUpClass(cls):
        database.init_db(temp_db_path)

    def test_sql_injection_payloads_in_queries(self):
        """Verify that malicious SQL injection inputs are treated strictly as data."""
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' --",
            "' UNION SELECT 1, 'admin', 'hacked@hack.com', 'pwd', NULL, 0, 0, NULL, NULL, NULL --",
            "'; DROP TABLE users; --",
            '\" OR \"\"=\"',
        ]

        for payload in sqli_payloads:
            # Querying with malicious username should safely return None, not crash or return a user
            user = database.get_user_by_identifier(payload, temp_db_path)
            self.assertIsNone(user, f"SQL Injection payload bypassed query: {payload}")

    def test_user_creation_and_retrieval(self):
        username = "sqli_test_user"
        email = "sqli_test@example.com"
        pwd_hash = security.hash_password("StrongP@ssw0rd99")

        user_id = database.create_user(username, email, pwd_hash, temp_db_path)
        self.assertIsNotNone(user_id)

        # Fetch by identifier
        u_by_name = database.get_user_by_identifier(username, temp_db_path)
        self.assertIsNotNone(u_by_name)
        self.assertEqual(u_by_name['email'], email)

        u_by_email = database.get_user_by_identifier(email, temp_db_path)
        self.assertIsNotNone(u_by_email)
        self.assertEqual(u_by_email['username'], username)

    def test_account_lockout_mechanism(self):
        user_id = database.create_user("lockout_user", "lockout@example.com", security.hash_password("SecureP@ss1"), temp_db_path)

        # Initially not locked
        locked, _ = database.is_account_locked(user_id, temp_db_path)
        self.assertFalse(locked)

        # Simulate 4 failed attempts
        for _ in range(4):
            database.record_login_failure(user_id, temp_db_path)
        
        locked, _ = database.is_account_locked(user_id, temp_db_path)
        self.assertFalse(locked)

        # 5th failed attempt should trigger lockout
        database.record_login_failure(user_id, temp_db_path)
        locked, mins = database.is_account_locked(user_id, temp_db_path)
        self.assertTrue(locked)
        self.assertGreater(mins, 0)

        # Success clears lockout
        database.record_login_success(user_id, temp_db_path)
        locked, _ = database.is_account_locked(user_id, temp_db_path)
        self.assertFalse(locked)


class TestAppFlowAndSessionSecurity(unittest.TestCase):
    """End-to-end integration tests using Flask test client."""

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    def get_csrf_token(self):
        with self.client.session_transaction() as sess:
            if '_csrf_token' not in sess:
                sess['_csrf_token'] = 'test-csrf-token'
            return sess['_csrf_token']

    def test_protected_route_requires_login(self):
        response = self.client.get('/dashboard', follow_redirects=False)
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_security_headers_present(self):
        response = self.client.get('/login')
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(response.headers.get('X-XSS-Protection'), '1; mode=block')
        self.assertIn('Content-Security-Policy', response.headers)

    def test_full_registration_and_login_flow(self):
        csrf = self.get_csrf_token()

        # 1. Register new user
        reg_response = self.client.post('/register', data={
            'csrf_token': csrf,
            'username': 'integration_user',
            'email': 'integration@test.com',
            'password': 'SecureP@ssword2026',
            'confirm_password': 'SecureP@ssword2026'
        }, follow_redirects=True)
        self.assertEqual(reg_response.status_code, 200)
        self.assertIn(b'Account created successfully', reg_response.data)

        # 2. Login with wrong password
        bad_login = self.client.post('/login', data={
            'csrf_token': csrf,
            'identifier': 'integration_user',
            'password': 'WrongPassword123!'
        }, follow_redirects=True)
        self.assertIn(b'Invalid credentials', bad_login.data)

        # 3. Login with SQL injection payload
        sqli_login = self.client.post('/login', data={
            'csrf_token': csrf,
            'identifier': "' OR 1=1 --",
            'password': 'any'
        }, follow_redirects=True)
        self.assertIn(b'Invalid credentials', sqli_login.data)

        # 4. Login with correct password
        good_login = self.client.post('/login', data={
            'csrf_token': csrf,
            'identifier': 'integration_user',
            'password': 'SecureP@ssword2026'
        }, follow_redirects=True)
        self.assertEqual(good_login.status_code, 200)
        self.assertIn(b'Security Dashboard', good_login.data)
        self.assertIn(b'integration_user', good_login.data)

        # 5. Access dashboard
        dash_res = self.client.get('/dashboard')
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn(b'integration_user', dash_res.data)

        # 6. Logout
        logout_res = self.client.get('/logout', follow_redirects=True)
        self.assertIn(b'securely logged out', logout_res.data)

        # Dashboard should now be guarded
        dash_res_after = self.client.get('/dashboard', follow_redirects=False)
        self.assertEqual(dash_res_after.status_code, 302)

    def test_two_factor_auth_workflow(self):
        csrf = self.get_csrf_token()

        # Register user for 2FA
        self.client.post('/register', data={
            'csrf_token': csrf,
            'username': 'twofa_user',
            'email': 'twofa@test.com',
            'password': 'TwoFaPassword!2026',
            'confirm_password': 'TwoFaPassword!2026'
        })

        # Login
        self.client.post('/login', data={
            'csrf_token': csrf,
            'identifier': 'twofa_user',
            'password': 'TwoFaPassword!2026'
        })

        # Request 2FA Setup page (GET generates secret in session)
        setup_get = self.client.get('/setup-2fa')
        self.assertEqual(setup_get.status_code, 200)
        self.assertIn(b'Step 1: Scan QR Code', setup_get.data)

        # Retrieve secret stored in session
        with self.client.session_transaction() as sess:
            secret = sess['pending_2fa_secret']

        # Generate valid TOTP code
        valid_totp = pyotp.TOTP(secret).now()

        # Activate 2FA
        activate_res = self.client.post('/setup-2fa', data={
            'csrf_token': csrf,
            'otp_code': valid_totp
        }, follow_redirects=True)
        self.assertIn(b'Two-Factor Authentication is now enabled', activate_res.data)

        # Log out
        self.client.get('/logout')

        # Now log in again: should prompt for 2FA challenge!
        login_res = self.client.post('/login', data={
            'csrf_token': csrf,
            'identifier': 'twofa_user',
            'password': 'TwoFaPassword!2026'
        }, follow_redirects=False)
        # Should redirect to /verify-2fa
        self.assertEqual(login_res.status_code, 302)
        self.assertIn('/verify-2fa', login_res.headers['Location'])

        # Try invalid 2FA code
        bad_verify = self.client.post('/verify-2fa', data={
            'csrf_token': csrf,
            'otp_code': '000000'
        }, follow_redirects=True)
        self.assertIn(b'Invalid or expired 6-digit code', bad_verify.data)

        # Provide valid 2FA code
        good_totp = pyotp.TOTP(secret).now()
        good_verify = self.client.post('/verify-2fa', data={
            'csrf_token': csrf,
            'otp_code': good_totp
        }, follow_redirects=True)
        self.assertEqual(good_verify.status_code, 200)
        self.assertIn(b'Security Dashboard', good_verify.data)

    def test_csrf_protection_rejection(self):
        """Verify that POST requests with missing or invalid CSRF tokens are rejected."""
        app.config['CSRF_PROTECT_TESTING'] = True
        try:
            # POST with no CSRF token
            res = self.client.post('/login', data={
                'identifier': 'anyone',
                'password': 'Password123!'
            }, follow_redirects=True)
            self.assertIn(b'Invalid or expired security token', res.data)
        finally:
            app.config['CSRF_PROTECT_TESTING'] = False

    @classmethod
    def tearDownClass(cls):
        try:
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)
        except Exception:
            pass

if __name__ == '__main__':
    unittest.main()
