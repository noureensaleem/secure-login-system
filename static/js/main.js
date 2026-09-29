// SecureAuth Client-Side Security & UI Interactions
document.addEventListener('DOMContentLoaded', () => {
    
    // 1. Password Visibility Toggle
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;
            
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerHTML = '🔒';
                btn.setAttribute('title', 'Hide password');
            } else {
                input.type = 'password';
                btn.innerHTML = '👁️';
                btn.setAttribute('title', 'Show password');
            }
        });
    });

    // 2. Dynamic Password Strength Meter (Registration)
    const regPassword = document.getElementById('reg-password');
    const strengthFill = document.getElementById('strength-fill');
    const strengthText = document.getElementById('strength-text');
    
    const reqLength = document.getElementById('req-length');
    const reqUpper = document.getElementById('req-upper');
    const reqLower = document.getElementById('req-lower');
    const reqNumber = document.getElementById('req-number');
    const reqSpecial = document.getElementById('req-special');

    if (regPassword && strengthFill) {
        regPassword.addEventListener('input', () => {
            const val = regPassword.value;
            let score = 0;
            
            const hasLength = val.length >= 8;
            const hasUpper = /[A-Z]/.test(val);
            const hasLower = /[a-z]/.test(val);
            const hasNumber = /[0-9]/.test(val);
            const hasSpecial = /[!@#$%^&*(),.?":{}|<>\-_=+\[\];/~]/.test(val);

            // Update checklist icons & colors
            updateReq(reqLength, hasLength);
            updateReq(reqUpper, hasUpper);
            updateReq(reqLower, hasLower);
            updateReq(reqNumber, hasNumber);
            updateReq(reqSpecial, hasSpecial);

            if (hasLength) score++;
            if (hasUpper) score++;
            if (hasLower) score++;
            if (hasNumber) score++;
            if (hasSpecial) score++;

            // Visual bar updates
            if (val.length === 0) {
                strengthFill.style.width = '0%';
                strengthFill.style.backgroundColor = 'transparent';
                strengthText.textContent = 'Password Strength';
                strengthText.style.color = 'var(--text-secondary)';
            } else if (score <= 2) {
                strengthFill.style.width = '25%';
                strengthFill.style.backgroundColor = 'var(--danger)';
                strengthText.textContent = 'Weak';
                strengthText.style.color = 'var(--danger)';
            } else if (score === 3 || score === 4) {
                strengthFill.style.width = '65%';
                strengthFill.style.backgroundColor = 'var(--warning)';
                strengthText.textContent = 'Moderate';
                strengthText.style.color = 'var(--warning)';
            } else if (score === 5) {
                strengthFill.style.width = '100%';
                strengthFill.style.backgroundColor = 'var(--success)';
                strengthText.textContent = 'Strong & Secure';
                strengthText.style.color = 'var(--success)';
            }
        });
    }

    function updateReq(el, isValid) {
        if (!el) return;
        if (isValid) {
            el.classList.add('valid');
            el.classList.remove('invalid');
            const icon = el.querySelector('.req-icon');
            if (icon) icon.textContent = '✓';
        } else {
            el.classList.remove('valid');
            el.classList.add('invalid');
            const icon = el.querySelector('.req-icon');
            if (icon) icon.textContent = '○';
        }
    }

    // 3. Password Confirmation Match Validation
    const confirmPassword = document.getElementById('reg-confirm-password');
    const matchError = document.getElementById('match-error');

    if (regPassword && confirmPassword && matchError) {
        const checkMatch = () => {
            if (confirmPassword.value && regPassword.value !== confirmPassword.value) {
                matchError.style.display = 'block';
            } else {
                matchError.style.display = 'none';
            }
        };
        regPassword.addEventListener('input', checkMatch);
        confirmPassword.addEventListener('input', checkMatch);
    }

    // 4. Auto-Copy Secret Key for 2FA
    const copyBtn = document.getElementById('copy-secret-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const rawSecret = copyBtn.getAttribute('data-secret');
            navigator.clipboard.writeText(rawSecret).then(() => {
                copyBtn.textContent = 'Copied!';
                setTimeout(() => {
                    copyBtn.textContent = 'Copy Key';
                }, 2000);
            });
        });
    }

    // 5. 6-Digit OTP Box Auto-Focus & Digit Formatting
    const otpInput = document.getElementById('otp_code');
    if (otpInput) {
        otpInput.focus();
        otpInput.addEventListener('input', (e) => {
            // Keep only digits and max 6
            e.target.value = e.target.value.replace(/[^0-9]/g, '').slice(0, 6);
        });
    }
});
