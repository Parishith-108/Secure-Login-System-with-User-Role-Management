// Password strength calculator
function calculatePasswordStrength(password) {
    let strength = 0;
    
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[@$!%*?&]/.test(password)) strength++;
    
    return Math.min(strength, 4);
}

// Initialize password strength meter
document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('register-password');
    const strengthMeter = document.getElementById('password-strength-meter');
    
    if (passwordInput && strengthMeter) {
        passwordInput.addEventListener('input', () => {
            const password = passwordInput.value;
            const strength = calculatePasswordStrength(password);
            
            // Update strength meter
            strengthMeter.className = 'password-strength-meter';
            strengthMeter.classList.add(`strength-${strength}`);
        });
    }
    
    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash');
    flashMessages.forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            setTimeout(() => flash.remove(), 500);
        }, 5000);
    });
    
    // Session timeout warning
    let timeoutWarning;
    const sessionTimeout = 30 * 60 * 1000; // 30 minutes
    
    function resetSessionTimer() {
        clearTimeout(timeoutWarning);
        timeoutWarning = setTimeout(showTimeoutWarning, sessionTimeout - 60000);
    }
    
    function showTimeoutWarning() {
        if (confirm('Your session is about to expire. Would you like to stay logged in?')) {
            resetSessionTimer();
        } else {
            window.location.href = '/logout';
        }
    }
    
    // Initialize session timer if logged in
    if (document.querySelector('.dashboard-container') || document.querySelector('.admin-container')) {
        document.addEventListener('mousemove', resetSessionTimer);
        document.addEventListener('keypress', resetSessionTimer);
        resetSessionTimer();
    }
});