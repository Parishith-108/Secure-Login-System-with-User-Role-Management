// Password strength check
document.getElementById('registerForm').addEventListener('submit', function(e) {
    const password = document.getElementById('password').value;
    if(password.length < 8) {
        alert('Password must be at least 8 characters');
        e.preventDefault();
    }
});

// Email format validation
document.getElementById('loginForm').addEventListener('submit', function(e) {
    const email = document.getElementById('email').value;
    if(!/^\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$/.test(email)) {
        alert('Invalid email format');
        e.preventDefault();
    }
});