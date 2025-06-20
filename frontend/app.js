document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const loginForm = document.getElementById('loginForm');
    
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
});

async function handleRegister(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const response = await fetch('/register', {
        method: 'POST',
        body: formData
    });
    
    const result = await response.json();
    document.getElementById('message').textContent = result.success || result.error;
    if (response.ok) {
        setTimeout(() => window.location.href = '/', 1500);
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const response = await fetch('/login', {
        method: 'POST',
        body: formData
    });
    
    const result = await response.json();
    if (response.ok) {
        window.location.href = '/dashboard';
    } else {
        document.getElementById('message').textContent = result.error;
    }
}

async function logout() {
    const response = await fetch('/logout', {
        method: 'POST',
        credentials: 'include'
    });
    
    if (response.ok) {
        window.location.href = '/';
    }
}

async function updateRole(userId) {
    const newRole = document.getElementById(`role_${userId}`).value;
    const response = await fetch('/update-role', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            user_id: userId,
            role: newRole
        }),
        credentials: 'include'
    });
    
    const result = await response.json();
    alert(result.success || result.error);
}