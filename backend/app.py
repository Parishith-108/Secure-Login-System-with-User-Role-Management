import os
from dotenv import load_dotenv # Import the load_dotenv function
load_dotenv()

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta, datetime
import os
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re  # For password validation

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite+pysqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'fallback-secret')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['RECAPTCHA_ENABLED'] = True
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', 'your-site-key')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', 'your-secret-key')
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
app.config['LOCKOUT_THRESHOLD'] = 5  # 5 failed attempts
app.config['LOCKOUT_TIME'] = 300  # 5 minutes in seconds

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# FIXED LIMITER INITIALIZATION
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# User Model with lockout fields
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

# Create database if it doesn't exist
def initialize_database():
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()
            print("Database created!")
    else:
        print("Database already exists")

initialize_database()

# ===== SECURITY MIDDLEWARE =====
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def validate_password(password):
    """Enforce strong password policy"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, ""

def check_account_lock(user):
    """Check if account is locked"""
    if user.locked_until and user.locked_until > datetime.utcnow():
        time_left = (user.locked_until - datetime.utcnow()).seconds
        return True, time_left
    elif user.failed_attempts >= app.config['LOCKOUT_THRESHOLD']:
        # Reset if lock time expired but failed attempts weren't reset
        user.failed_attempts = 0
        db.session.commit()
    return False, 0

# =============== ROUTES ===============

@app.route('/')
def home():
    return "Backend is running! Endpoints: /register, /login, /protected, /admin/users"

# Registration endpoint with CAPTCHA and password validation
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data received'}), 400
    
    # CAPTCHA verification (frontend will send token)
    if app.config['RECAPTCHA_ENABLED']:
        captcha_token = data.get('captcha_token')
        if not captcha_token:
            return jsonify({'error': 'CAPTCHA verification required'}), 400
        
        # In production, verify with Google
        # For demo, we'll just check if token exists
        if not captcha_token:
            return jsonify({'error': 'CAPTCHA verification required'}), 400
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    
    if not all([username, email, password, role]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Validate password strength
    is_valid, pwd_msg = validate_password(password)
    if not is_valid:
        return jsonify({'error': pwd_msg}), 400
    
    # Check for existing user
    existing_email = User.query.filter_by(email=email).first()
    existing_username = User.query.filter_by(username=username).first()
    
    if existing_email:
        return jsonify({'error': 'Email already registered'}), 400
    if existing_username:
        return jsonify({'error': 'Username already taken'}), 400
    
    try:
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role
        )
        
        # Add to database
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'message': 'Registration successful!',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'role': new_user.role
            }
        }), 201
    
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

# Login endpoint with account lockout
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data received'}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    if not all([email, password]):
        return jsonify({'error': 'Missing email or password'}), 400
    
    # Find user by email
    user = User.query.filter_by(email=email).first()
    
    # Check account lock
    if user:
        is_locked, time_left = check_account_lock(user)
        if is_locked:
            return jsonify({
                'error': f'Account locked. Try again in {time_left} seconds'
            }), 403
    
    # Verify credentials
    if not user or not bcrypt.check_password_hash(user.password, password):
        if user:
            # Increment failed attempts
            user.failed_attempts += 1
            
            # Lock account if threshold reached
            if user.failed_attempts >= app.config['LOCKOUT_THRESHOLD']:
                user.locked_until = datetime.utcnow() + timedelta(
                    seconds=app.config['LOCKOUT_TIME']
                )
            
            db.session.commit()
        
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Reset failed attempts on successful login
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()
    
    # Create access token
    access_token = create_access_token(identity={
        'id': user.id,
        'email': user.email,
        'role': user.role
    })
    
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role
        }
    }), 200

# Protected route - requires valid JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    try:
        # Get identity from JWT token
        current_user = get_jwt_identity()
        
        # Get full user details from database
        user = User.query.get(current_user['id'])
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'message': 'Access granted',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get all users (admin only)
@app.route('/admin/users', methods=['GET'])
@jwt_required()
@admin_required
def get_all_users():
    users = User.query.all()
    users_list = []
    for user in users:
        users_list.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        })
    return jsonify(users_list), 200

# Update user role (admin only)
@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_user_role(user_id):
    data = request.get_json()
    if not data or 'role' not in data:
        return jsonify({'error': 'Role is required'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if data['role'] not in ['admin', 'user']:
        return jsonify({'error': 'Invalid role'}), 400
    
    user.role = data['role']
    db.session.commit()
    
    return jsonify({
        'message': 'User role updated',
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role
        }
    }), 200

# Delete user (admin only)
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Cannot delete self
    current_user_id = get_jwt_identity()['id']
    if user.id == current_user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)