import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, validators
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get the base directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Create Flask app with explicit template and static folders
app = Flask(__name__,
            template_folder=os.path.join(basedir, 'templates'),
            static_folder=os.path.join(basedir, 'static'))

# App configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY', '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Rate limiting setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"],
    storage_uri="memory://"
)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(min=4, max=20)
    ])
    email = StringField('Email', [
        validators.DataRequired(),
        validators.Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8),
        validators.Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
            message='Password must contain uppercase, lowercase, number, and special character'
        )
    ])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])

class LoginForm(FlaskForm):
    email = StringField('Email', [
        validators.DataRequired(),
        validators.Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', [
        validators.DataRequired()
    ])

# Create admin user if not exists
def create_admin_user():
    with app.app_context():
        admin_email = "admin@example.com"
        admin_exists = User.query.filter_by(email=admin_email).first()
        
        if not admin_exists:
            hashed_password = bcrypt.generate_password_hash("AdminPass123!").decode('utf-8')
            admin_user = User(
                username="admin",
                email=admin_email,
                password=hashed_password,
                role="admin"
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Created admin user: admin@example.com / AdminPass123!")

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", exempt_when=lambda: request.method == "GET")
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Account lockout check
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            remaining = user.locked_until - datetime.utcnow()
            flash(f'Account locked! Try again in {remaining.seconds//60} minutes', 'danger')
            return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        # Verify reCAPTCHA
        if not verify_recaptcha():
            flash('reCAPTCHA verification failed. Please try again.', 'danger')
            return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # Reset failed attempts
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            # Set session variables
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['username'] = user.username
            
            if user.role == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('dashboard'))
        else:
            # Increment failed attempts
            if user:
                user.failed_attempts += 1
                # Lock account after 3 failed attempts
                if user.failed_attempts >= 3:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Account locked for 15 minutes due to multiple failed attempts!', 'danger')
                db.session.commit()
            
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Verify reCAPTCHA
        if not verify_recaptcha():
            flash('reCAPTCHA verification failed. Please try again.', 'danger')
            return render_template('register.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        # Check if email exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'danger')
            return render_template('register.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        # Check if username exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken', 'danger')
            return render_template('register.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])
        
        # Create new user
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! You can now log in', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}', 'danger')
    
    return render_template('register.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    if session['user_role'] != 'admin':
        flash('Admin access required!', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin.html', users=users, datetime=datetime.utcnow)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Helper Functions
def verify_recaptcha():
    # In a real application, verify reCAPTCHA with Google's API
    # For demo purposes, we'll skip actual verification
    return True  # Replace with actual verification

def create_tables():
    with app.app_context():
        db.create_all()
        print("Database tables created successfully")
        create_admin_user()

# Debugging function to print folder information
def print_folder_info():
    print(f"Current working directory: {os.getcwd()}")
    print(f"Base directory: {basedir}")
    print(f"Template folder: {app.template_folder}")
    print(f"Static folder: {app.static_folder}")
    
    try:
        template_files = os.listdir(app.template_folder)
        print(f"Files in template folder: {template_files}")
    except FileNotFoundError:
        print("Template folder not found!")
    
    try:
        static_files = os.listdir(app.static_folder)
        print(f"Files in static folder: {static_files}")
        
        css_files = os.listdir(os.path.join(app.static_folder, 'css'))
        print(f"CSS files: {css_files}")
        
        js_files = os.listdir(os.path.join(app.static_folder, 'js'))
        print(f"JS files: {js_files}")
    except FileNotFoundError:
        print("Static folder not found!")

# Application Entry Point
if __name__ == '__main__':
    print("=== Starting Application ===")
    print_folder_info()
    
    print("\nCreating database tables...")
    create_tables()
    
    print("\nStarting Flask server...")
    app.run(debug=True)