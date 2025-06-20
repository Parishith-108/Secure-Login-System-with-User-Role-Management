import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, set_access_cookies, unset_jwt_cookies
)
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY')

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        data = {
            'secret': app.config['RECAPTCHA_SECRET_KEY'],
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()
        
        if not result.get('success'):
            return jsonify({"error": "reCAPTCHA verification failed"}), 400
        
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 400
        
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({"success": "User created successfully"}), 201
    
    return render_template('registration.html', site_key=os.getenv('RECAPTCHA_SITE_KEY'))

@app.route('/login', methods=['POST'])
def login():
    recaptcha_response = request.form.get('g-recaptcha-response')
    data = {
        'secret': app.config['RECAPTCHA_SECRET_KEY'],
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    
    if not result.get('success'):
        return jsonify({"error": "reCAPTCHA verification failed"}), 400
    
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username, password=password).first()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    access_token = create_access_token(identity={
        'id': user.id,
        'username': user.username,
        'role': user.role
    })
    
    response = jsonify({"success": "Logged in successfully"})
    set_access_cookies(response, access_token)
    return response, 200

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"error": "Admin access required"}), 403
    
    users = User.query.all()
    return render_template('admin.html', users=users, current_user=current_user)

@app.route('/update-role', methods=['POST'])
@jwt_required()
def update_role():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({"error": "Admin access required"}), 403
    
    user_id = request.json.get('user_id')
    new_role = request.json.get('role')
    
    if not user_id or not new_role:
        return jsonify({"error": "Missing parameters"}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    user.role = new_role
    db.session.commit()
    return jsonify({"success": "Role updated successfully"}), 200

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({"success": "Logged out successfully"})
    unset_jwt_cookies(response)
    return response, 200

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)