# Import Flask library
from flask import Flask

# Create Flask application instance
app = Flask(__name__)

# Define a route for the home page
@app.route('/')
def home():
    return "Backend is working!"

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
    from flask import Flask
from flask_sqlalchemy import SQLAlchemy  # Add this import

app = Flask(__name__)

# Configure database location
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Define User model (database table)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return "Backend is working! Database is ready."

if __name__ == '__main__':
    app.run(debug=True)