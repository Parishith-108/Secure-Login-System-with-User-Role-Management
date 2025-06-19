from app import db, app
from app import User  # Import the User model

with app.app_context():
    # Create a test user
    test_user = User(
        username="testuser",
        email="test@example.com",
        password="testpassword",
        role="admin"
    )
    
    # Add to database
    db.session.add(test_user)
    db.session.commit()
    
    print("Test user added successfully!")