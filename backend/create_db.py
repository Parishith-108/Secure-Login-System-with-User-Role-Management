from app import db, app

# This will create the database
with app.app_context():
    db.create_all()
    print("Database created successfully!")