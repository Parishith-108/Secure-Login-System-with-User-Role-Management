from app import app, db

with app.app_context():
    db.create_all()
    # Create admin user if not exists
    if not db.session.query(db.exists().where(User.username == 'admin')).scalar():
        admin_user = User(username='admin', password='adminpass', role='admin')
        db.session.add(admin_user)
        db.session.commit()
    print("Database created successfully!")