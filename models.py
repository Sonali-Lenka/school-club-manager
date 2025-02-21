from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='student')  # student, moderator, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship with clubs (many-to-many)
    clubs_joined = db.relationship('Club', secondary='user_club',
                                 backref=db.backref('members', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_club_permission(self, club):
        return self.is_admin or self.role == 'moderator' or club.creator_id == self.id

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref='clubs_created', foreign_keys=[creator_id])
    status = db.Column(db.String(20), default='active')  # active, inactive, pending
    requires_approval = db.Column(db.Boolean, default=True)

# Association table for User-Club many-to-many relationship
user_club = db.Table('user_club',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('club_id', db.Integer, db.ForeignKey('club.id'), primary_key=True),
    db.Column('role', db.String(20), default='member')  # member, officer, leader
)