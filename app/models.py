# Import necessary modules and classes

# app/models.py
from app import db
from flask_login import UserMixin
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta, timezone


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    mobile_number = db.Column(db.String(15), nullable=False)
    id_number = db.Column(db.String(20), unique=True, nullable=False)
    education_level = db.Column(db.String(50), nullable=False)
    occupation = db.Column(db.String(255), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    membership = db.Column(db.Boolean, default=False, nullable=False)
    verification_status = db.Column(db.Boolean, default=False, nullable=False)
    profile_picture = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc) + timedelta(hours=3), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', backref='users')
    loans = db.relationship('Loan', backref='guarantor', lazy=True)
    contributions = db.relationship('Contribution', backref='user', lazy=True)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Verification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    verified = db.Column(db.Boolean, default=False, nullable=False)
    user = db.relationship('User', backref=db.backref('verifications', lazy=True))
    role = db.relationship('Role', backref=db.backref('verified_members', lazy=True))

class System(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_types = db.Column(db.String(255), nullable=True)
    loan_durations = db.Column(db.Integer, nullable=True)
    contribution_deadline_day = db.Column(db.Integer, default=15, nullable=False)
    fine_amount = db.Column(db.Float, default=100, nullable=False)
    loans = db.relationship('Loan', back_populates='system')

class Contribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contributor = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.Boolean, nullable=False)
    fine_amount = db.Column(db.Float, default=0, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(255), nullable=False)
    guarantor_name = db.Column(db.String(255), nullable=False)
    loan_type = db.Column(db.String(255), nullable=False)
    principal = db.Column(db.Float, nullable=False)
    loan_duration = db.Column(db.Integer, nullable=False)
    interest_rate = db.Column(db.Float, default=10, nullable=False)
    service_cost = db.Column(db.Float, default=0, nullable=False)
    fines = db.Column(db.Float, default=0, nullable=True)
    partial_issuance = db.Column(db.Float, default=0, nullable=True)
    partial_payment = db.Column(db.Float, default=0, nullable=True)
    partial_balance = db.Column(db.Float, default=0, nullable=True)
    repayment = db.Column(db.Float, nullable=False)
    profit = db.Column(db.Float, nullable=False)
    loan_status = db.Column(db.String(255), default='pending', nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc) + timedelta(hours=3), nullable=False)
    approval_timestamp = db.Column(db.DateTime, nullable=True)
    issuance_timestamp = db.Column(db.DateTime, nullable=True)
    payment_timestamp = db.Column(db.DateTime, nullable=True)
    guarantor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    system_id = db.Column(db.Integer, db.ForeignKey('system.id'), nullable=False)
    system = relationship('System', back_populates='loans')

class Records(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    document_path = db.Column(db.String(255))
    tags = db.Column(db.String(255))
    description = db.Column(db.Text)
    invitees = db.Column(db.String(50))
    meeting_date = db.Column(db.DateTime)
    location = db.Column(db.String(255))
    location_address = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc) + timedelta(hours=3), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='records')

    def __repr__(self):
        return f"Records('{self.title}', '{self.timestamp}')"

class Reminder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='reminders')

