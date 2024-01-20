# Import necessary modules and classes

# app/setup.py
from datetime import datetime
from app import db
from app.models import User, Role, System, Verification


def add_admin_role():
    roles = Role.query.filter(Role.name.in_(['system', 'admin', 'member', 'standard'])).all()
    if not roles:
        role_names = ['system', 'admin', 'member', 'standard']

        for role_name in role_names:
            add_roles = Role(name=role_name)
            db.session.add(add_roles)

        db.session.commit()

def add_admin_user():
    check_admin_user = User.query.filter_by(email='admin@mail.com').first()
    if not check_admin_user:
        admin_role = Role.query.filter_by(name='system').first()
        if admin_role:
            admin_user = User(
                first_name='system',
                last_name='admin',
                email='admin@mail.com',
                mobile_number='0000000000',
                id_number='unique_id',
                education_level='admin',
                occupation='administrator',
                dob=datetime.strptime('2023-11-01', '%Y-%m-%d'),
                membership=True,
                verification_status=True,
                password='$2b$12$4ZCociSjbcQPxJ26nbn6tu3yYZydKntC9wz4JEZIJWIzCYbHMO2W.',  # Apogen@2023
                role=admin_role
            )

            db.session.add(admin_user)
            db.session.commit()

def verify_admin_user():
    check_admin_user = User.query.filter_by(email='admin@mail.com').first()
    if check_admin_user:
        admin_role = Role.query.filter_by(name='system').first()
        if admin_role:
            verified = Verification.query.filter_by(user_id=check_admin_user.id, role_id=admin_role.id).first()
            if not verified:
                verify = Verification(user_id=check_admin_user.id, role_id=admin_role.id, verified=True)
                db.session.add(verify)
                db.session.commit()

def add_loan_types():
    check_not_null_loan_types = System.query.filter(System.loan_types != '').all()
    if not check_not_null_loan_types:
        loan_types = ['personal loan', 'mortgage loan', 'business loan']

        for loan_type in loan_types:
            add_loan_type = System(loan_types=loan_type)
            db.session.add(add_loan_type)

        db.session.commit()

def add_loan_durations():
    check_not_null_loan_durations = System.query.filter(System.loan_durations != '').all()
    if not check_not_null_loan_durations:
        loan_durations = ['30', '60', '90']

        for loan_duration in loan_durations:
            add_loan_duration = System(loan_durations=loan_duration)
            db.session.add(add_loan_duration)

        db.session.commit()
