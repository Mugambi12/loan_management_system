# Import necessary modules and classes

# app/routes.py
import calendar
import os
from flask import Blueprint, request, render_template, redirect, url_for, flash, jsonify, current_app
from flask_login import login_user, login_required, current_user, logout_user
from wtforms.validators import  ValidationError
from sqlalchemy import extract
from sqlalchemy.sql import func
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from operator import attrgetter
from app.server.forms.forms import *
from app.server.database.models import *
from app.server import db, bcrypt, login_manager


routes = Blueprint('routes', __name__)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@routes.context_processor
def inject_now():
    return {'now': datetime.utcnow() + timedelta(hours=3)}


# Functions
def validate_password(form, field):
    password = field.data
    if len(password) < 6:
        raise ValidationError('Password must be at least 6 characters long.')

def get_customer_names():
    if current_user.membership:
        customers = User.query.filter(User.id != '1', User.verification_status.is_(True)).all()
    elif current_user.verification_status:
        customers = [current_user]
    else:
        customers = []
    all_names = [f"{customer.first_name} {customer.last_name}" for customer in customers]
    names = sorted(all_names)  # Alphabetically sort names
    return names

def get_guarantor_names():
    guarantors = User.query.filter(User.id != '1', User.membership.is_(True)).all()
    all_names = [f"{guarantor.first_name} {guarantor.last_name}" for guarantor in guarantors]
    names = sorted(all_names)  # Alphabetically sort names
    return names

def get_loan_types():
    all_loan_types = System.query.filter(System.loan_types.isnot(None)).all()

    loan_types = sorted(all_loan_types, key=attrgetter('loan_types'))

    names = [loan_type.loan_types for loan_type in loan_types]
    return names

def get_loan_durations():
    loan_durations = System.query.filter(System.loan_durations.isnot(None)).all()
    all_durations = [loan_duration.loan_durations for loan_duration in loan_durations]
    durations = sorted(all_durations, key=lambda x: int(x))  # Sort durations as integers
    return durations

def get_system_id_by_loan_type(loan_type):
    system = System.query.filter_by(loan_types=loan_type).first()
    return system.id if system else None

def create_new_loan(customer_name, guarantor, loan_type, loan_duration, principal, service_cost, system_id):
    new_loan = Loan(
        customer_name=customer_name,
        guarantor_name=guarantor.first_name + " " + guarantor.last_name,
        loan_type=loan_type,
        loan_duration=loan_duration,
        principal=principal,
        service_cost=service_cost,
        system_id=system_id,
        guarantor_id=guarantor.id,
        timestamp=datetime.utcnow() + timedelta(hours=3),
        payment_timestamp=datetime.utcnow() + timedelta(days=int(loan_duration))
    )

    # Calculate outstanding balance
    new_loan.repayment = calculate_repayment(
        principal=principal,
        interest_rate=new_loan.interest_rate,
        fines=new_loan.fines if new_loan.fines else 0
    )

    # Calculate and update profit
    new_loan.profit = calculate_profit(
        repayment=new_loan.repayment,
        principal=principal
    )

    db.session.add(new_loan)
    db.session.commit()

def calculate_repayment(principal, interest_rate, fines):
    if interest_rate is not None:
        interest_amount = principal * (interest_rate / 100)
    else:
        interest_amount = 0

    repayment = principal + interest_amount + fines
    return repayment

def calculate_profit(repayment, principal):
    profit = repayment - principal
    return profit

def get_or_create_contribution_form():
    contribution_form = ContributionForm(request.form)
    contribution_form.members_name.choices = [(name, name) for name in get_guarantor_names()]
    return contribution_form

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def allowed_docs_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_DOCS_EXTENSIONS']

def handle_update_roles(role_ids, updated_roles):
    for role_id, updated_role in zip(role_ids, updated_roles):
        role = Role.query.get(role_id)
        if role:
            role.name = updated_role
    db.session.commit()
    flash('Roles updated successfully.', 'success')

def handle_add_new_roles(new_roles):
    for new_role in new_roles:
        if new_role:
            role = Role(name=new_role)
            db.session.add(role)
    db.session.commit()
    flash('New roles added successfully.', 'success')

def handle_delete_roles(roles_to_delete):
    for role_id in roles_to_delete:
        role = Role.query.get(role_id)
        if role:
            db.session.delete(role)
    db.session.commit()
    flash('Roles deleted successfully.', 'success')

def handle_update_loan_types(loan_type_ids, updated_loan_types):
    system = System.query.get(1)
    if system:
        # Update the loan types based on the IDs
        for loan_type_id, updated_loan_type in zip(loan_type_ids, updated_loan_types):
            loan_type = System.query.filter_by(id=int(loan_type_id)).first()
            if loan_type:
                loan_type.loan_types = updated_loan_type
        db.session.commit()
        flash('Loan types updated successfully.', 'success')

def handle_add_loan_types(new_loan_types):
    for new_loan_type in new_loan_types:
        if new_loan_type:
            loan_types = System(loan_types=new_loan_type)
            db.session.add(loan_types)
    db.session.commit()
    flash('New loan types added successfully.', 'success')

def handle_delete_loan_types(loan_types_to_delete):
    for loan_type in loan_types_to_delete:
        loan_types = System.query.get(loan_type)
        if loan_types:
            db.session.delete(loan_types)
    db.session.commit()
    flash('Loan types deleted successfully.', 'success')

def handle_update_loan_durations(loan_duration_ids, updated_loan_durations):
    system = System.query.get(1)
    if system:
        # Update the loan durations based on the IDs
        for loan_duration_id, updated_loan_duration in zip(loan_duration_ids, updated_loan_durations):
            loan_duration = System.query.filter_by(id=int(loan_duration_id)).first()
            if loan_duration:
                loan_duration.loan_durations = int(updated_loan_duration)
        db.session.commit()
        flash('Loan durations updated successfully.', 'success')

def handle_add_loan_durations(new_loan_durations):
    for new_loan_duration in new_loan_durations:
        if new_loan_duration:
            loan_durations = System(loan_durations=new_loan_duration)
            db.session.add(loan_durations)
    db.session.commit()
    flash('New loan durations added successfully.', 'success')

def handle_delete_loan_durations(loan_durations_to_delete):
    for loan_duration in loan_durations_to_delete:
        loan_durations = System.query.get(loan_duration)
        if loan_durations:
            db.session.delete(loan_durations)
    db.session.commit()
    flash('Loan durations deleted successfully.', 'success')

def calculate_users_acquisition_per_month(db, extract, func, User, calendar):
    users_acquisition_per_month = (
        db.session.query(
            extract('year', User.timestamp).label('year'),
            extract('month', User.timestamp).label('month'),
            func.count(User.id).label('count')
        )
        .filter(User.id != 1)
        .group_by('year', 'month')
        .order_by('year', 'month')
        .all()
    )

    customer_acquisition_data = {
        'labels': [f"{calendar.month_name[entry.month]} {entry.year}" for entry in users_acquisition_per_month],
        'data': [entry.count for entry in users_acquisition_per_month]
    }

    return customer_acquisition_data

def calculate_loans_processed_per_month(db, extract, func, Loan):
    loans_processed_per_month = (
        db.session.query(
            extract('year', Loan.timestamp).label('year'),
            extract('month', Loan.timestamp).label('month'),
            func.sum(Loan.principal).label('total_principal')
        )
        .group_by('year', 'month')
        .order_by('year', 'month')
        .all()
    )

    loans_processed_data = {
        'labels': [f"{calendar.month_name[entry.month]} {entry.year}" for entry in loans_processed_per_month],
        'data': [entry.total_principal or 0 for entry in loans_processed_per_month]
    }

    return loans_processed_data

def retrieve_loan_status_data(Loan, func):
    loan_status_data = {
        'labels': ['Pending', 'Approved', 'Fully Issued', 'Partially Issued', 'Partially Paid', 'Fully Paid'],
        'data': [
            Loan.query.filter_by(loan_status='pending').with_entities(func.sum(Loan.principal)).scalar() or 0,
            Loan.query.filter_by(loan_status='approved').with_entities(func.sum(Loan.principal)).scalar() or 0,
            Loan.query.filter_by(loan_status='fully_issued').with_entities(func.sum(Loan.principal)).scalar() or 0,
            Loan.query.filter_by(loan_status='partially_issued').with_entities(func.sum(Loan.principal)).scalar() or 0,
            Loan.query.filter_by(loan_status='partially_paid').with_entities(func.sum(Loan.principal)).scalar() or 0,
            Loan.query.filter_by(loan_status='fully_paid').with_entities(func.sum(Loan.principal)).scalar() or 0,
        ],
        'backgroundColor': ['#FFC107', '#4CAF50', '#FF9800', '#2196F3', '#FF5722', '#8BC34A'],
    }

    return loan_status_data

def retrieve_contributions_per_user(db, func, User):
    contributions_per_user = (
        db.session.query(
            User.id,
            User.first_name,
            User.last_name,
            func.sum(Contribution.amount).label('total_contribution')
        )
        .join(Contribution)
        .group_by(User.id, User.first_name, User.last_name)
        .all()
    )

    contributions_data = {
        'labels': [f"{entry.first_name} {entry.last_name}" for entry in contributions_per_user],
        'data': [entry.total_contribution or 0 for entry in contributions_per_user]
    }

    return contributions_data

# Routes
# Auth Management Routes
@routes.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if user.verification_status:
                login_user(user)
                flash('You have been logged in successfully.', 'info')
                return redirect(url_for('routes.dashboard'))
            else:
                flash('Your account is not verified. Please wait for verification before logging in.', 'warning')
        else:
            flash('Invalid email or password. Please try again.', 'danger')

    return render_template('auth/login.html', form=form, hide_navbar=True)

@routes.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if the email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Email address already exists. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        try:
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            # Set the default role as "standard"
            default_role = Role.query.filter_by(name='standard').first()

            # Create a new user
            new_user = User(
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                email=form.email.data,
                mobile_number=form.mobile_number.data,
                id_number=form.id_number.data,
                education_level=form.education_level.data,
                occupation=form.occupation.data,
                dob=form.dob.data,
                password=hashed_password,
                role=default_role  # Assign the default role to the user
            )

            # Add the new user to the database
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('routes.login'))

        except Exception as e:
            # Handle any exceptions that may occur during database operations
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            return redirect(url_for('routes.register'))

    # If form validation fails, display error messages
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'{field.capitalize()}: {error}', 'danger')

    return render_template('auth/register.html', form=form, hide_navbar=True)

@routes.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('routes.login'))


# General Dashboard Route
@routes.route('/dashboard')
@login_required
def dashboard():
    # Retrieve user-related data
    user_id = current_user.get_id()
    user = User.query.get_or_404(user_id)
    users = User.query.all()

    # Retrieve Loans data
    loans = Loan.query.all()
    loans_approved_count = Loan.query.filter_by(loan_status='approved').count()
    total_loans_as_customer = Loan.query.filter_by(customer_name=f"{current_user.first_name} {current_user.last_name}").count()

    # Retrieve Contributions data
    contribution_form = get_or_create_contribution_form()
    contributions = Contribution.query.all()

    # Retrieve Records data
    records_form = RecordsForm()
    reminder_form = ReminderForm()
    records = Records.query.all()
    reminders = Reminder.query.filter_by(user_id=current_user.id).order_by(Reminder.id.desc()).all()

    # Retrieve system settings data
    setting_form = SettingsForm()
    roles = Role.query.all()
    all_loan_types = System.query.filter(System.loan_types.isnot(None)).all()
    loan_types = sorted(all_loan_types, key=attrgetter('loan_types'))
    loan_durations = System.query.filter(System.loan_durations.isnot(None)).all()

    # Retrieve Charts data
    customer_acquisition_data = calculate_users_acquisition_per_month(db, extract, func, User, calendar)
    loans_processed_data = calculate_loans_processed_per_month(db, extract, func, Loan)
    loan_status_data = retrieve_loan_status_data(Loan, func)
    contributions_per_user_data = retrieve_contributions_per_user(db, func, User)

    # Prepare chart data
    chart_data = {
        'loan_status_data': loan_status_data,
        'customer_acquisition_data': customer_acquisition_data,
        'loans_processed_data': loans_processed_data,
        'contributions_per_user_data': contributions_per_user_data  # Include contributions per user data
    }

    # Handle JSON request
    if request.is_json:
        return jsonify(chart_data)

    # Render the template with organized data
    return render_template(
        'home/base.html',
        user=user,
        users=users,
        loans=loans,
        loans_approved_count=loans_approved_count,
        total_loans_as_customer=total_loans_as_customer,
        contributions=contributions,
        contributions_per_user_data=contributions_per_user_data,
        roles=roles,
        loan_types=loan_types,
        loan_durations=loan_durations,
        setting_form=setting_form,
        contribution_form=contribution_form,
        records=records,
        records_form=records_form,
        reminders=reminders,
        reminder_form=reminder_form
    )

# User Management Routes
@routes.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm()
    roles = Role.query.all()
    form.role.choices = [(role.id, role.name) for role in roles]

    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.email = form.email.data
        user.mobile_number = form.mobile_number.data
        user.id_number = form.id_number.data
        user.education_level = form.education_level.data
        user.occupation = form.occupation.data
        user.dob = form.dob.data
        user.membership = form.membership.data
        user.verification_status = form.verification_status.data
        selected_role_id = form.role.data
        selected_role = Role.query.get(selected_role_id)
        user.role = selected_role

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                rename_filename = f"user_{user_id}.{file.filename.rsplit('.', 1)[1].lower()}"
                renamed_filename = secure_filename(rename_filename)
                filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], renamed_filename)
                file.save(filepath)
                user.profile_picture = renamed_filename

        # Handle password change
        current_password = form.current_password.data
        new_password = form.new_password.data
        confirm_new_password = form.confirm_new_password.data

        if current_password and new_password and confirm_new_password and new_password != None:
            if bcrypt.check_password_hash(user.password, current_password):
                if new_password == confirm_new_password:
                    # Hash the new password using bcrypt
                    hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    user.password = hashed_new_password

                    db.session.commit()
                    flash('Password changed successfully!', 'success')
                    return redirect(url_for('routes.dashboard'))
                else:
                    flash('New password and confirm new password do not match. Password not changed.', 'danger')
                    return redirect(url_for('routes.dashboard'))
            else:
                flash('Current password is incorrect. Password not changed.', 'danger')
                return redirect(url_for('routes.dashboard'))

        db.session.commit()
        flash('Your changes have been saved!', 'success')
        return redirect(url_for('routes.dashboard'))

    elif request.method == 'GET':
        form.first_name.data = user.first_name
        form.last_name.data = user.last_name
        form.email.data = user.email
        form.mobile_number.data = user.mobile_number
        form.id_number.data = user.id_number
        form.education_level.data = user.education_level
        form.occupation.data = user.occupation
        form.dob.data = user.dob
        form.membership.data = user.membership
        form.verification_status.data = user.verification_status
        form.role.data = user.role.id if user.role else None

    return render_template('common/edit_user.html', title='Edit User', form=form, user=user)

@routes.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)

    if request.method == 'POST':
        try:
            Verification.query.filter_by(user_id=user_id).delete()
            db.session.delete(user_to_delete)
            db.session.commit()
            flash('User deleted successfully', 'success')
            return redirect(url_for('routes.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting user: {str(e)}', 'danger')

    return render_template('common/edit_user.html', user=user_to_delete)


# Loan Management Routes
@routes.route('/add_loan', methods=['GET', 'POST'])
@login_required
def add_loan():
    form = LoanForm()

    # Populate choices for dropdowns
    form.customer_name.choices = [(name, name) for name in get_customer_names()]
    form.guarantor_name.choices = [(name, name) for name in get_guarantor_names()]
    form.loan_type.choices = [(name, name) for name in get_loan_types()]
    form.loan_duration.choices = [(duration, duration) for duration in get_loan_durations()]

    if form.validate_on_submit():
        customer_name = form.customer_name.data
        guarantor_name = form.guarantor_name.data
        loan_type = form.loan_type.data
        loan_duration = form.loan_duration.data
        principal = form.principal.data
        service_cost = form.service_cost.data  or 0.0

        guarantor_first_name, guarantor_last_name = guarantor_name.split(" ", 1)
        guarantor = User.query.filter_by(first_name=guarantor_first_name, last_name=guarantor_last_name).first()

        if guarantor:
            system_id = get_system_id_by_loan_type(loan_type)

            try:
                create_new_loan(customer_name, guarantor, loan_type, loan_duration, principal, service_cost, system_id)
                flash('Loan added successfully.', 'success')
                return redirect(url_for('routes.dashboard'))
            except Exception as e:
                flash(f'Error adding loan: {str(e)}', 'danger')
        else:
            flash('Guarantor not found.', 'warning')

    return render_template('common/add_loan.html', form=form)

@routes.route('/edit_loan/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def edit_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    form = EditLoanForm(obj=loan)

    form.customer_name.choices = get_customer_names()
    form.guarantor_name.choices = get_guarantor_names()
    form.loan_type.choices = get_loan_types()
    form.loan_duration.choices = get_loan_durations()

    if form.validate_on_submit():
        form.populate_obj(loan)

        if form.payment_timestamp.data:
            loan.payment_timestamp = form.payment_timestamp.data
        else:
            loan.loan_duration = form.loan_duration.data
            loan.payment_timestamp = datetime.utcnow() + timedelta(days=int(form.loan_duration.data))

        if form.issuance_timestamp.data:
            loan.issuance_timestamp = form.issuance_timestamp.data
        else:
            loan.issuance_timestamp = datetime.utcnow()

        if form.approval_timestamp.data:
            loan.approval_timestamp = form.approval_timestamp.data
        else:
            loan.approval_timestamp = datetime.utcnow()

        db.session.commit()

        flash('Loan details have been updated!', 'success')
        return redirect(url_for('routes.dashboard'))

    return render_template('common/edit_loan.html', title='Edit Loan', form=form, loan=loan)

@routes.route('/approve_loan/<int:loan_id>')
@login_required
def approve_loan(loan_id):
    loan = Loan.query.get(loan_id)
    if loan:
        loan.loan_status = 'approved'
        loan.approval_timestamp = datetime.now(timezone.utc) + timedelta(hours=3)
        db.session.commit()
        flash('Loan approved successfully.', 'success')
    return redirect(url_for('routes.dashboard'))

@routes.route('/decline_loan/<int:loan_id>')
@login_required
def decline_loan(loan_id):
    loan = Loan.query.get(loan_id)
    if loan:
        loan.loan_status = 'declined'
        loan.approval_timestamp = datetime.now(timezone.utc) + timedelta(hours=3)
        db.session.commit()
        flash('Loan declined successfully.', 'danger')
    return redirect(url_for('routes.dashboard'))

@routes.route('/issue_fully/<int:loan_id>')
@login_required
def issue_fully(loan_id):
    loan = Loan.query.get(loan_id)
    if loan:
        loan.loan_status = 'fully_issued'
        loan.issuance_timestamp = datetime.now(timezone.utc) + timedelta(hours=3)
        db.session.commit()
        flash('Loan fully issued successfully.', 'success')
    return redirect(url_for('routes.dashboard'))

@routes.route('/issue_partially/<int:loan_id>')
@login_required
def issue_partially(loan_id):
    loan = Loan.query.get(loan_id)
    if loan:
        loan.loan_status = 'partially_issued'
        db.session.commit()
        flash('Loan partially issued successfully.', 'success')
    return redirect(url_for('routes.dashboard'))

@routes.route('/paid_partially/<int:loan_id>')
@login_required
def paid_partially(loan_id):
    loan = Loan.query.get(loan_id)
    if loan:
        loan.loan_status = 'partially_paid'
        db.session.commit()
        flash('Loan partially paid successfully.', 'success')
    return redirect(url_for('routes.dashboard'))

@routes.route('/paid_fully/<int:loan_id>')
@login_required
def paid_fully(loan_id):
    loan = Loan.query.get(loan_id)
    if loan:
        loan.loan_status = 'fully_paid'
        loan.payment_timestamp = datetime.now(timezone.utc) + timedelta(hours=3)
        db.session.commit()
        flash('Loan fully paid successfully.', 'success')
    return redirect(url_for('routes.dashboard'))

@routes.route('/delete_loan/<int:loan_id>')
@login_required
def delete_loan(loan_id):
    loan = Loan.query.get(loan_id)
    if loan:
        db.session.delete(loan)
        db.session.commit()
        flash('Loan deleted successfully.', 'danger')
    return redirect(url_for('routes.dashboard'))


# Contribution Management Routes
@routes.route('/submit_contribution', methods=['GET', 'POST'])
@login_required
def submit_contribution():
    contribution_form = get_or_create_contribution_form()

    if contribution_form.validate_on_submit():
        members_name = contribution_form.members_name.data
        amount = contribution_form.amount.data
        transaction_type = contribution_form.transaction_type.data == 'true'
        fine_amount = contribution_form.fine_amount.data or 0.0

        member_first_name, member_last_name = members_name.split(" ", 1)
        member = User.query.filter_by(first_name=member_first_name, last_name=member_last_name).first()

        if member:
            contributor_id = member.id

            new_contribution = Contribution(
                user_id=contributor_id,
                contributor=members_name,
                amount=amount,
                transaction_type=transaction_type,
                fine_amount=fine_amount,
                timestamp=datetime.utcnow() + timedelta(hours=3)
            )

            db.session.add(new_contribution)
            db.session.commit()

            flash('Transaction submitted successfully!', 'success')
        else:
            flash('Invalid Member ID. Please select a valid member.', 'danger')

        return redirect(url_for('routes.dashboard'))

    return render_template('dashboard.html', form=contribution_form)

@routes.route('/edit_contribution/<int:contribution_id>', methods=['GET', 'POST'])
@login_required
def edit_contribution(contribution_id):
    contribution = Contribution.query.get_or_404(contribution_id)
    form = EditContributionForm(request.form, obj=contribution)

    if request.method == 'POST' and form.validate():
        # Update contribution details
        contribution.amount = form.amount.data
        contribution.transaction_type = form.transaction_type.data == 'true'
        contribution.fine_amount = form.fine_amount.data or 0.0

        db.session.commit()

        flash('Transaction updated successfully!', 'success')

        return redirect(url_for('routes.dashboard'))

    return render_template('common/edit_contribution.html', contribution=contribution, edit_contribution_form=form, contributor_name=contribution.contributor)


# Record/Meeting Management Routes
@routes.route('/submit_record', methods=['POST'])
@login_required
def submit_record():
    records_form = RecordsForm(request.form)

    if records_form.validate_on_submit():

        # Create Records instance
        new_record = Records(
            title=records_form.title.data,
            category=records_form.category.data,
            tags=records_form.tags.data,
            description=records_form.description.data,
            invitees=records_form.invitees.data,
            meeting_date=records_form.meeting_date.data,
            location=records_form.location.data,
            location_address=records_form.location_address.data,
            user=current_user
        )

        # Save uploaded document if provided
        if 'document' in request.files:
            file = request.files['document']
            if file:
                if allowed_docs_file(file.filename):
                    current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
                    rename_filename = f"{current_time}.{file.filename.rsplit('.', 1)[1].lower()}"
                    renamed_filename = secure_filename(rename_filename)
                    filepath = os.path.join(current_app.config['DOCS_FOLDER'], renamed_filename)
                    file.save(filepath)
                    new_record.document_path = renamed_filename
                else:
                    flash('Invalid document format. Allowed formats: PDF, DOCX', 'danger')
                    return redirect(url_for('routes.dashboard'))

        # Save the record to the database
        db.session.add(new_record)
        db.session.commit()

        # Flash formatted message based on the category
        category_flash_message = {
            'archives': 'Archival submitted successfully!',
            'meetings': 'Meeting scheduled successfully!'
        }
        flash(category_flash_message.get(new_record.category, 'Record submitted successfully!'), 'success')

        return redirect(url_for('routes.dashboard'))

    # Provide more specific error messages
    flash_errors = "\n".join([f"{field.label.text}: {', '.join(errors)}" for field, errors in records_form.errors.items()])
    flash(f'Failed to submit meeting. Please check your input:\n{flash_errors}', 'danger')
    return render_template('errors/error.html', records_form=records_form)


# Reminder Management Routes
@routes.route('/reminders', methods=['GET', 'POST'])
@login_required
def reminders():
    form = ReminderForm()

    if form.validate_on_submit():
        # Add new reminder
        new_reminder = Reminder(text=form.text.data, user=current_user)
        db.session.add(new_reminder)
        flash('Reminder added successfully!', 'success')
        db.session.commit()
        return redirect(url_for('routes.dashboard'))

    reminders_list = current_user.reminders
    return render_template('reminders.html', form=form, reminders_list=reminders_list)

@routes.route('/reminders/delete/<int:reminder_id>', methods=['POST'])
@login_required
def delete_reminder(reminder_id):
    reminder = Reminder.query.get_or_404(reminder_id)
    if reminder.user_id != current_user.id:
        flash('Permission Denied', 'danger')
        return redirect(url_for('reminders'))

    db.session.delete(reminder)
    db.session.commit()
    flash('Reminder deleted successfully!', 'success')
    return redirect(url_for('routes.dashboard'))

@routes.route('/reminders/toggle/<int:reminder_id>', methods=['POST'])
@login_required
def toggle_completed(reminder_id):
    reminder = Reminder.query.get_or_404(reminder_id)
    if reminder.user_id != current_user.id:
        flash('Permission Denied', 'danger')
        return redirect(url_for('reminders'))

    reminder.completed = not reminder.completed
    db.session.commit()
    flash('Reminder updated successfully!', 'success')
    return redirect(url_for('routes.dashboard'))


# Define SettingsForm
@routes.route('/system_settings', methods=['GET', 'POST'])
@login_required
def system_settings():
    roles = Role.query.all()
    loan_types = System.query.with_entities(System.loan_types).first()
    loan_durations = System.query.with_entities(System.loan_durations).first()

    if request.method == 'POST':
        if 'update_roles' in request.form:
            handle_update_roles(request.form.getlist('selectRoleToUpdate'), request.form.getlist('updatedRoleName'))

        elif 'add_new_roles' in request.form:
            handle_add_new_roles(request.form.getlist('newRoleName'))

        elif 'delete_roles' in request.form:
            handle_delete_roles(request.form.getlist('selectRoleToDelete'))

        elif 'update_loan_type' in request.form:
            handle_update_loan_types(request.form.getlist('selectLoanTypeToUpdate'), request.form.getlist('updatedLoanTypeName'))

        elif 'add_loan_type' in request.form:
            handle_add_loan_types(request.form.getlist('newLoanTypeName'))

        elif 'delete_loan_type' in request.form:
            handle_delete_loan_types(request.form.getlist('selectLoanTypeToDelete'))

        elif 'update_loan_duration' in request.form:
            handle_update_loan_durations(request.form.getlist('selectLoanDurationToUpdate'), request.form.getlist('updatedLoanDurationName'))

        elif 'add_loan_durition' in request.form:
            handle_add_loan_durations(request.form.getlist('newLoanDurationName'))

        elif 'dalete_loan_durition' in request.form:
            handle_delete_loan_durations(request.form.getlist('selectLoanDurationToDelete'))
    else:
        flash('The changes were not updated.', 'danger')

    return redirect(url_for('routes.dashboard', roles=roles, loan_types=loan_types, loan_durations=loan_durations))
