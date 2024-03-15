# Import necessary modules and classes

# app/forms.py
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField, DateField, FloatField, BooleanField, SelectField, FileField, DateTimeField, TextAreaField, DateTimeLocalField
from wtforms.validators import DataRequired, Email, Length, Optional, EqualTo, NumberRange, InputRequired


# Forms
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobile_number = StringField('Mobile Number', validators=[DataRequired(), Length(min=10, max=15)])
    id_number = StringField('ID Number', validators=[DataRequired()])
    education_level = SelectField('Education Level', choices=[('high school', 'High School'), ('diploma', 'Diploma'), ('undergraduate', 'Undergraduate'), ('graduate', 'Graduate'), ('post graduate', 'Post Graduate'), ('doctorate', 'Doctorate'), ('other', 'Other')], validators=[DataRequired()])
    occupation = StringField('Occupation', validators=[DataRequired()])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EditUserForm(FlaskForm):
    profile_picture = FileField('Profile Picture')
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=255)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=255)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    mobile_number = StringField('Mobile Number', validators=[DataRequired(), Length(max=15)])
    id_number = StringField('ID Number', validators=[DataRequired(), Length(max=20)])
    education_level = SelectField('Education Level', choices=[('high school', 'High School'), ('diploma', 'Diploma'), ('undergraduate', 'Undergraduate'), ('graduate', 'Graduate'), ('post graduate', 'Post Graduate'), ('doctorate', 'Doctorate'), ('other', 'Other')], validators=[DataRequired()])
    occupation = StringField('Occupation', validators=[DataRequired(), Length(max=255)])
    dob = DateField('Date of Birth', validators=[DataRequired()])
    membership = BooleanField('Activate Membership')
    verification_status = BooleanField('Activate Verification')
    role = SelectField('Role', coerce=int, validators=[DataRequired()])
    current_password = PasswordField('Current Password', validators=[Optional(), Length(min=6)])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[Optional(), Length(min=6)])
    submit = SubmitField('Save Changes')
    delete = SubmitField('Delete User')

class LoanForm(FlaskForm):
    customer_name = SelectField('Customer Name', choices=[], validators=[DataRequired()])
    guarantor_name = SelectField('Guarantor Name', choices=[], validators=[DataRequired()])
    loan_type = SelectField('Loan Type', choices=[], validators=[DataRequired()])
    loan_duration = SelectField('Loan Duration', choices=[], validators=[DataRequired()])
    principal = FloatField('Principal Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    service_cost = FloatField('Service Cost', validators=[DataRequired(), NumberRange(min=0.01)])

class EditLoanForm(FlaskForm):
    customer_name = SelectField('Customer Name', choices=[], validators=[DataRequired()])
    guarantor_name = SelectField('Guarantor Name', choices=[], validators=[DataRequired()])
    loan_type = SelectField('Loan Type', choices=[], validators=[DataRequired()])
    loan_duration = SelectField('Loan Duration (Days)', choices=[], validators=[DataRequired()])
    principal = FloatField('Principal Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    interest_rate = FloatField('Interest Rate', default=10, validators=[DataRequired(), NumberRange(min=0.01)])
    service_cost = FloatField('Service Cost', validators=[DataRequired(), NumberRange(min=0.01)])
    fines = FloatField('Fines', default=0, validators=[NumberRange(min=0)])
    partial_issuance = FloatField('Partial Issuance', default=0, validators=[NumberRange(min=0)])
    partial_payment = FloatField('Partial Payment', default=0, validators=[NumberRange(min=0)])
    payment_timestamp = DateTimeField('Payment Timestamp', format='%d-%m-%Y', validators=[Optional()])
    approval_timestamp = DateTimeField('Approval Timestamp', format='%d-%m-%Y', validators=[Optional()])
    issuance_timestamp = DateTimeField('Issuance Timestamp', format='%d-%m-%Y', validators=[Optional()])
    submit = SubmitField('Save Changes')

class ContributionForm(FlaskForm):
    members_name = SelectField('Members Name', choices=[], validators=[DataRequired()])
    amount = FloatField('Contribution Amount (KES)', validators=[InputRequired(), NumberRange(min=0)])
    transaction_type = SelectField('Payment Status', choices=[('true', 'Contribution'), ('false', 'Welfare')], validators=[InputRequired()])
    fine_amount = FloatField('Fine Amount (KES)', validators=[NumberRange(min=0)])

class EditContributionForm(FlaskForm):
    amount = FloatField('Contribution Amount (KES)', validators=[InputRequired(), NumberRange(min=0)])
    transaction_type = SelectField('Payment Status', choices=[('true', 'Paid'), ('false', 'Not Paid')], validators=[InputRequired()])
    fine_amount = FloatField('Fine Amount (KES)', validators=[NumberRange(min=0)])

class RecordsForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    category = SelectField('Category', choices=[('archives', 'Create Archive'), ('meetings', 'Schedule Meeting')], validators=[DataRequired()])
    document = FileField('Upload Document')
    tags = StringField('Document Tags')
    description = TextAreaField('Document Description')
    invitees = SelectField('Meeting Invitees', choices=[('all users', 'All Users'), ('members', 'Members'), ('customers', 'Customers')])
    meeting_date = DateTimeLocalField('Select Meeting Date', format='%Y-%m-%dT%H:%M', validators=[Optional()])
    location = StringField('Meeting Location')
    location_address = StringField('Meeting Location Address')

class ReminderForm(FlaskForm):
    text = StringField('Reminder', validators=[DataRequired()])
    completed = BooleanField('completed Reminder')

class SettingsForm(FlaskForm):
    selectRoleToUpdate = StringField('Role to Update')
    updatedRoleName = StringField('Updated Role Name')
    newRoleName = StringField('New Role Name')
    selectRoleToDelete = StringField('Role to Delete')

    selectLoanTypeToUpdate = StringField('Loan Type to Update')
    updatedLoanTypeName = StringField('Updated Loan Type Name')
    newLoanTypeName = StringField('New Loan Type Name')
    selectLoanTypeToDelete = StringField('Loan Type to Delete')

    selectLoanDurationToUpdate = StringField('Loan Duration to Update')
    updatedLoanDurationName = StringField('Updated Loan Duration Name')
    newLoanDurationName = StringField('New Loan Duration Name')
    selectLoanDurationToDelete = StringField('Loan Duration to Delete')
    submit = SubmitField('Save Changes')
