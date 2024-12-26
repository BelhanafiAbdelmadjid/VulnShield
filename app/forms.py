from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Email, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SubscriptionForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    cve_types = SelectMultipleField('CVE Types', choices=[('type1', 'Type 1'), ('type2', 'Type 2')])
    submit = SubmitField('Subscribe')
