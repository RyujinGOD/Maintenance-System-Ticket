from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class RegisterForm(FlaskForm):
    name = StringField('Full name', validators=[DataRequired(), Length(max=120)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TicketForm(FlaskForm):
    type = SelectField('Problem type', choices=[('hardware','Hardware'), ('software','Software'), ('network','Network'), ('other','Other')], validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=2000)])
    submit = SubmitField('Submit Ticket')

class TicketUpdateForm(FlaskForm):
    status = SelectField('Status', choices=[('open','Open'), ('in_progress','In progress'), ('resolved','Resolved')], validators=[DataRequired()])
    action_done = TextAreaField('Action taken', validators=[Length(max=2000)])
    managed_by = SelectField('Managed by (assign to)', coerce=int)
    submit = SubmitField('Save')
