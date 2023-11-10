from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, URLField, validators


class ProfileForm(FlaskForm):
    username = StringField('Username', render_kw={'readonly': True})
    password = PasswordField('Password', [
        validators.optional(),
        validators.equal_to('password_again', message='Passwords must match'),
        validators.InputRequired(message='Password is required'),
        validators.Length(min=8, message='Password must be at least 8 characters long'),
        validators.Regexp(regex='^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()-_+=<>?/])(?!.*\s).+$', 
                          message='Password must meet the criteria'),
    ])
    
    password_again = PasswordField('Repeat Password')
    birthdate = DateField('Birth date', [validators.optional()])
    color = StringField('Favourite color')
    picture_url = URLField('Picture URL', [validators.url(), validators.optional()])
    about = TextAreaField('About')
    save = SubmitField('Save changes')

