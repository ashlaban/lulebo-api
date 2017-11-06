from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SelectField, validators
# from .models import User

from backend.models import UserNotFoundError

#If errors: check if adding 'validators.' before validators solves it...
class LoginForm(Form):
	username = StringField('username'  , [validators.InputRequired(message='Username required')])
	password = PasswordField('password', [validators.InputRequired(message='Password required')])
	
	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.user = None

	def validate(self):
		rv = Form.validate(self)
		if not rv:
			return False

		try:
			if User.authenticate(self.username.data, self.password.data):
				user = User.get_by_name(self.username.data)
				self.user = user
				return True
		except UserNotFoundError:
			self.username.errors.append('Unknown username')
			return False
		self.password.errors.append('Wrong password')
		return False

	def getErrors(self):
		return self.username.errors + self.password.errors

class SignupForm(Form):
	username = StringField('username'  , [validators.InputRequired(message='Username required')])
	email    = StringField('email'     , [validators.InputRequired(message='Please enter your email'), validators.Email(message='Email must be valid')])
	password = PasswordField('password', [validators.InputRequired(message='Please choose a password'), validators.EqualTo('confirm', message='Passwords must match')])
	confirm  = PasswordField('confirm' , [validators.InputRequired(message='You must confirm password')])

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.user = None

	def validate(self):
		# TODO: Implement email validation check, we require it to be unique.
		if not Form.validate(self):
			return False

		if len(self.username.data) > 64:
			self.username.errors.append('Username too long')
			return False

		if len(self.password.data) > 128:
			self.username.errors.append('Password too long')
			return False

		if User.exists(self.username.data):
			self.username.errors.append('Username taken')
			return False

		if User.exists_email(self.email.data):
			self.username.errors.append('Email already taken')
			return False

		return True

	def getErrors(self):
		return self.username.errors + self.password.errors + self.email.errors
