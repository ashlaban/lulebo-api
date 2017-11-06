from flask import render_template, flash, redirect, session, url_for, request, g
from flask_login import login_user, logout_user, current_user, login_required
from backend import backend, db, lm
from .models import User

from backend import util
from backend.models import UserNotFoundError

import requests
import collections
import werkzeug
import sqlalchemy

from luleboapi import LuleboApi

@lm.user_loader
def load_user(id):
	return User.query.get(int(id))

@backend.before_request
def before_request():
	g.user = current_user

@backend.route('/')
@backend.route('/index')
def index():
	# if g.user is not None and g.user.is_authenticated:
	# 	return redirect(url_for('profile_mod.show_profile_page'))
	return render_template('index.html')






@backend.route('/api/lulebo/login')
def api_lulebo_login():
	user = User.get_by_name('helena')

	session_id = LuleboApi.Login.login(user.lulebo_username, user.lulebo_password)
	r = LuleboApi.Session.getSessionStatus(session_id)
	


	# r = lulebo_build_request('https://portal.lulebo.se/LuleboMV.asmx/getObjectInfo', session_id)
	# r = lulebo_build_request('https://portal.lulebo.se/LuleboMV.asmx/queryObjectStatus', session_id)
	# r = lulebo_build_request('https://portal.lulebo.se/LuleboSession.asmx/getSessionStatus', session_id)
	# r = lulebo_build_request('https://portal.lulebo.se/LuleboStatus.asmx/GetActiveStatusPosts', session_id)
	print (r.headers)
	return r.text

@backend.route('/api/lulebo/object-info')
def lulebo_object_info():
	return lulebo_simple_forward('getObjectInfo')

@backend.route('/api/lulebo/object-status')
def lulebo_object_status():
	return lulebo_simple_forward('queryObjectStatus')

@backend.route('/api/lulebo/direct-start')
def lulebo_direct_start():
	return lulebo_simple_forward('directStartObject')

# @backend.route('/signup', methods=['GET', 'POST'])
# def signup():
# 	form = SignupForm()
# 	return render_template('signup.html', title='Signup', form=form)

# # TODO: Implement salted passwords: http://flask.pocoo.org/snippets/54/
# @backend.route('/login', methods=['GET', 'POST'])
# def login():
# 	if g.user is not None and g.user.is_authenticated:
# 		return redirect(url_for('index'))
# 	form = LoginForm()
# 	return render_template('login.html', title='Login', form=form)

# @backend.route('/logout')
# @login_required
# def logout():
# 	logout_user()
# 	return redirect(url_for('index'))

@backend.route('/api/signup', methods=['POST'])
def api_signup():
	args = util.parse_request_to_json(request)
	form = SignupForm.from_json(args)

	if not form.validate():
		return util.make_json_error(msg=form.getErrors())
	
	user = User(username=form.username.data, password=form.password.data, email=form.email.data)
	db.session.add(user)
	db.session.commit()

	login_user(user)
	return util.make_json_success(msg='Thanks for signing up.')

@backend.route('/api/login', methods=['POST'])
def api_login():
	args = util.parse_request_to_json(request)
	form = LoginForm.from_json(args)

	if not form.validate():
		return util.make_json_error(msg=form.getErrors())
	
	user = User.get_by_name(form.username.data)
	login_user(user)
	return util.make_json_success(msg='Welcome.')
