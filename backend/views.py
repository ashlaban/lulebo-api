from flask import session, request, jsonify, Blueprint
from flask_login import login_user, logout_user, current_user, login_required
from backend import db, lm
from .models import User

from backend import util
from backend.models import UserNotFoundError

import sqlalchemy
import uuid
import werkzeug

from luleboapi import LuleboApi



backend_api = Blueprint('backend', __name__)



# ==============================================================================
# === Authentication
# ==============================================================================

@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

@backend_api.route('/signup', methods=['POST'])
def signup():
    json_data = request.get_json()

    # TODO: Validation
    try   : username = json_data['username']
    except: return util.make_json_error(msg='Missing username')
    try   : email = json_data['email']
    except: return util.make_json_error(msg='Missing email')
    try   : password = json_data['password']
    except: return util.make_json_error(msg='Missing password')
    try   : passvalid = json_data['passvalid']
    except: return util.make_json_error(msg='Missing password validation')

    # Validation
    if password != passvalid:
        return util.make_json_error(msg='Passwords don\'t match')

    try:
        User.get_by_name(username)
        return util.make_json_error(msg='User "{}" already registered'.format(username))
    except: pass

    try:
        User.get_by_email(email)
        return util.make_json_error(msg='Email already registered')
    except: pass

    # All checks passed, create user
    user = User(
        username  = username ,
        email     = email    ,
        password  = password ,
        lulebo_username = '' ,
        lulebo_password = '' ,
        uuid = str(uuid.uuid4())
    )

    try:
        db.session.add(user)
        db.session.commit()
        msg = 'Success'
        status = 'ok'
    except Exception as e:
        print(e)
        msg = 'unknown error'
        status = 'error'
    db.session.close()
    return jsonify({'msg': msg, 'status': status})

@backend_api.route('/login', methods=['POST'])
def login():
    json_data = request.get_json()

    if json_data is None:
        return util.make_json_error(msg='No credentials provided')

    try   : username = json_data['username']
    except: return util.make_json_error(msg='Missing username')
    try   : password = json_data['password']
    except: return util.make_json_error(msg='Missing password')

    if not User.authenticate(username, password):
        return util.make_json_error(msg='Wrong username and/or password')

    try:
        user = User.get_by_name(json_data['username'])
        login_user(user)
        return util.make_json_success(msg='Success')
    except UserNotFoundError as e:
        return util.make_json_error(msg='User not found')
    
@login_required
@backend_api.route('/logout')
def logout():
    logout_user()
    return util.make_json_success(msg='Logged out')


@backend_api.route('/hi')
def say_hi():
    return util.make_json_success(msg='Hello!')


@backend_api.route('/secret-hi')
@login_required
def say_secret_hi():
    return util.make_json_success(msg='Hello! (Logged in)')
    






# ==============================================================================
# === Lulebo
# ==============================================================================

@backend_api.route('/lulebo/login')
def lulebo_login():
    user = User.get_by_name('helena')

    session_id = LuleboApi.Login.login(user.lulebo_username, user.lulebo_password)
    r = LuleboApi.Session.getSessionStatus(session_id)
    


    # r = lulebo_build_request('https://portal.lulebo.se/LuleboMV.asmx/getObjectInfo', session_id)
    # r = lulebo_build_request('https://portal.lulebo.se/LuleboMV.asmx/queryObjectStatus', session_id)
    # r = lulebo_build_request('https://portal.lulebo.se/LuleboSession.asmx/getSessionStatus', session_id)
    # r = lulebo_build_request('https://portal.lulebo.se/LuleboStatus.asmx/GetActiveStatusPosts', session_id)
    print (r.headers)
    return r.text

@backend_api.route('/lulebo/object-info')
def lulebo_object_info():
    return lulebo_simple_forward('getObjectInfo')

@backend_api.route('/lulebo/object-status')
def lulebo_object_status():
    return lulebo_simple_forward('queryObjectStatus')

@backend_api.route('/lulebo/direct-start')
def lulebo_direct_start():
    return lulebo_simple_forward('directStartObject')


