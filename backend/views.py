from flask import session, request, jsonify, Blueprint
from flask_login import login_user, logout_user, current_user, login_required
from backend import db, lm
from .models import User

from backend import util
from backend.models import UserNotFoundError

import base64
import sqlalchemy
import uuid
import werkzeug

from werkzeug.wrappers import AuthorizationMixin

from luleboapi import LuleboApi
from luleboapi import LuleboApiError
from luleboapi import LuleboApiLoginError



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

@backend_api.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'GET':
        user_dict = request.authorization
    elif request.method == 'POST':
        user_dict = request.get_json()

    if user_dict is None or user_dict is '':
        return util.make_auth_challenge(msg='No credentials provided')
    
    try   : username = user_dict['username']
    except: return util.make_json_error(msg='Missing username', error_code=401)
    try   : password = user_dict['password']
    except: return util.make_json_error(msg='Missing password', error_code=401)
    
    if not User.authenticate(username, password):
        return util.make_json_error(msg='Wrong username and/or password', error_code=401)
    
    try:
        user = User.get_by_name(user_dict['username'])
        login_user(user)
        return util.make_json_success(msg='Success')
    except UserNotFoundError as e:
        return util.make_json_error(msg='User not found', error_code=401)
    
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
    
# Gives info about user object
@backend_api.route('/u')
@login_required
def user_info():
    '''
    Login by
        ```
        wget -qO- http://localhost:8081/login               \
        --save-cookies c.txt                                \
        --post-data '{"username":"kim", "password":"pass"}' \
        --header="Content-Type: application/json"           \
        --keep-session-cookie
        ```
        or
        ```
        wget -S -qO- http://kim:pass@localhost:8081/login \
        --save-cookies c.txt                              \
        --keep-session-cookie
        ```
        Test this resource with
        ```
        wget -qO- --load-cookies c.txt http://localhost:8081/u
        ```
        or
        ```
        wget -S -qO- http://kim:pass@localhost:8081/login \
        http://localhost:8081/u
        ```

    '''

    data = {
        'username': current_user.username,
        'email':current_user.email,
        'uuid':current_user.uuid
    }

    return util.make_json_success(msg='', data=data)

# Gives loginless access to certain commands
@backend_api.route('/u/<user_uuid>')
def user_uuid(user_uuid):
    print('/u/', user_uuid)
    user = User.get_by_uuid(user_uuid)
    return util.make_json_success(msg='', data={'username':user.username})

@backend_api.route('/u/<user_uuid>/direct-start/<time>')
def user_direct_start(user_uuid):
    '''Direct-start of engine header
    '''
    user = User.get_by_uuid(user_uuid)
    return {'username':user.username}





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


