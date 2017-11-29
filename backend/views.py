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

@lm.request_loader
def load_user_request(id):
    user_dict = request.authorization

    if user_dict is None or user_dict is '':
        return None

    try   : username = user_dict['username']
    except: return None
    try   : password = user_dict['password']
    except: return None
    
    if not User.authenticate(username, password):
        return None
    
    try:
        user = User.get_by_name(user_dict['username'])
        login_user(user)
        return user
    except UserNotFoundError as e:
        return None

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
    except: return util.make_json_error(msg='Missing username', status_code=401)
    try   : password = user_dict['password']
    except: return util.make_json_error(msg='Missing password', status_code=401)
    
    if not User.authenticate(username, password):
        return util.make_json_error(msg='Wrong username and/or password', status_code=401)
    
    try:
        user = User.get_by_name(user_dict['username'])
        login_user(user)
        return util.make_json_success(msg='Success')
    except UserNotFoundError as e:
        return util.make_json_error(msg='User not found', status_code=401)
    
@login_required
@backend_api.route('/logout')
def logout():
    logout_user()
    return util.make_json_success(msg='Logged out')





# ==============================================================================
# === Testing
# ==============================================================================

@backend_api.route('/hi')
def say_hi():
    return util.make_json_success(msg='Hello!')


@backend_api.route('/secret-hi')
@login_required
def say_secret_hi():
    return util.make_json_success(msg='Hello! (Logged in)')





# ==============================================================================
# === User
# ==============================================================================

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

        Testing with curl
        ```
        curl '{kim:pass@localhost:8081/login,localhost:8081/u}' -c ''
        ```

    '''

    data = {
        'username': current_user.username,
        'email':current_user.email,
        'uuid':current_user.uuid
    }

    return util.make_json_success(msg='', data=data)

# Gives loginless access to certain commands
@backend_api.route('/u/<uuid:user_uuid>')
def user_uuid(user_uuid):
    print('/u/', user_uuid)
    user = User.get_by_uuid(str(user_uuid))
    return util.make_json_success(msg='', data={'username':user.username})

@backend_api.route('/u/<uuid:user_uuid>/direct-start/<time>')
def user_direct_start(user_uuid, time):
    '''Direct-start of engine header
    '''

    # TODO: parse time string
    # TODO: retrieve lulebo login
    # TODO: send lulebo request

    user = User.get_by_uuid(str(user_uuid))
    return {'username':user.username}





# ==============================================================================
# === Lulebo
# ==============================================================================

def lulebo_login(user):
    '''
    Logs a user (authenticated to site already) into LuleboAPI and stores the
    associated session key in the database.
    '''
    username = user.lulebo_username
    password = user.lulebo_password

    try:
        session_id = LuleboApi.Login.login(username, password)
    except LuleboApiLoginError as e:
        return util.make_json_error(
            msg='Lulebo authentication failed with message {}'.format(e.msg),
            error_code='login-1'
        )

    user.lulebo_session_id = session_id

    try:
        db.session.add(user)
        db.session.commit()
        db.session.close()
        return util.make_json_success('Logged in to LuleboAPI')
    except Exception as e:
        db.session.rollback()
        db.session.close()
        return util.make_json_error('Lulebo authentication failed', error_code='login-2')

def lulebo_session_info(session_id):
    r = LuleboApi.Session.getSessionStatus(session_id)
    data = r.json()['d']
    return util.make_json_success(data=data)

def lulebo_site_info(session_id):
    r = LuleboApi.MV.getSiteInfo(session_id)
    data = r.json()['d']
    return util.make_json_success(data=data)

def lulebo_object_info(session_id):
    r = LuleboApi.MV.getObjectInfo(session_id)
    data = r.json()['d']
    return util.make_json_success(data=data)

def lulebo_object_status(session_id):
    r = LuleboApi.MV.queryObjectStatus(session_id)
    data = r.json()['d']
    return util.make_json_success(data=data)

def lulebo_direct_start(session_id):
    r = LuleboApi.MV.directStartObject(session_id)
    data = r.json()['d']
    return util.make_json_success(data=data)
    
    
    


# ==============================================================================
# === Lulebo -- Authenticated
# ==============================================================================

@backend_api.route('/lulebo/login')
@login_required
def lulebo_auth_login():
    return lulebo_login(current_user)

@backend_api.route('/lulebo/session-info')
@login_required
def lulebo_auth_session_info():
    return lulebo_session_info(current_user.lulebo_session_id)

@backend_api.route('/lulebo/site-info')
@login_required
def lulebo_auth_site_info():
    return lulebo_site_info(current_user.lulebo_session_id)

@backend_api.route('/lulebo/object-info')
@login_required
def lulebo_auth_object_info():
    return lulebo_object_info(current_user.lulebo_session_id)

@backend_api.route('/lulebo/object-status')
@login_required
def lulebo_auth_object_status():
    return lulebo_object_status(current_user.lulebo_session_id)

@backend_api.route('/lulebo/direct-start')
@login_required
def lulebo_auth_direct_start():
    return lulebo_direct_start(current_user.lulebo_session_id)





# ==============================================================================
# === Lulebo -- Unauthenticated
# ==============================================================================

@backend_api.route('/u/<uuid:user_uuid>/login')
def lulebo_unauth_login(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    return lulebo_login(user)

@backend_api.route('/u/<uuid:user_uuid>/session-info')
@util.lulebo_retry_unauth
def lulebo_unauth_session_info(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    return lulebo_session_info(user.lulebo_session_id)

@backend_api.route('/u/<uuid:user_uuid>/site-info')
@util.lulebo_retry_unauth
def lulebo_unauth_site_info(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    return lulebo_site_info(user.lulebo_session_id)

@backend_api.route('/u/<uuid:user_uuid>/object-info')
@util.lulebo_retry_unauth
def lulebo_unauth_object_info(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    return lulebo_object_info(user.lulebo_session_id)

@backend_api.route('/u/<uuid:user_uuid>/object-status')
@util.lulebo_retry_unauth
def lulebo_unauth_object_status(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    return lulebo_object_status(user.lulebo_session_id)

@backend_api.route('/u/<uuid:user_uuid>/direct-start')
@util.lulebo_retry_unauth
def lulebo_unauth_direct_start(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    return lulebo_direct_start(user.lulebo_session_id)
