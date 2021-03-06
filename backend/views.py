from flask import session, request, jsonify, Blueprint
from flask_login import login_user, logout_user, current_user, login_required

from backend import db
from backend import lm
from backend import util

from backend.models import User
from backend.models import UserNotFoundError

import base64
import sqlalchemy
import uuid
import werkzeug

from werkzeug.wrappers import AuthorizationMixin





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

    # Optional
    try   : lulebo_username = json_data['lulebo_username']
    except: lulebo_username = None
    try   : lulebo_password = json_data['lulebo_password']
    except: lulebo_password = None

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
        lulebo_username = lulebo_username if lulebo_username is not None else '',
        lulebo_password = lulebo_password if lulebo_password is not None else '',
        uuid = str(uuid.uuid4())
    )

    try:
        db.session.add(user)
        db.session.commit()
        msg, status = 'Success', 'ok'
    except Exception as e:
        db.session.rollback()
        msg, status = 'unknown error', 'error'
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
@backend_api.route('/u', methods=['GET'])
@login_required
def user_info_get():
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
        'username'       : current_user.username,
        'email'          : current_user.email,
        'lulebo_username': current_user.lulebo_username,
        'lulebo_password': current_user.lulebo_password,
        'uuid'           : current_user.uuid
    }

    return util.make_json_success(msg='', data=data)

@backend_api.route('/u', methods=['PATCH'])
@login_required
def user_info_update():
    json_data = request.get_json()

    ## TODO: If json_data is not dict, error
    print(json_data)

    try   : current_user.email = json_data['email']
    except: pass
    try   : current_user.lulebo_username = json_data['lulebo_username']
    except: pass
    try   : current_user.lulebo_password = json_data['lulebo_password']
    except: pass

    try   : password        = json_data['password']
    except: password        = None
    try   : passvalid       = json_data['passvalid']
    except: passvalid       = None

    if password is not None:
        if password == passvalid:
            current_user.password = password
        else:
            return util.make_json_error(msg='Passwords don\'t match')

    print('=== CURRENT USER ===')
    print(current_user.username)
    print(current_user.password)
    print(current_user.email)
    print(current_user.lulebo_username)
    print(current_user.lulebo_password)

    try:
        db.session.add(current_user)
        db.session.commit()
        msg, status = 'Success', 'ok'
    except Exception as e:
        db.session.rollback()
        msg, status = 'unknown error', 'error'
        print (e)
    db.session.close()
    return jsonify({'msg': msg, 'status': status})

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
# === Lulebo-local -- Authenticated
# ==============================================================================

@backend_api.route('/lulebo/login')
@login_required
def lulebo_auth_login():
    return util.lulebo_login(current_user)

@backend_api.route('/lulebo/session-info')
@login_required
def lulebo_auth_session_info():
    data = util.lulebo_session_info(current_user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/lulebo/site-info')
@login_required
def lulebo_auth_site_info():
    data = util.lulebo_site_info(current_user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/lulebo/object-info')
@login_required
def lulebo_auth_object_info():
    data = util.lulebo_object_info(current_user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/lulebo/object-status')
@login_required
def lulebo_auth_object_status():
    data = util.lulebo_object_status(current_user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/lulebo/direct-start')
@login_required
def lulebo_auth_direct_start():
    data = util.lulebo_direct_start(current_user.lulebo_session_id)
    return util.make_json_success(data=data)





# ==============================================================================
# === Lulebo-local -- Unauthenticated
# ==============================================================================

@backend_api.route('/u/<uuid:user_uuid>/login')
def lulebo_unauth_login(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    return util.lulebo_login(user)

@backend_api.route('/u/<uuid:user_uuid>/session-info')
@util.lulebo_retry_unauth
def lulebo_unauth_session_info(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    data = util.lulebo_session_info(user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/u/<uuid:user_uuid>/site-info')
@util.lulebo_retry_unauth
def lulebo_unauth_site_info(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    data = util.lulebo_site_info(user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/u/<uuid:user_uuid>/object-info')
@util.lulebo_retry_unauth
def lulebo_unauth_object_info(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    data = util.lulebo_object_info(user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/u/<uuid:user_uuid>/object-status')
@util.lulebo_retry_unauth
def lulebo_unauth_object_status(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    data = util.lulebo_object_status(user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/u/<uuid:user_uuid>/direct-start')
@util.lulebo_retry_unauth
def lulebo_unauth_direct_start(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    data = util.lulebo_direct_start(user.lulebo_session_id)
    return util.make_json_success(data=data)

@backend_api.route('/u/<uuid:user_uuid>/cord')
@util.lulebo_retry_unauth
def lulebo_unauth_cord(user_uuid):
    user = User.get_by_uuid(str(user_uuid))
    json = util.lulebo_object_status(user.lulebo_session_id)

    is_connected = json['IsConnected']
    data = dict(cordConnected=True if is_connected == '1' else False,
                loginStatus=json['loginStatus'])
    return util.make_json_success(data=data)
