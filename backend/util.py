import collections
import json
import uuid
import werkzeug

from flask import Response

def make_auth_challenge(msg='Authentication required'):
    status_code = 401
    headers =  {'WWW-Authenticate': 'Basic realm="Login Required"'}
    return Response(msg, status_code, headers)

def make_json_error(msg='', status_code=400, error_code=''):
    response = {
        'status'     : 'error',
        'msg'        : msg,
    }

    if error_code is not None and error_code != '':
        response['error_code'] = error_code

    # return jsonify(response), status_code
    return json.dumps(response), status_code

def make_json_success(data=None, msg='', status_code=200, error_code=''):
    # TODO: make_json_success(msg='', data=None, status_code=200, error_code='')
    response = {
            'status': 'ok',
            'msg'   : msg,
        }

    if error_code is not None and error_code != '':
        response['error_code'] = error_code

    if data is not None:
        response['data'] = data

    # return jsonify(response), status_code
    return json.dumps(response), status_code

def parse_request_to_json(req):
    args = req.get_json()
    args = collections.defaultdict(lambda:None, **args) if args is not None else collections.defaultdict(lambda:None)
    return args

def html_escape_or_none(item):
    return werkzeug.utils.escape(item).strip() if item is not None else None





# ==============================================================================
# === Lulebo-local
# ==============================================================================

from backend import db

from backend.models import User
from backend.models import UserNotFoundError

from luleboapi import LuleboApi
from luleboapi import LuleboApiError
from luleboapi import LuleboApiLoginError

def lulebo_retry_unauth(func):
    '''
    Takes a `lulebo_unauth_xxx` endpoint function and ensures a retry if the
    stored session id is non-exitant or stale.

    A `lulebo_unauth_xxx` is a function that takes a user uuid and returns a
    lulebo response json object with the, for this function relevant, property
    that key `response.d.loginStatus` is defined. A value of `"zilch"` for this
    key indicated that unauthenticated access was done and this decorated then
    retries the original function after attempting to log in one.

    Arguments:
    - func -- a `lulebo_unauth_xxx` or compatible function
    '''

    def f(user_uuid):
        json_str, status_code = func(user_uuid)
        json_obj = json.loads(json_str)

        if json_obj['data']['loginStatus'] == 'zilch':
            user = User.get_by_uuid(str(user_uuid))
            lulebo_login(user)
            return func(user_uuid)
        return json_str, status_code
    f.__name__=func.__name__
    return f

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
        return make_json_error(
            msg='Lulebo authentication failed with message {}'.format(e.msg),
            error_code='login-1'
        )

    user.lulebo_session_id = session_id

    try:
        db.session.add(user)
        db.session.commit()
        db.session.close()
        return make_json_success('Logged in to LuleboAPI')
    except Exception as e:
        db.session.rollback()
        db.session.close()
        return make_json_error('Lulebo authentication failed', error_code='login-2')

def lulebo_session_info(session_id):
    r = LuleboApi.Session.getSessionStatus(session_id)
    data = r.json()['d']
    return data

def lulebo_site_info(session_id):
    r = LuleboApi.MV.getSiteInfo(session_id)
    data = r.json()['d']
    return data

def lulebo_object_info(session_id):
    r = LuleboApi.MV.getObjectInfo(session_id)
    data = r.json()['d']
    return data

def lulebo_object_status(session_id):
    r = LuleboApi.MV.queryObjectStatus(session_id)
    data = r.json()['d']
    return data

def lulebo_direct_start(session_id):
    r = LuleboApi.MV.directStartObject(session_id)
    data = r.json()['d']
    return data





# ==============================================================================
# === Database
# ==============================================================================

from backend import models as user_models

def add_user(db, user):
    '''Add a user to the database
    '''

    username        = user['username']
    password        = user['password']
    email           = user['email']
    lulebo_username = user['lulebo_username']
    lulebo_password = user['lulebo_password']

    print ('Add user ' + username + '')
    try:
        user_models.User.get_by_name(username)
        print ('\tSkipping -- user _does_ exist.')
        return False
    except user_models.UserNotFoundError:
        pass

    try:
        u = user_models.User(
            username=username,
            password=password,
            email=email,
            uuid=str(uuid.uuid4()),
            lulebo_username=lulebo_username,
            lulebo_password=lulebo_password
        )
        db.session.add(u)
        db.session.commit()
    except Exception as e:
        print (e)
        print ('\tSkipping -- unknown error.')
        return False

    return True