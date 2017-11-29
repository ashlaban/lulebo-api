import collections
import json
import werkzeug

from flask import Response

def make_auth_challenge(msg='Authentication required'):
    status_code = 401
    headers =  {'WWW-Authenticate': 'Basic realm="Login Required"'}
    return Response(msg, status_code, headers)

def make_json_error(msg='', status_code=400, error_code=''):
    response = {
        'status'     : 'error',
        'error_code' : error_code,
        'msg'        : msg,
    }

    # return jsonify(response), status_code
    return json.dumps(response), status_code

def make_json_success(data=None, msg='', status_code=200, error_code=''):
    # TODO: make_json_success(msg='', data=None, status_code=200, error_code='')
    response = {
            'status': 'ok',
            'msg'   : msg,
        }

    if error_code is not '':
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