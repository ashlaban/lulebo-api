import collections
import json
import werkzeug

def make_json_error(msg='', error_code=400):
    response = {
        'status': 'error',
        'msg'   : msg,
    }
    return json.dumps(response), error_code

def make_json_success(data=None, msg=''):
    response = {
            'status': 'ok',
            'msg'   : msg,
        }

    if data is not None:
        response['data'] = data

    return json.dumps(response)

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