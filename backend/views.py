from flask import session, request, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from backend import backend, db, lm
from .models import User

from backend import util
from backend.models import UserNotFoundError

import werkzeug
import sqlalchemy

from luleboapi import LuleboApi






# ==============================================================================
# === Authentication
# ==============================================================================

@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

@backend.route('/api/signup', methods=['POST'])
def api_signup():
    json_data = request.json
    user = User(
        username = json_data['uesrname'],
        email    = json_data['email'],
        password = json_data['password']
    )
    try:
        db.session.add(user)
        db.session.commit()
        msg = 'success'
        status = 'ok'
    except:
        msg = 'this user is already registered'
        status = 'error'
    db.session.close()
    return jsonify({'msg': msg, 'status': status})

@backend.route('/api/login', methods=['POST'])
def login():
    args = util.parse_request_to_json(request)
    form = LoginForm.from_json(args)

    if not form.validate():
        return util.make_json_error(msg=form.getErrors())
    
    user = User.get_by_name(form.username.data)
    login_user(user)
    return util.make_json_success(msg='Welcome.')
    
@login_required
@backend.route('/logout')
def logout():
    logout_user()
    return util.make_json_success(msg='Logged out')






# ==============================================================================
# === Lulebo
# ==============================================================================

@backend.route('/api/lulebo/login')
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

@backend.route('/api/lulebo/object-info')
def lulebo_object_info():
    return lulebo_simple_forward('getObjectInfo')

@backend.route('/api/lulebo/object-status')
def lulebo_object_status():
    return lulebo_simple_forward('queryObjectStatus')

@backend.route('/api/lulebo/direct-start')
def lulebo_direct_start():
    return lulebo_simple_forward('directStartObject')


