import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import basedir

backend = Flask(__name__)
backend.config.from_object('config')
db = SQLAlchemy(backend)

lm = LoginManager()
lm.init_app(backend)
lm.login_view = 'login'

# Register blueprint(s)
# from backend.profile.controllers  import profile     as profile_mod
# backend.register_blueprint(modules_mod)


from backend import views, models
