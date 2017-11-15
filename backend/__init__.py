import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import basedir

db = SQLAlchemy()
lm = LoginManager()

# lm.login_view = 'login'

def create_app(config=None, name=__name__):
    app = Flask(name)
    app.config.from_object('config')

    if config is not None:
        for key in config:
            app.config[key] = config[key]

    app.register_blueprint(backend_api)

    db.init_app(app)
    lm.init_app(app)

    app.app_context().push()

    return app

# backend = create_app()

# Register blueprint(s)
# from backend.profile.controllers  import profile     as profile_mod
# backend.register_blueprint(modules_mod)

from backend import models
from .views  import backend_api
