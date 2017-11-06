import os
basedir = os.path.abspath(os.path.dirname(__file__))

WTF_CSRF_ENABLED = False

#Change and place in untracked file on prod server!
SECRET_KEY = 'very-secret'

WEB_PORT_BACKEND  = 8081
WEB_PORT_FRONTEND = 8080
#DB_PORT  = 28015
DEBUG_MODE = False

LOG_FILE = ''
LOG_LEVEL = 'info'

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

# To disable warning about "significant overhead added by this feature".
SQLALCHEMY_TRACK_MODIFICATIONS = False
