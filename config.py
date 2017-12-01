import os

from base64 import urlsafe_b64encode

basedir = os.path.abspath(os.path.dirname(__file__))

def gen_db_path(db_name):
    return 'sqlite:///' + os.path.join(basedir, db_name) + '.db'

WTF_CSRF_ENABLED = False

# Change and place in untracked file on prod server!
SECRET_KEY = 'very-secret'
LULEBO_SECRET_KEY = urlsafe_b64encode(b'very-secret                     ')

WEB_PORT_BACKEND  = 8081
WEB_PORT_FRONTEND = 8080
#DB_PORT  = 28015
DEBUG_MODE = False

LOG_FILE = ''
LOG_LEVEL = 'info'

SQLALCHEMY_DATABASE_URI = gen_db_path('app')
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')

# To disable warning about "significant overhead added by this feature".
SQLALCHEMY_TRACK_MODIFICATIONS = False
