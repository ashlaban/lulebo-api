import os
from flask import Flask

import wtforms_json
wtforms_json.init()

frontend = Flask(__name__)
frontend.config.from_object('config')

from frontend import views
