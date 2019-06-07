from flask import Flask

app = Flask(__name__)

from flask_session import Session
from flask_cors import CORS

from .server import mod, db, load_api_keys
from .model import create_account, User
from werkzeug.contrib.fixers import ProxyFix
import redis # used in the envvar config

__version__ = '0.0.27'


def setup_app():
    app.config.from_envvar('AUTH_CONFIG_SETTINGS')
    Session(app)
    CORS(app, expose_headers='WWW-Authenticate')

    app.wsgi_app = ProxyFix(app.wsgi_app)

    with app.app_context():
        db.init_app(app)
        db.create_all()

        existing_admin = User.get({"email": "chris@eyewire.org"})

        if not existing_admin:
            create_account("chris@eyewire.org", "chris", role_names=["admin", "edit_all"])

        load_api_keys()
    
    app.register_blueprint(mod)

    return app
