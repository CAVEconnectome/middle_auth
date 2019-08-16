from flask import Flask

app = Flask(__name__)

from flask_session import Session
from flask_cors import CORS

from .server import mod, db
from .model import User, APIKey
from werkzeug.contrib.fixers import ProxyFix
import redis # used in the envvar config

# from flask_migrate import Migrate

__version__ = '0.0.30'


def setup_app():
    app.config.from_envvar('AUTH_CONFIG_SETTINGS')
    Session(app)
    CORS(app, expose_headers=['WWW-Authenticate', 'X-Requested-With'])

    app.wsgi_app = ProxyFix(app.wsgi_app)

    with app.app_context():
        db.init_app(app)
        # migrate = Migrate(app, db)

        existing_admin = User.get_by_email("chris@eyewire.org")

        if not existing_admin:
            User.create_account("chris@eyewire.org", "chris", admin=True, group_names=["default"])

        APIKey.load_into_cache()

    app.register_blueprint(mod)

    return app
