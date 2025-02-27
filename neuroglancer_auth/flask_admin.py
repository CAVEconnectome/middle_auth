import os

import flask
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from middle_auth_client import auth_required

from .model.affiliation import Affiliation, UserAffiliation
from .model.app import App
from .model.cell_temp import CellTemp
from .model.dataset import Dataset
from .model.group import Group
from .model.permission import Permission
from .model.table_mapping import ServiceTable
from .model.tos import Tos
from .model.user import User

TOKEN_NAME = os.environ.get("TOKEN_NAME", "middle_auth_token")


class SuperAdminView(ModelView):
    can_export = True

    def is_accessible(self):
        @auth_required
        def helper():
            return True

        return helper() and flask.g.get("auth_user", {}).get("admin", False)

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return flask.redirect(flask.url_for("admin.index"))


# Create customized index view class that handles login & registration
class MyAdminIndexView(AdminIndexView):
    @expose("/", methods=["GET"])
    @auth_required
    def index(self):
        return super(MyAdminIndexView, self).index()

    def is_accessible(self):
        return True


def setup_admin(app, db):
    admin = Admin(
        app,
        name="middle auth admin",
        index_view=MyAdminIndexView(url="/sticky_auth/flask_admin"),
        template_mode="bootstrap4",
    )

    SuperAdminView.column_searchable_list = ("name",)
    SuperAdminView.column_filters = ("admin", "gdpr_consent", "pi", "read_only")
    admin.add_view(SuperAdminView(User, db.session))
    SuperAdminView.column_filters = ()

    admin.add_view(SuperAdminView(Group, db.session))
    SuperAdminView.column_searchable_list = ()

    admin.add_view(SuperAdminView(Affiliation, db.session))
    admin.add_view(SuperAdminView(UserAffiliation, db.session))
    admin.add_view(SuperAdminView(Dataset, db.session))
    admin.add_view(SuperAdminView(Permission, db.session))
    admin.add_view(SuperAdminView(Tos, db.session))
    admin.add_view(SuperAdminView(CellTemp, db.session))

    SuperAdminView.column_searchable_list = ("dataset_id", "service_name", "table_name")
    SuperAdminView.column_filters = ("dataset_id",)
    admin.add_view(SuperAdminView(ServiceTable, db.session))
    SuperAdminView.column_searchable_list = ()
    SuperAdminView.column_filters = ()

    admin.add_view(SuperAdminView(App, db.session))
    return admin
