from .base import db
from .dataset import Dataset

from flask_sqlalchemy import event

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "name": self.name,
        }

    @staticmethod
    def get_by_id(id):
        return Group.query.filter_by(id=id).first()

    @staticmethod
    def search_by_name(name):
        if name:
            return Group.query.filter(Group.name.ilike(f'%{name}%')).all()
        else:
            return Group.query.order_by(Group.id.asc()).all()

    @staticmethod
    def add(name):
        group = Group(name=name)
        db.session.add(group)
        db.session.commit()
        return group

    def update_cache(self):
        # move to UserGroup
        from .user import User
        from .user_group import UserGroup
        from .service_account import ServiceAccount
        from .service_account_group import ServiceAccountGroup

        users = UserGroup.get_users(self.id)

        for user in users:
            User.get_by_id(user["id"]).update_cache()
        
        service_accounts = ServiceAccountGroup.get_users(self.id)

        for sa in service_accounts:
            ServiceAccount.get_by_id(sa["id"]).update_cache()

def insert_default_groups(target, connection, **kw):
    db.session.add(Group(name="default"))
    db.session.commit()

event.listen(Group.__table__, 'after_create', insert_default_groups)
