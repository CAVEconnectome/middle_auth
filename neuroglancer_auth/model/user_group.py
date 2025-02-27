from .base import db
from .user import User


class UserGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column("user_id", db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(
        "group_id", db.Integer, db.ForeignKey("group.id"), nullable=False
    )
    admin = db.Column("admin", db.Boolean, server_default="0", nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "group_id"),)

    @staticmethod
    def get(group_id, user_id):
        return UserGroup.query.filter_by(group_id=group_id, user_id=user_id).first()

    @staticmethod
    def is_group_admin(user_id, group_id):
        query = UserGroup.query.filter_by(
            user_id=user_id, group_id=group_id, admin=True
        ).exists()
        return db.session.query(query).scalar()

    @staticmethod
    def is_group_admin_any(user_id):
        query = UserGroup.query.filter_by(user_id=user_id, admin=True).exists()
        return db.session.query(query).scalar()

    @staticmethod
    def add(user_id, group_id, admin=False):
        ug = UserGroup(user_id=user_id, group_id=group_id, admin=admin)
        db.session.add(ug)
        db.session.commit()
        user = User.get_by_id(user_id)
        user.update_cache()

    @staticmethod
    def get_users(group_id):
        users = (
            db.session.query(User)
            .filter(UserGroup.user_id == User.id)
            .filter(UserGroup.group_id == group_id)
            .all()
        )

        return users

    @staticmethod
    def get_member_list(group_id):
        users = (
            db.session.query(UserGroup.user_id, User.name, UserGroup.admin)
            .filter(UserGroup.user_id == User.id)
            .filter(UserGroup.group_id == group_id)
            .filter(User.parent_id.is_(None))
            .all()
        )

        return [
            {"id": user_id, "name": name, "admin": admin}
            for user_id, name, admin in users
        ]

    @staticmethod
    def get_service_accounts(group_id):
        users = (
            db.session.query(UserGroup.user_id, User.name)
            .filter(UserGroup.user_id == User.id)
            .filter(UserGroup.group_id == group_id)
            .filter(User.parent_id.isnot(None))
            .all()
        )

        return [{"id": user_id, "name": name} for user_id, name in users]

    @staticmethod
    def get_admins(group_id):
        users = (
            db.session.query(UserGroup.user_id, User.name)
            .filter(UserGroup.admin == True)
            .filter(UserGroup.user_id == User.id)
            .filter(UserGroup.group_id == group_id)
            .all()
        )

        return [{"id": user_id, "name": name} for user_id, name in users]

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        User.get_by_id(self.user_id).update_cache()

    def update(self, data):
        if "admin" in data:
            self.admin = data["admin"]

        db.session.commit()
