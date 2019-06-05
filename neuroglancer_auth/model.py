from flask_sqlalchemy import SQLAlchemy, event

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

# initial data for roles
def insert_default_roles(target, connection, **kw):
    db.session.add(Role(name="admin"))
    db.session.add(Role(name="edit_all"))
    db.session.commit()

event.listen(Role.__table__, 'after_create', insert_default_roles)

class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
    role_id = db.Column('role_id', db.Integer, db.ForeignKey("role.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "role_id"),)

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    key = db.Column(db.String(32), unique=True, nullable=False)
