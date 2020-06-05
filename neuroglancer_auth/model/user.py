from .base import db, r

import json
from sqlalchemy.sql import func

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), unique=False, nullable=False) # public
    email = db.Column(db.String(120), unique=True, nullable=False) # public + affiliation
    admin = db.Column(db.Boolean, server_default="0", nullable=False)
    gdpr_consent = db.Column(db.Boolean, server_default="0", nullable=False)
    pi = db.Column(db.String(80), server_default="", nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    parent_id = db.Column('parent_id', db.Integer, db.ForeignKey("user.id"), nullable=True)
    read_only = db.Column(db.Boolean, server_default="0", nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "service_account": self.parent_id is not None,
            "parent_id": self.parent_id,
            "read_only": self.read_only,
            "name": self.name,
            "email": self.email,
            "admin": self.admin,
            "pi": self.pi,
            "gdpr_consent": self.gdpr_consent,
            "admin_datasets": self.get_datasets_adminning()
        }

    @staticmethod
    def create_account(email, name, pi, admin=False, gdpr_consent=False, group_names=[], parent_id=None):
        from .user_group import UserGroup
        from .group import Group

        user = User(name=name, email=email, admin=admin, pi=pi, gdpr_consent=gdpr_consent, parent_id=parent_id)
        db.session.add(user)
        db.session.flush() # get inserted id

        groups = Group.query.filter(Group.name.in_(group_names)).all()

        for group in groups:
            db.session.add(UserGroup(user_id=user.id, group_id=group.id))

        db.session.commit()
        return user

    @staticmethod
    def get_by_id(id):
        return User.query.filter_by(id=id).first()
    
    @staticmethod
    def get_by_parent(id):
        return User.query.filter_by(parent_id=id).first()
    
    @staticmethod
    def get_normal_accounts():
        return User.query.filter(User.parent_id.is_(None)).order_by(User.id.asc()).all()

    @staticmethod
    def get_service_accounts():
        return User.query.filter(User.parent_id.isnot(None)).order_by(User.id.asc()).all()
    
    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def filter_by_ids(ids):
        return User.query.filter(User.id.in_(ids)).all()

    @staticmethod
    def search_by_email(email):
        return User.query.filter(User.email.ilike(f'%{email}%')).all()

    @staticmethod
    def search_by_name(name):
        return User.query.filter(User.parent_id.is_(None)).filter(User.name.ilike(f'%{name}%')).all()
    
    @staticmethod
    def sa_search_by_name(name):
        return User.query.filter(User.parent_id.isnot(None)).filter(User.name.ilike(f'%{name}%')).all()

    def update(self, data):
        user_fields = ['admin', 'name', 'pi', 'gdpr_consent', 'read_only']

        for field in user_fields:
            if field in data:
                setattr(self, field, data[field])

        db.session.commit()
        self.update_cache()

    def get_groups(self):
        # move to UserGroup
        from .group import Group
        from .user_group import UserGroup

        query = db.session.query(Group.id, Group.name)\
            .join(UserGroup, UserGroup.group_id == Group.id)\
            .filter(UserGroup.user_id == self.id)

        groups = query.all()

        return [{'id': id, 'name': name} for id, name in groups]

    def get_permissions(self):
        # messy dependencies, not sure if it should be moved
        from .group_dataset import GroupDataset
        from .dataset import Dataset
        from .user_group import UserGroup

        query = db.session.query(GroupDataset.dataset_id, Dataset.name, func.max(GroupDataset.level))\
            .join(UserGroup, UserGroup.group_id == GroupDataset.group_id)\
            .join(Dataset, Dataset.id == GroupDataset.dataset_id)\
            .filter(UserGroup.user_id == self.id)\
            .group_by(UserGroup.user_id, GroupDataset.dataset_id, Dataset.name)
        
        permissions = query.all()
        
        return [{'id': dataset_id, 'name': dataset_name, 'level': level} for dataset_id, dataset_name, level in permissions]

    def get_datasets_adminning(self):
        # move to DatasetAdmin
        from .dataset_admin import DatasetAdmin
        from .dataset import Dataset

        query = db.session.query(DatasetAdmin.dataset_id, Dataset.name)\
            .join(Dataset, DatasetAdmin.dataset_id == Dataset.id)\
            .filter(DatasetAdmin.user_id == self.id)
        
        datasets = query.all()
        
        return [{'id': dataset_id, 'name': dataset_name} for dataset_id, dataset_name in datasets]

    def create_cache(self):
        return {
            'id': self.id,
            "service_account": self.parent_id is not None,
            "parent_id": self.parent_id,
            'name': self.name,
            'email': self.email,
            'admin': self.admin,
            'groups': [x['name'] for x in self.get_groups()],
            'permissions': {x['name']: x['level'] for x in self.get_permissions()},
        }

    def update_cache(self):
        user_json = json.dumps(self.create_cache())

        tokens = r.smembers("userid_" + str(self.id))

        for token_bytes in tokens:
            token = token_bytes.decode('utf-8')
            ttl = r.ttl("token_" + token) # update token without changing ttl

            if ttl == -2: # doesn't exist (expired)
                r.srem("userid_" + str(self.id), token)
            else:
                ttl = ttl if ttl != -1 else None # -1 is no expiration (API KEYS)
                r.set("token_" + token, user_json, nx=False, ex=ttl)
