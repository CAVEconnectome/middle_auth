from .user import User
from .base import db, r

import json
import secrets

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    key = db.Column(db.String(32), unique=True, nullable=False)

    # load api keys into cache if they don't already exist in redis
    # i.e. new deployment or some redis failure
    @staticmethod
    def load_into_cache():
        api_keys = APIKey().query.all()

        for api_key in api_keys:
            user = User.get_by_id(api_key.user_id)
            r.set("token_" + api_key.key, json.dumps(user.create_cache()), nx=True)
    
    @staticmethod
    def generate(user_id):
        entry = APIKey.query.filter_by(user_id=user_id).first()

        new_entry = not entry

        if new_entry:
            entry = APIKey(user_id=user_id, key="")

        user = User.get_by_id(user_id)
        user_json = json.dumps(user.create_cache())
        token = insert_and_generate_unique_token(user_id, user_json)

        if not new_entry:
            delete_token(user_id, entry.key)

        entry.key = token

        if new_entry:
            db.session.add(entry)

        db.session.commit()

        return token

def insert_and_generate_unique_token(user_id, value, ex=None):
    token = None

    # keep trying to insert a random token into redis until it finds one that is not already in use
    while True:
        token = secrets.token_hex(16)
        # nx = Only set the key if it does not already exist
        not_dupe = r.set("token_" + token, value, nx=True, ex=ex)

        if not_dupe:
            break

    r.sadd("userid_" + str(user_id), token)

    return token

def delete_token(user_id, token):
    p = r.pipeline()
    p.delete("token_" + token)
    p.srem("userid_" + str(user_id), token)
    p.execute()