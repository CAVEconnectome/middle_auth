# import json
# import secrets
import os

import redis
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

r = redis.Redis(
    host=os.environ.get("REDISHOST", "localhost"),
    port=int(os.environ.get("REDISPORT", 6379)),
)
