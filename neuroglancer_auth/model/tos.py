# import json
from sqlalchemy.sql import func

from .base import db

# import sqlalchemy


class Tos(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    text = db.Column(db.Text, unique=False, nullable=False)
    created = db.Column(db.DateTime, server_default=func.now())
    updated = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

    def as_dict(self):
        res = {
            "id": self.id,
            "name": self.name,
            "text": self.text,
        }

        return res

    @staticmethod
    def get_by_id(id):
        return Tos.query.filter_by(id=id).first()

    @staticmethod
    def add(name, text):
        el = Tos(name=name, text=text)
        db.session.add(el)
        db.session.commit()
        return el

    def update(self, data):
        fields = ["name", "text"]

        for field in fields:
            if field in data:
                setattr(self, field, data[field])

        db.session.commit()

    @staticmethod
    def search_by_name(name):
        if name:
            return Tos.query.filter(Tos.name.ilike(f"%{name}%")).all()
        else:
            return Tos.query.order_by(Tos.id.asc()).all()
