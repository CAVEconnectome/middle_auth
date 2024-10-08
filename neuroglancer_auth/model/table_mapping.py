from .base import db

from sqlalchemy.orm import relationship

from .dataset import Dataset

class ServiceTable(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_name = db.Column(db.String(120), nullable=False)
    table_name = db.Column(db.String(120), nullable=False)
    dataset_id = db.Column('dataset_id', db.Integer, db.ForeignKey("dataset.id"), nullable=False)

    __table_args__ = (db.UniqueConstraint("service_name", "table_name"),)

    dataset = relationship(Dataset)

    def __repr__(self):
        return self.name

    @staticmethod
    def get_dataset_by_service_table(service, table):
        el = ServiceTable.query.filter_by(service_name=service, table_name=table).first()
        if el:
            return el.dataset.name

    @staticmethod
    def add(service_name, table_name, dataset):
        try:
            dataset = Dataset.search_by_name(dataset)[0]
        except IndexError:
            raise ValueError(f"{dataset} does not exist.")
        sta = ServiceTable(
            service_name=service_name, table_name=table_name, dataset_id=dataset.id
        )
        db.session.add(sta)
        db.session.commit()

    @staticmethod
    def remove(service_name, table_name, dataset):
        try:
            dataset = Dataset.search_by_name(dataset)[0]
        except IndexError:
            raise ValueError(f"{dataset} does not exist.")
        ServiceTable.query.filter_by(
            service_name=service_name, table_name=table_name, dataset_id=dataset.id
        ).delete()
        db.session.commit()

