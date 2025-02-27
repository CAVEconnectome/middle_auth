from .base import db
from .dataset import Dataset
from .group import Group
from .permission import Permission


class GroupDatasetPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    group_id = db.Column(
        "group_id", db.Integer, db.ForeignKey("group.id"), nullable=False
    )
    dataset_id = db.Column(
        "dataset_id", db.Integer, db.ForeignKey("dataset.id"), nullable=False
    )
    permission_id = db.Column(
        "permission_id", db.Integer, db.ForeignKey("permission.id"), nullable=False
    )
    __table_args__ = (db.UniqueConstraint("group_id", "dataset_id", "permission_id"),)

    @staticmethod
    def add(group_id, dataset_id, permission_ids=[]):
        for permission_id in permission_ids:
            gd = GroupDatasetPermission(
                group_id=group_id, dataset_id=dataset_id, permission_id=permission_id
            )
            db.session.add(gd)
        db.session.commit()
        group = Group.get_by_id(group_id)
        group.update_cache()

    @staticmethod
    def remove(group_id, dataset_id, permission_id):
        GroupDatasetPermission.query.filter_by(
            group_id=group_id, dataset_id=dataset_id, permission_id=permission_id
        ).delete()
        db.session.commit()
        Group.get_by_id(group_id).update_cache()

    @staticmethod
    def get_groups_by_dataset(dataset_id):
        query = db.session.query(Group).join(
            GroupDatasetPermission,
            GroupDatasetPermission.group_id == GroupDatasetPermission.group_id,
        )

        return query.distinct()

    @staticmethod
    def get_permissions_for_group(group_id):
        query = (
            db.session.query(
                GroupDatasetPermission.dataset_id,
                Dataset.name,
                Permission.name,
                Permission.id,
            )
            .join(Dataset, Dataset.id == GroupDatasetPermission.dataset_id)
            .join(Permission, Permission.id == GroupDatasetPermission.permission_id)
            .filter(GroupDatasetPermission.group_id == group_id)
            .order_by(GroupDatasetPermission.dataset_id.asc(), Permission.id.asc())
        )

        permissions = query.all()

        return [
            {
                "id": dataset_id,
                "name": dataset_name,
                "permission": permission_name,
                "permission_id": permission_id,
            }
            for dataset_id, dataset_name, permission_name, permission_id in permissions
        ]

    @staticmethod
    def get_all_group_permissions(dataset_id):
        query = (
            db.session.query(
                GroupDatasetPermission.group_id,
                Group.name,
                Permission.name,
                Permission.id,
            )
            .join(Group, Group.id == GroupDatasetPermission.group_id)
            .join(Permission, Permission.id == GroupDatasetPermission.permission_id)
            .filter(GroupDatasetPermission.dataset_id == dataset_id)
            .order_by(GroupDatasetPermission.group_id.asc(), Permission.id.asc())
        )

        permissions = query.all()

        return [
            {
                "id": group_id,
                "name": group_name,
                "permission": permission_name,
                "permission_id": permission_id,
            }
            for group_id, group_name, permission_name, permission_id in permissions
        ]
