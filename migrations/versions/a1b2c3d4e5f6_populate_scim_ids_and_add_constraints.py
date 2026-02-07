"""populate scim ids and add constraints

Revision ID: a1b2c3d4e5f6
Revises: 15ae05f61e12
Create Date: 2024-01-02 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# Import from utils to avoid duplicating the UUID namespace
from neuroglancer_auth.scim.utils import generate_scim_id

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "15ae05f61e12"
branch_labels = None
depends_on = None


def upgrade():
    # Populate scim_id for existing records using deterministic UUID5
    # Use raw SQL to avoid model import issues during migration
    connection = op.get_bind()
    
    # Populate user scim_id
    users = connection.execute(sa.text("SELECT id FROM user WHERE scim_id IS NULL"))
    for (user_id,) in users:
        scim_id = generate_scim_id(user_id, "User")
        connection.execute(
            sa.text("UPDATE user SET scim_id = :scim_id WHERE id = :id"),
            {"scim_id": scim_id, "id": user_id}
        )
    
    # Populate group scim_id
    groups = connection.execute(sa.text("SELECT id FROM group WHERE scim_id IS NULL"))
    for (group_id,) in groups:
        scim_id = generate_scim_id(group_id, "Group")
        connection.execute(
            sa.text("UPDATE group SET scim_id = :scim_id WHERE id = :id"),
            {"scim_id": scim_id, "id": group_id}
        )
    
    # Populate dataset scim_id
    datasets = connection.execute(sa.text("SELECT id FROM dataset WHERE scim_id IS NULL"))
    for (dataset_id,) in datasets:
        scim_id = generate_scim_id(dataset_id, "Dataset")
        connection.execute(
            sa.text("UPDATE dataset SET scim_id = :scim_id WHERE id = :id"),
            {"scim_id": scim_id, "id": dataset_id}
        )
    
    # Create indexes after populating data (ensures uniqueness)
    op.create_index("ix_user_scim_id", "user", ["scim_id"], unique=True)
    op.create_index("ix_user_external_id", "user", ["external_id"])
    op.create_index("ix_group_scim_id", "group", ["scim_id"], unique=True)
    op.create_index("ix_group_external_id", "group", ["external_id"])
    op.create_index("ix_dataset_scim_id", "dataset", ["scim_id"], unique=True)
    op.create_index("ix_dataset_external_id", "dataset", ["external_id"])
    
    # Make scim_id columns NOT NULL after populating all records
    # Note: external_id remains nullable as it's optional
    #op.alter_column("user", "scim_id", nullable=False)
    #op.alter_column("group", "scim_id", nullable=False)
    #op.alter_column("dataset", "scim_id", nullable=False)


def downgrade():
    # Make scim_id columns nullable again
    #op.alter_column("dataset", "scim_id", nullable=True)
    #op.alter_column("group", "scim_id", nullable=True)
    #op.alter_column("user", "scim_id", nullable=True)
    
    # Remove indexes
    op.drop_index("ix_dataset_external_id", table_name="dataset")
    op.drop_index("ix_dataset_scim_id", table_name="dataset")
    op.drop_index("ix_group_external_id", table_name="group")
    op.drop_index("ix_group_scim_id", table_name="group")
    op.drop_index("ix_user_external_id", table_name="user")
    op.drop_index("ix_user_scim_id", table_name="user")
    
    # Note: We don't clear scim_id values in downgrade - they remain in the database
    # but become nullable again
