"""add scim fields

Revision ID: 15ae05f61e12
Revises: 9451e1b711f4
Create Date: 2024-01-01 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "15ae05f61e12"
down_revision = "9451e1b711f4"
branch_labels = None
depends_on = None


def upgrade():
    # Add SCIM fields to user table (nullable initially)
    op.add_column("user", sa.Column("scim_id", sa.String(length=36), nullable=True))
    op.add_column("user", sa.Column("external_id", sa.String(length=255), nullable=True))
    
    # Add SCIM fields to group table (nullable initially)
    op.add_column("group", sa.Column("scim_id", sa.String(length=36), nullable=True))
    op.add_column("group", sa.Column("external_id", sa.String(length=255), nullable=True))
    
    # Add SCIM fields to dataset table (nullable initially)
    op.add_column("dataset", sa.Column("scim_id", sa.String(length=36), nullable=True))
    op.add_column("dataset", sa.Column("external_id", sa.String(length=255), nullable=True))


def downgrade():
    # Remove indexes
    op.drop_index("ix_dataset_external_id", table_name="dataset")
    op.drop_index("ix_dataset_scim_id", table_name="dataset")
    op.drop_index("ix_group_external_id", table_name="group")
    op.drop_index("ix_group_scim_id", table_name="group")
    op.drop_index("ix_user_external_id", table_name="user")
    op.drop_index("ix_user_scim_id", table_name="user")

    # Remove columns
    op.drop_column("dataset", "external_id")
    op.drop_column("dataset", "scim_id")
    op.drop_column("group", "external_id")
    op.drop_column("group", "scim_id")
    op.drop_column("user", "external_id")
    op.drop_column("user", "scim_id")
