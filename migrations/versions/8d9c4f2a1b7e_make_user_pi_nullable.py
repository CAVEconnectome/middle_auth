"""make user pi nullable

Revision ID: 8d9c4f2a1b7e
Revises: 9451e1b711f4
Create Date: 2023-12-31 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "8d9c4f2a1b7e"
down_revision = "9451e1b711f4"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "user",
        "pi",
        existing_type=sa.String(length=80),
        nullable=True,
    )


def downgrade():
    op.execute(sa.text('UPDATE "user" SET pi = \'\' WHERE pi IS NULL'))
    op.alter_column(
        "user",
        "pi",
        existing_type=sa.String(length=80),
        nullable=False,
    )
