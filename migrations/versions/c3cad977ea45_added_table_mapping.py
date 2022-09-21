"""added table mapping

Revision ID: c3cad977ea45
Revises: a489357589a6
Create Date: 2022-03-16 18:06:04.435658

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3cad977ea45'
down_revision = 'a489357589a6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('service_table',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('service_name', sa.String(length=120), nullable=False),
    sa.Column('table_name', sa.String(length=120), nullable=False),
    sa.Column('dataset_id', sa.Integer(), nullable=False),
    sa.Column('contact_name', sa.String(length=120), nullable=False),
    sa.Column('contact_email', sa.String(length=120), nullable=False),
    sa.ForeignKeyConstraint(['dataset_id'], ['dataset.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('service_name', 'table_name')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('service_table')
    # ### end Alembic commands ###