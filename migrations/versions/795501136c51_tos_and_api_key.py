"""tos_and_api_key

Revision ID: 795501136c51
Revises: 2276d0c90076
Create Date: 2021-06-29 23:17:20.690810

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '795501136c51'
down_revision = '2276d0c90076'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('tos',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('linkText', sa.Text(), nullable=False),
    sa.Column('created', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_tos',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('tos_id', sa.Integer(), nullable=False),
    sa.Column('created', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.ForeignKeyConstraint(['tos_id'], ['tos.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'tos_id')
    )
    op.add_column('api_key', sa.Column('created', sa.DateTime(), server_default=sa.text('now()'), nullable=True))
    op.add_column('api_key', sa.Column('updated', sa.DateTime(), server_default=sa.text('now()'), nullable=True))
    op.drop_constraint('api_key_user_id_key', 'api_key', type_='unique')
    op.add_column('dataset', sa.Column('tos_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_dataset_tos_id', 'dataset', 'tos', ['tos_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('fk_dataset_tos_id', 'dataset', type_='foreignkey')
    op.drop_column('dataset', 'tos_id')
    op.create_unique_constraint('api_key_user_id_key', 'api_key', ['user_id'])
    op.drop_column('api_key', 'updated')
    op.drop_column('api_key', 'created')
    op.drop_table('user_tos')
    op.drop_table('tos')
    # ### end Alembic commands ###