"""empty message

Revision ID: 9d0b1a1244a3
Revises: d2af19a46c73
Create Date: 2022-04-09 15:26:27.463717

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9d0b1a1244a3'
down_revision = 'd2af19a46c73'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('film_info', sa.Column('score', sa.Float(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('film_info', 'score')
    # ### end Alembic commands ###
