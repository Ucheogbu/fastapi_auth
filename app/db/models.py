from sqlalchemy import Column, String, INTEGER, BOOLEAN
from .db import Base, engine, session


class User(Base):
    __tablename__ = 'user'

    user_id = Column('user_id', INTEGER, primary_key=True)
    username = Column('username', String(255))
    email = Column('email', String(255))
    password = Column('password', String(255))

    is_active = Column('is_active', BOOLEAN)
    is_admin = Column('is_admin', BOOLEAN)
    is_superuser = Column('is_superuser', BOOLEAN)


if not session.query(User):
    Base.metadata.create_all(engine)
