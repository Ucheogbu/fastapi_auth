from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///../test_db.db")
Base = declarative_base()

# from models import User

Session = sessionmaker(bind=engine)

session = Session()

