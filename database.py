from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from config import settings

#Database setup
engine = create_engine(settings.DATABASE_URL)

session_local = sessionmaker(autocommit=False, bind=engine)

base_table_class = declarative_base() 

#Tables
class User(base_table_class):
    __tablename__ = "users"

    id = Column(Integer, primary_key = True, index = True) #id is necessary
    username = Column(String(50), unique = True, index = True, nullable = False)
    email = Column(String(100), unique = True, index = True, nullable = False)
    hashed_password = Column(String(255), nullable = False)
    is_active = Column(Boolean, default = True)
    last_logout_time = Column(DateTime, nullable = True)
    created_at = Column(DateTime, default = datetime.utcnow)

class RefreshToken(base_table_class):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key = True, index = True)
    user_id = Column(Integer, index = True, nullable = False)
    token_hash = Column(String(255), unique = True, nullable = False)
    expires_at = Column(DateTime, nullable = False)
    is_revoked = Column(Boolean, default = False)
    created_at = Column(DateTime, default = datetime.utcnow)

#Create tables
def create_tables():
    base_table_class.metadata.create_all(bind = engine)

#Dependency in database
def get_db():
    db = session_local()      #open new session
    try:
        yield db            #session to endpoint
    finally:
        db.close()          #close session
