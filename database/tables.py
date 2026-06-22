from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, Integer
from sqlalchemy.ext.declarative import declarative_base

import enum
from sqlalchemy import Enum

class UserRole(enum.IntEnum):
    USER = 1
    ADMIN = 2
    SERVICE = 3  # for other systems in service

table_class = declarative_base() 

class User(table_class):
    __tablename__ = "users"

    id = Column(Integer, primary_key = True, index = True)
    username = Column(String(50), unique = True, index = True, nullable = False)
    email = Column(String(100), unique = True, index = True, nullable = False)
    hashed_password = Column(String(255), nullable = False)
    is_active = Column(Boolean, default = True)
    last_logout_time = Column(DateTime, nullable = True)
    created_at = Column(DateTime, default = datetime.utcnow)
    role = Column(Enum(UserRole), default = UserRole.USER, index = True, nullable = False)
    current_refresh_jti = Column(String, nullable=True)