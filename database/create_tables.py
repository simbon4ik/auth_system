from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from settings.config import settings
from database.tables import table_class

# database setup
engine = create_engine(settings.DATABASE_URL)

session_local = sessionmaker(autocommit=False, bind=engine)

def create_tables():
    table_class.metadata.create_all(bind=engine)

# operations with database
def get_db():
    db = session_local()
    try:
        yield db
    finally:
        db.close()
