# janus_data/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# PostgreSQL connection string
# Fetch password from environment variable for security
DB_PASSWORD = os.getenv("JANUS_DB_PASSWORD")

if not DB_PASSWORD:
    raise ValueError("JANUS_DB_PASSWORD environment variable not set. Create a .env file in the project root.")

DATABASE_URL = f"postgresql://janus_user:{DB_PASSWORD}@localhost/janus_db"

# SQLAlchemy Engine
engine = create_engine(DATABASE_URL, echo=False)

# Base class for declarative models
Base = declarative_base()

# Session factory to interact with the database
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """
    Initializes the database by creating all tables defined in Base.metadata.
    """
    print(f"Initializing PostgreSQL database: janus_db")
    Base.metadata.create_all(bind=engine)
    print("Database tables created (if they didn't exist).")

def get_db():
    """
    Dependency to get a database session.
    Yields a session which is then closed automatically.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()